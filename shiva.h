#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <stdint.h>
#include <signal.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/queue.h>
#include <elf.h>
#include <errno.h>

#include <capstone/capstone.h>
#include "/opt/elfmaster/include/libelfmaster.h"
#include "shiva_debug.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define ELF_MIN_ALIGN 4096
#define ELF_PAGESTART(_v) ((_v) & ~(unsigned long)(ELF_MIN_ALIGN-1))
#define ELF_PAGEOFFSET(_v) ((_v) & (ELF_MIN_ALIGN-1))
#define ELF_PAGEALIGN(_v, _a) (((_v) + _a - 1) & ~(_a - 1))

#define SHIVA_F_JMP_CFLOW		(1UL << 0)
#define SHIVA_F_STRING_ARGS		(1UL << 1)
#define SHIVA_F_RETURN_FLOW		(1UL << 2)

#define SHIVA_F_ULEXEC_LDSO_NEEDED	(1UL << 0)

#define SHIVA_STACK_SIZE	(PAGE_SIZE * 100)

#define SHIVA_LDSO_BASE		0x600000
#define SHIVA_TARGET_BASE	0x1000000

#define SHIVA_MODULE_F_RUNTIME	(1UL << 0)
#define SHIVA_MODULE_F_INIT	(1UL << 1)

#define SHIVA_ULEXEC_LDSO_TRANSFER(stack, addr, entry) __asm__ __volatile__("mov %0, %%rsp\n" \
                                            "push %1\n" \
                                            "mov %2, %%rax\n" \
                                            "mov $0, %%rbx\n" \
                                            "mov $0, %%rcx\n" \
                                            "mov $0, %%rdx\n" \
                                            "mov $0, %%rsi\n" \
                                            "mov $0, %%rdi\n" \
                                            "mov $0, %%rbp\n" \
                                            "mov $0, %%r8\n" \
                                            "mov $0, %%r9\n" \
                                            "mov $0, %%r10\n" \
                                            "mov $0, %%r11\n" \
                                            "mov $0, %%r12\n" \
                                            "mov $0, %%r13\n" \
                                            "mov $0, %%r14\n" \
                                            "mov $0, %%r15\n" \
                                            "ret" :: "r" (stack), "g" (addr), "g"(entry))


typedef enum shiva_iterator_res {
	SHIVA_ITER_OK = 0,
	SHIVA_ITER_DONE,
	SHIVA_ITER_ERROR
} shiva_iterator_res_t;

typedef struct shiva_auxv_iterator {
	unsigned int index;
	struct shiva_ctx *ctx;
	Elf64_auxv_t *auxv;
} shiva_auxv_iterator_t;

typedef struct shiva_auxv_entry {
	uint64_t value;
	int type;
	char *string;
} shiva_auxv_entry_t;

#define SHIVA_TRACE_THREAD_F_TRACED	(1UL << 0)	// thread is traced by SHIVA
#define SHIVA_TRACE_THREAD_F_PAUSED	(1UL << 1)	// pause thread
#define SHIVA_TRACE_THREAD_F_EXTERN_TRACER	(1UL << 2) // thread is traced by ptrace
#define SHIVA_TRACE_THREAD_F_COREDUMPING	(1UL << 3)

typedef enum shiva_trace_op {
        SHIVA_TRACE_OP_CONT = 0,
	SHIVA_TRACE_OP_ATTACH,
        SHIVA_TRACE_OP_POKE,
        SHIVA_TRACE_OP_PEEK,
        SHIVA_TRACE_OP_GETREGS,
        SHIVA_TRACE_OP_SETREGS,
        SHIVA_TRACE_OP_SETFPREGS,
        SHIVA_TRACE_OP_GETSIGINFO,
        SHIVA_TRACE_OP_SETSIGINFO
} shiva_trace_op_t;

struct shiva_trace_thread {
	char *name;
	uid_t uid;
	gid_t gid;
	pid_t pid;
	pid_t ppid;
	pid_t external_tracer_pid;
	uint64_t flags;
	TAILQ_ENTRY(shiva_trace_thread) _linkage;
};

typedef enum shiva_branch_type {
	SHIVA_BRANCH_JMP = 0,
	SHIVA_BRANCH_CALL,
	SHIVA_BRANCH_RET
} shiva_branch_type_t;

struct shiva_branch_site {
	struct elf_symbol symbol; // symbol being called
	shiva_branch_type_t branch_type;
	uint64_t target_vaddr;
	uint64_t branch_site;
	SLIST_ENTRY(shiva_branch_site) _linkage;
};

typedef enum shiva_module_section_map_attr {
        LP_SECTION_TEXTSEGMENT = 0,
        LP_SECTION_DATASEGMENT,
        LP_SECTION_UNKNOWN
} shiva_module_section_map_attr_t;

struct shiva_module_section_mapping {
        struct elf_section section;
        shiva_module_section_map_attr_t map_attribute;
        uint64_t vaddr; /* Which memory address the section contents is placed in */
        uint64_t offset;
        uint64_t size;
        char *name;
        TAILQ_ENTRY(shiva_module_section_mapping) _linkage;
};

#define SHIVA_MODULE_MAX_PLT_COUNT 4096

struct shiva_module_plt_entry {
        char *symname;
        uint64_t vaddr;
        size_t offset;
        TAILQ_ENTRY(shiva_module_plt_entry) _linkage;
};

struct shiva_module {
        int fd;
	uint64_t flags;
        uint8_t *text_mem;
        uint8_t *data_mem; /* Includes .bss */
        uintptr_t *pltgot;
        uintptr_t *plt;
        size_t pltgot_size;
        size_t plt_size;
        size_t plt_off;
        size_t plt_count;
        size_t pltgot_off;
        size_t text_size;
        size_t data_size;
        uint64_t text_vaddr;
        uint64_t data_vaddr;
        elfobj_t elfobj;
        struct {
                TAILQ_HEAD(, shiva_module_section_mapping) section_maplist;
                TAILQ_HEAD(, shiva_module_plt_entry) plt_list;
        } tailq;
        struct {
                struct hsearch_data plt;
        } cache;
};

typedef struct shiva_ctx {
	char *path;
	int argc;
	char **args;
	char **argv;
	char **envp;
	int argcount;
	elfobj_t elfobj;
	elfobj_t ldsobj;
	uint64_t flags;
	int pid;
	struct {
		struct shiva_module *runtime;
		struct shiva_module *initcode;
	} module;
	struct {
		csh handle;
		cs_insn *insn;
		uint8_t *textptr;
		size_t count;
	} disas;
	struct {
		/*
		 * basic runtime data created during
		 * userland exec.
		 */
		uint8_t *stack;
		uint8_t *mem;
		uint64_t rsp_start;
		uint64_t entry_point;
		uint64_t base_vaddr;
		uint64_t phdr_vaddr; // vaddr of phdr table for mapped binary
		size_t arglen;
		size_t envpcount;
		size_t envplen;
		char *envstr;
		char *argstr;
		struct {
			size_t sz;
			size_t count;
			uint8_t *vector;
		} auxv;
		/*
		 * mapped LDSO specific data
		 */
		struct {
			uint64_t entry_point;
			uint64_t base_vaddr;
			uint64_t phdr_vaddr;
		} ldso;
		uint64_t flags; // SHIVA_F_ULEXEC_* flags
	} ulexec;
	struct {
		SLIST_HEAD(, shiva_branch_site) branch_slist;
	} slist;
	struct {
		TAILQ_HEAD(, shiva_trace_thread) thread_tqlist;
	} tailq;
} shiva_ctx_t;

/*
 * util.c
 */

char * shiva_strdup(const char *);
char * shiva_fmtstrdup(char *, ...);
void * shiva_malloc(size_t);

/*
 * signal.c
 */

void shiva_sighandle(int);

/*
 * shiva_iter.c
 */
bool shiva_auxv_iterator_init(struct shiva_ctx *, struct shiva_auxv_iterator *);
shiva_iterator_res_t shiva_auxv_iterator_next(struct shiva_auxv_iterator *, struct shiva_auxv_entry *);
bool shiva_auxv_set_value(struct shiva_auxv_iterator *, long);

/*
 * shiva_ulexec.c
 */
bool shiva_ulexec_prep(shiva_ctx_t *);

/*
 * shiva_module.c
 */
bool shiva_module_loader(const char *, struct shiva_module **, uint64_t);

/*
 * shiva_trace.c
 */

/*
 * shiva_trace_thread.c
 */
bool shiva_trace_thread_insert(struct shiva_ctx *ctx, pid_t pid);
