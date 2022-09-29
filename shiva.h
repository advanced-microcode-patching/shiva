#ifndef __SHIVA_H_
#define __SHIVA_H_

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
#include <sys/prctl.h>
#include <sys/wait.h>

#include "./udis86-1.7.2/udis86.h"
#include "/opt/elfmaster/include/libelfmaster.h"
#include "shiva_debug.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define ELF_MIN_ALIGN 4096
#define ELF_PAGESTART(_v) ((_v) & ~(unsigned long)(ELF_MIN_ALIGN-1))
#define ELF_PAGEOFFSET(_v) ((_v) & (ELF_MIN_ALIGN-1))
#define ELF_PAGEALIGN(_v, _a) (((_v) + _a - 1) & ~(_a - 1))

#define SHIVA_RUNTIME_ADDR(addr) (addr + ctx->ulexec.base)

#define SHIVA_OPTS_F_MODULE_PATH		(1UL << 0)
#define SHIVA_OPTS_F_ULEXEC_ONLY		(1UL << 1)
#define SHIVA_OPTS_F_INTERP_MODE		(1UL << 2)

#define SHIVA_F_ULEXEC_LDSO_NEEDED	(1UL << 0)

#define SHIVA_STACK_SIZE	(PAGE_SIZE * 1000)

#define SHIVA_LDSO_BASE		0x1000000
#define SHIVA_TARGET_BASE	0x40000000

#define SHIVA_MODULE_F_RUNTIME	(1UL << 0)
#define SHIVA_MODULE_F_INIT	(1UL << 1)

/*
 * Path to real dynamic linker.
 * XXX this should be configurable via environment.
 */
#define SHIVA_LDSO_PATH "/lib64/ld-linux-x86-64.so.2"

#define SHIVA_ULEXEC_LDSO_TRANSFER(stack, addr, entry) __asm__ __volatile__("mov %0, %%rsp\n" \
					    "push %1\n" \
					    "mov %2, %%rax\n" \
					    "mov $0, %%rbx\n" \
					    "mov $0, %%rcx\n" \
					    "mov $0, %%rdx\n" \
					    "mov $0, %%rsi\n" \
					    "mov $0, %%rdi\n" \
					    "mov $0, %%rbp\n" \
					    "ret" :: "r" (stack), "g" (addr), "g"(entry))


typedef struct shiva_addr_struct {
	uint64_t addr;
	TAILQ_ENTRY(shiva_addr_struct) _linkage;
} shiva_addr_struct_t;

typedef enum shiva_iterator_res {
	SHIVA_ITER_OK = 0,
	SHIVA_ITER_DONE,
	SHIVA_ITER_ERROR
} shiva_iterator_res_t;

typedef struct shiva_maps_iterator {
	struct shiva_ctx *ctx;
	struct shiva_mmap_entry *current;
} shiva_maps_iterator_t;

typedef struct shiva_callsite_iterator {
	struct shiva_branch_site *current;
	struct shiva_ctx *ctx;
} shiva_callsite_iterator_t;

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

#define SHIVA_TRACE_MAX_ERROR_STRLEN 4096

typedef struct shiva_error {
	char string[SHIVA_TRACE_MAX_ERROR_STRLEN];
	int _errno;
} shiva_error_t;

typedef enum shiva_branch_type {
	SHIVA_BRANCH_JMP = 0,
	SHIVA_BRANCH_CALL,
	SHIVA_BRANCH_RET
} shiva_branch_type_t;

#define SHIVA_BRANCH_F_PLTCALL  (1UL << 0)

struct shiva_branch_site {
	struct elf_symbol symbol; // symbol being called
	shiva_branch_type_t branch_type;
	uint64_t branch_flags;
	uint64_t target_vaddr;
	uint64_t branch_site;
	uint64_t retaddr; /*
			   * If this is a SHIVA_BRANCH_CALL then
			   * retaddr will point to the return address
			   * of the function being called. For now
			   * retaddr is not used in any other branch
			   * site type.
			   */
	TAILQ_ENTRY(shiva_branch_site) _linkage;
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
	size_t plt_count;
	TAILQ_ENTRY(shiva_module_plt_entry) _linkage;
};

struct shiva_module_got_entry {
	char *symname;
	uint64_t gotaddr; // address of GOT entry
	uint64_t gotoff; // offset of GOT entry
	TAILQ_ENTRY(shiva_module_got_entry) _linkage;
};

typedef enum shiva_mmap_type {
	SHIVA_MMAP_TYPE_HEAP = 0,
	SHIVA_MMAP_TYPE_STACK,
	SHIVA_MMAP_TYPE_VDSO,
	SHIVA_MMAP_TYPE_SHIVA,
	SHIVA_MMAP_TYPE_MISC
} shiva_mmap_type_t;

typedef struct shiva_mmap_entry {
	uint64_t base;
	size_t len;
	uint32_t prot;	  // mapping prot
	uint32_t mapping; // shared, private
	shiva_mmap_type_t mmap_type;
	bool debugger_mapping;
	TAILQ_ENTRY(shiva_mmap_entry) _linkage;
} shiva_mmap_entry_t;

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
	uint64_t shiva_base; /* base address of shiva executable at runtime */
	elfobj_t elfobj; /* elfobj to the module */
	elfobj_t self; /* elfobj to self (Debugger binary) */
	struct {
		TAILQ_HEAD(, shiva_module_got_entry) got_list;
		TAILQ_HEAD(, shiva_module_section_mapping) section_maplist;
		TAILQ_HEAD(, shiva_module_plt_entry) plt_list;
	} tailq;
	struct {
		struct hsearch_data got;
	} cache;
};

typedef struct shiva_trace_regset_x86_64 {
	uint64_t rax, rbx, rcx, rdx;
	uint64_t rsi, rdi;
	uint64_t rbp, rsp, rip;
	uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
	uint64_t flags, cs, ss, fs, ds;
} shiva_trace_regset_x86_64_t;

typedef struct shiva_trace_regset_x86_64 shiva_trace_jumpbuf_t;

#define RAX_OFF 0
#define RBX_OFF 8
#define RCX_OFF 16
#define RDX_OFF 24
#define RSI_OFF 32
#define RDI_OFF 40
#define RBP_OFF 48
#define RSP_OFF 56
#define RIP_OFF 64
#define R8_OFF	72
#define R9_OFF	80
#define R10_OFF 88
#define R11_OFF 96
#define R12_OFF 104
#define R13_OFF 112
#define R14_OFF 120
#define R15_OFF 128

typedef struct shiva_ctx {
	char *path; // path to target executable
	int argc;
	char **args;
	char **argv;
	char **envp;
	int argcount;
	elfobj_t shiva_elfobj; // shiva executable
	elfobj_t elfobj;	// target executable
	elfobj_t ldsobj;	// ldso executable
	uint64_t flags;
	int pid;
	int duplicate_pid;
	uint64_t duplicate_base;
	char *shiva_path; // path to /bin/shiva
	union {
		struct shiva_trace_regset_x86_64 regset_x86_64;
	} regs;
	struct {
		struct shiva_module *runtime;
		struct shiva_module *initcode;
	} module;
	struct {
		Elf64_Rela *jmprel;
		size_t jmprel_count;
	} altrelocs;
	struct {
		ud_t ud_obj;
		uint8_t *textptr;
		uint64_t base;
	} disas;
	struct {
		uint64_t base;
	} shiva;
	struct {
		/*
		 * basic runtime data created during
		 * userland exec.
		 */
		uint8_t *stack;
		uint8_t *mem;
		uint64_t rsp_start;
		uint64_t heap_vaddr;
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
		TAILQ_HEAD(, shiva_trace_thread) thread_tqlist;
		TAILQ_HEAD(, shiva_mmap_entry) mmap_tqlist;
		TAILQ_HEAD(, shiva_branch_site) branch_tqlist;
		TAILQ_HEAD(, shiva_trace_handler) trace_handlers_tqlist;
	} tailq;
} shiva_ctx_t;

extern struct shiva_ctx *ctx_global;

/*
 * util.c
 */

char * shiva_strdup(const char *);
char * shiva_xfmtstrdup(char *, ...);
void * shiva_malloc(size_t);

/*
 * signal.c
 */

void shiva_sighandle(int);

/*
 * shiva_iter.c
 */
bool shiva_auxv_iterator_init(struct shiva_ctx *, struct shiva_auxv_iterator *, void *);
shiva_iterator_res_t shiva_auxv_iterator_next(struct shiva_auxv_iterator *, struct shiva_auxv_entry *);
bool shiva_auxv_set_value(struct shiva_auxv_iterator *, long);

/*
 * shiva_ulexec.c
 */
bool shiva_ulexec_prep(shiva_ctx_t *);
bool shiva_ulexec_load_elf_binary(struct shiva_ctx *, elfobj_t *, bool);
uint8_t * shiva_ulexec_allocstack(struct shiva_ctx *);
/*
 * shiva_module.c
 */
bool shiva_module_loader(shiva_ctx_t *, const char *, struct shiva_module **, uint64_t);

/*
 * shiva_error.c
 */
bool shiva_error_set(shiva_error_t *, const char *, ...);
const char * shiva_error_msg(shiva_error_t *);

/*
 * shiva_maps.c
 */
bool shiva_maps_prot_by_addr(struct shiva_ctx *, uint64_t, int *);
bool shiva_maps_build_list(shiva_ctx_t *);
bool shiva_maps_validate_addr(shiva_ctx_t *, uint64_t);
void shiva_maps_iterator_init(shiva_ctx_t *, shiva_maps_iterator_t *);
shiva_iterator_res_t shiva_maps_iterator_next(shiva_maps_iterator_t *, struct shiva_mmap_entry *);
bool shiva_maps_get_base(shiva_ctx_t *, uint64_t *);
/*
 * shiva_callsite.c
 */
void shiva_callsite_iterator_init(struct shiva_ctx *, struct shiva_callsite_iterator *);
shiva_iterator_res_t shiva_callsite_iterator_next(shiva_callsite_iterator_t *, struct shiva_branch_site *);

/*
 * shiva_analyze.c
 */
bool shiva_analyze_find_calls(shiva_ctx_t *);
bool shiva_analyze_run(shiva_ctx_t *);

/*
 * shiva_target.c
 */
bool
shiva_target_dynamic_set(struct shiva_ctx *, uint64_t, uint64_t);

/*
 * shiva_proc.c
 */
bool shiva_proc_duplicate_image(shiva_ctx_t *ctx);
/*
 * Shiva tracing functionality.
 * shiva_trace.c
 * shiva_trace_thread.c
 */

#define SHIVA_TRACE_THREAD_F_TRACED	(1UL << 0)	// thread is traced by SHIVA
#define SHIVA_TRACE_THREAD_F_PAUSED	(1UL << 1)	// pause thread
#define SHIVA_TRACE_THREAD_F_EXTERN_TRACER	(1UL << 2) // thread is traced by ptrace
#define SHIVA_TRACE_THREAD_F_COREDUMPING	(1UL << 3)
#define SHIVA_TRACE_THREAD_F_NEW		(1UL << 4) // newly added into thread list

#define SHIVA_TRACE_HANDLER_F_CALL		(1UL << 0) // handler is invoked via  call
#define SHIVA_TRACE_HANDLER_F_JMP		(1UL << 1) // handler is invoked via jmp
#define SHIVA_TRACE_HANDLER_F_INT3		(1UL << 2) // handler is invoked via int3
#define SHIVA_TRACE_HANDLER_F_TRAMPOLINE	(1UL << 3) // handler is invoked via function trampoline


/*
 * When your handler function executes, assuming is was invoked
 * via a BP_CALL breakpoint, then it probably wants to call the
 * original function and return. This macro allows you to do this,
 * see modules/shakti_runtime.c
 */
#define SHIVA_TRACE_CALL_ORIGINAL(bp) { \
	do {\
		void * (*o_func)(void *, void *, void *, void *, \
				 void *, void *, void *);	\
		o_func = (void *)bp->o_target;				\
		return o_func((void *)ctx_global->regs.regset_x86_64.rdi,	\
		       (void *)ctx_global->regs.regset_x86_64.rsi,	\
		       (void *)ctx_global->regs.regset_x86_64.rdx,	\
		       (void *)ctx_global->regs.regset_x86_64.rcx,	\
		       (void *)ctx_global->regs.regset_x86_64.r8,	\
		       (void *)ctx_global->regs.regset_x86_64.r9,	\
		       (void *)ctx_global->regs.regset_x86_64.r10);	\
	} while(0); \
}

typedef enum shiva_trace_bp_type {
	SHIVA_TRACE_BP_JMP = 0,
	SHIVA_TRACE_BP_CALL,
	SHIVA_TRACE_BP_INT3,
	SHIVA_TRACE_BP_SEGV,
	SHIVA_TRACE_BP_SIGILL,
	SHIVA_TRACE_BP_TRAMPOLINE,
	SHIVA_TRACE_BP_PLTGOT
} shiva_trace_bp_type_t;

/*
 * Get the breakpoint struct that correlates to the handler
 * function that you are currently in.
 * NOTE: Can ONLY be used from within a module callback/handler
 */
#define SHIVA_TRACE_BP_STRUCT(bp, handler) { \
	do {\
		void *__ret = __builtin_return_address(0); \
		struct shiva_addr_struct *addr;			\
		TAILQ_FOREACH(bp, &handler->bp_tqlist, _linkage)  { \
			if (bp->bp_type == SHIVA_TRACE_BP_TRAMPOLINE) \
				break;	\
			if (bp->bp_type == SHIVA_TRACE_BP_PLTGOT) { \
				TAILQ_FOREACH(addr, &bp->retaddr_list, _linkage) { \
					if (addr->addr == __ret)	\
						break;	\
				}	\
			}	\
			if ((void *)bp->callsite_retaddr == __ret)	\
				break;	\
		} \
	} while(0); \
}

/*
 * A necessary longjmp from a trap handler back to the
 * instruction that was trapped on. We must reset the
 * registers and rewind the stack back. TODO: Need to handle
 * issue with rbp restoration.
 */
#define SHIVA_TRACE_LONGJMP_RETURN(regptr, rip_target)	\
			__asm__ __volatile__("movq %0, %%rdx\n" :: "r"(regptr)); \
			__asm__ __volatile__(				\
					"movq 0(%%rdx), %%r8\n\t" \
					"movq 8(%%rdx), %%r9\n\t"	\
					"movq 16(%%rdx), %%r10\n\t"	\
					"movq 24(%%rdx), %%r11\n\t"	\
					"movq 32(%%rdx), %%r12\n\t"	\
					"movq 40(%%rdx), %%r13\n\t"	\
					"movq 48(%%rdx), %%r14\n\t"	\
					"movq 56(%%rdx), %%r15\n\t" \
					"movq 64(%%rdx), %%rdi\n\t"	\
					"movq 72(%%rdx), %%rsi\n\t"	\
					"movq 88(%%rdx), %%rbx\n\t" \
					"movq 104(%%rdx), %%rax\n\t" \
					"movq 112(%%rdx), %%rcx\n\t" \
					"movq 120(%%rdx), %%rsp\n\t" \
					"jmp %0" :: "r"(rip_target));

#define SHIVA_TRACE_SET_TRAPFLAG __asm__ __volatile__(	\
				"pushfq\n\t"	\
				"pop %rdx\n\t"	\
				"or %rdx, 0x100\n\t"	\
				"push %rdx\n\t"	\
				"popfq");


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

#define SHIVA_MAX_INST_LEN 15

typedef struct shiva_trace_insn
{
	uint8_t o_insn[SHIVA_MAX_INST_LEN];
	uint8_t n_insn[SHIVA_MAX_INST_LEN];
	size_t o_insn_len;
	size_t n_insn_len;
} shiva_trace_insn_t;

typedef struct shiva_trace_bp {
	shiva_trace_bp_type_t bp_type;
	uint64_t bp_addr;
	size_t bp_len;
	uint8_t *inst_ptr;
	uint64_t callsite_retaddr; // only used for CALL hooks
	uint64_t plt_addr; // Only used for PLTGOT hooks. This holds the corresponding PLT stub address.
	uint64_t o_target; // for CALL/JMP hooks this holds original target. For PLTGOT hooks it holds original gotptr
	int64_t o_call_offset; // if this is a call or jmp breakpoint, o_offset holds the original target offset
	struct elf_symbol symbol;
	char *call_target_symname; // only used for SHIVA_TRACE_BP_CALL hooks
	bool symbol_location;	// true if bp->symbol gets set
	struct shiva_trace_insn insn;
	struct hsearch_data valid_plt_retaddrs; // only used for SHIVA_TRACE_BP_PLTGOT hooks
	TAILQ_HEAD(, shiva_addr_struct) retaddr_list;
	TAILQ_ENTRY(shiva_trace_bp) _linkage;
} shiva_trace_bp_t;

typedef struct shiva_trace_handler {
	shiva_trace_bp_type_t type;
	void * (*handler_fn)(void *); // points to handler triggered by BP
	struct sigaction sa;
	TAILQ_HEAD(, shiva_trace_bp) bp_tqlist; // list of current bp's
	TAILQ_ENTRY(shiva_trace_handler) _linkage;
} shiva_trace_handler_t;

typedef struct shiva_trace_regs {
	struct shiva_trace_regset_x86_64 x86_64;
} shiva_trace_regs_t;

typedef struct shiva_trace_thread {
	char *name;
	uid_t uid;
	gid_t gid;
	pid_t pid;
	pid_t ppid;
	pid_t external_tracer_pid;
	uint64_t flags;
	TAILQ_ENTRY(shiva_trace_thread) _linkage;
} shiva_trace_thread_t;

bool shiva_trace(shiva_ctx_t *, pid_t, shiva_trace_op_t, void *, void *, size_t, shiva_error_t *);
bool shiva_trace_register_handler(shiva_ctx_t *, void * (*)(void *), shiva_trace_bp_type_t,
    shiva_error_t *);
struct shiva_trace_handler * shiva_trace_find_handler(struct shiva_ctx *, void *);
struct shiva_trace_bp * shiva_trace_bp_struct(void *);
bool shiva_trace_set_breakpoint(shiva_ctx_t *, void * (*)(void *), uint64_t, void *, shiva_error_t *);
bool shiva_trace_write(struct shiva_ctx *, pid_t, void *, const void *, size_t, shiva_error_t *);
void __attribute__((naked)) shiva_trace_getregs_x86_64(struct shiva_trace_regset_x86_64 *);
void __attribute__((naked)) shiva_trace_setjmp_x86_64(shiva_trace_jumpbuf_t *);
void shiva_trace_longjmp_x86_64(shiva_trace_jumpbuf_t *jumpbuf, uint64_t ip);
uint64_t shiva_trace_base_addr(struct shiva_ctx *);
/*
 * shiva_trace_thread.c
 */
bool shiva_trace_thread_insert(shiva_ctx_t *, pid_t, uint64_t *);

#endif
