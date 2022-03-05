#define _GNU_SOURCE
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

int global_pid;

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

typedef struct shiva_ctx {
	char *path;
	char **args;
	int argcount;
	elfobj_t elfobj;
	uint64_t flags;
	int pid;
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
		uint64_t entry_point;
		uint64_t base_vaddr;
		uint64_t phdr_vaddr; // vaddr of phdr table for mapped binary
	} ulexec;
	struct {
		SLIST_HEAD(, shiva_branch_site) branch_list;
	} list;
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
