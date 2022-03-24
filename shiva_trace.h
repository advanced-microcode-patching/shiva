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

#include "shiva.h"

#define SHIVA_TRACE_THREAD_F_TRACED	(1UL << 0)	// thread is traced by SHIVA
#define SHIVA_TRACE_THREAD_F_PAUSED	(1UL << 1)	// pause thread
#define SHIVA_TRACE_THREAD_F_EXTERN_TRACER	(1UL << 2) // thread is traced by ptrace
#define SHIVA_TRACE_THREAD_F_COREDUMPING	(1UL << 3)
#define SHIVA_TRACE_THREAD_F_NEW		(1UL << 4) // newly added into thread list

#define SHIVA_TRACE_HANDLER_F_CALL	(1UL << 0) // handler is invoked via  call
#define SHIVA_TRACE_HANDLER_F_JMP	(1UL << 1) // handler is invoked via jmp
#define SHIVA_TRACE_HANDLER_F_INT3	(1UL << 2) // handler is invoked via int3

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

typedef enum shiva_trace_bp_type {
	SHIVA_TRACE_BP_JMP = 0,
	SHIVA_TRACE_BP_CALL,
	SHIVA_TRACE_BP_INT3
} shiva_trace_bp_type_t;

typedef struct shiva_trace_bp {
	shiva_trace_bp_type_t bp_type;
	uint64_t bp_addr;
	size_t bp_len;
	uint8_t *inst_ptr;
	struct elf_symbol symbol;
	bool symbol_location;
	struct shiva_trace_insn insn;
	TAILQ_ENTRY(shiva_trace_bp) _linkage;
} shiva_trace_bp_t;

typedef struct shiva_trace_handler {
	shiva_trace_bp_type_t type;
	void * (*handler_fn)(shiva_ctx_t *); // points to handler triggered by BP
	TAILQ_HEAD(, shiva_trace_bp) bp_tqlist; // list of current bp's
	TAILQ_ENTRY(shiva_trace_handler) _linkage;
} shiva_trace_handler_t;

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

bool shiva_trace(shiva_ctx_t *, pid_t, shiva_trace_op_t, void *, void *, shiva_error_t *);
bool shiva_trace_register_handler(shiva_ctx_t *, void * (*)(shiva_ctx_t *), shiva_trace_bp_type_t,
    shiva_error_t *);
bool shiva_trace_set_breakpoint(shiva_ctx_t *, void * (*)(shiva_ctx_t *), uint64_t, shiva_error_t *);
bool shiva_trace_write(struct shiva_ctx *, pid_t, void *, const void *, size_t, shiva_error_t *);
/*
 * shiva_trace_thread.c
 */
bool shiva_trace_thread_insert(shiva_ctx_t *, pid_t, uint64_t *);
