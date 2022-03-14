#include "shiva.h"

/*
 * shiva_ptrace_op_t types:
 * SHIVA_PTRACE_OP_CONT
 * SHIVA_PTRACE_OP_POKE
 * SHIVA_PTRACE_OP_PEEK
 * SHIVA_PTRACE_OP_GETREGS
 * SHIVA_PTRACE_OP_SETREGS
 * SHIVA_PTRACE_OP_SETFPREGS
 * SHIVA_PTRACE_OP_GETSIGINFO
 * SHIVA_PTRACE_OP_SETSIGINFO
 */

bool
shiva_ptrace(shiva_ctx_t *ctx, pid_t pid, shiva_ptrace_op_t op,
    void *addr, void *data)
{
	bool res;

	if (pid != 0) {
		shiva_debug("invoking shiva_ptrace_thread()\n");
		res = shiva_ptrace_thread(ctx, pid, op, addr, data);
	}
}
