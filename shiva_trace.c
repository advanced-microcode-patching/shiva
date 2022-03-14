#include "shiva.h"

static bool
shiva_trace_thread(struct shiva_ctx *ctx, pid_t pid, shiva_trace_op_t op,
    void *addr, void *data)
{
	return true;
}

/*
 * shiva_trace_op_t types:
 * SHIVA_TRACE_OP_CONT
 * SHIVA_TRACE_OP_POKE
 * SHIVA_TRACE_OP_PEEK
 * SHIVA_TRACE_OP_GETREGS
 * SHIVA_TRACE_OP_SETREGS
 * SHIVA_TRACE_OP_SETFPREGS
 * SHIVA_TRACE_OP_GETSIGINFO
 * SHIVA_TRACE_OP_SETSIGINFO
 */

bool
shiva_trace(struct shiva_ctx *ctx, pid_t pid, shiva_trace_op_t op,
    void *addr, void *data)
{
	bool res;

	switch(op) {
	}
	if (pid != 0) {
		shiva_debug("invoking shiva_trace_thread()\n");
		return shiva_trace_thread(ctx, pid, op, addr, data);
	}


}
