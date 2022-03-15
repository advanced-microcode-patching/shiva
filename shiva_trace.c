#include "shiva.h"

bool
shiva_trace_op_attach(struct shiva_ctx *ctx, pid_t pid,
    void *addr, void *data, shiva_error_t *error)
{
	bool res;
	uint64_t status;

	if (pid == 0) {
		res = shiva_trace_thread_insert(ctx, pid, &status);
		if (res == false) {
			if (status & SHIVA_TRACE_THREAD_F_EXTERN_TRACER) {
				shiva_error_set(error, "attach pid (%d) failed:"
				    " thread is being traced by another process\n", pid);
				return false;
			} else if (status & SHIVA_TRACE_THREAD_F_COREDUMPING) {
				shiva_error_set(error, "attach pid (%d) failed:"
				    " thread is coredumping\n", pid);
				return false;
			} else {
				shiva_error_set(error, "attach pid (%d) failed: reason unknown\n", pid);
				return false;
			}
		}

	} else {
		/*
		 * TODO for multiple threads
		 */
		shiva_error_set(error, "attach pid (%d) failed: no support for multiple threads\n", pid);
		return false;
	}
	return true;
}

bool
shiva_trace_op_cont(struct shiva_ctx *ctx, pid_t pid,
    void *addr, void *data, shiva_error_t *error)
{

	return true;
}

bool
shiva_trace_op_poke(struct shiva_ctx *ctx, pid_t pid,
    void *addr, void *data, shiva_error_t *error)
{
	uintptr_t *ptr = addr;
	uintptr_t *value = data;

}

/*
 * shiva_trace_op_t types:
 * SHIVA_TRACE_OP_ATTACH
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
    void *addr, void *data, shiva_error_t *error)
{
	bool res;

	switch(op) {
	case SHIVA_TRACE_OP_ENTER:
		res = shiva_trace_op_attach(ctx, pid, addr, data, error);
		break;
	case SHIVA_TRACE_OP_ATTACH:
		res = shiva_trace_op_attach(ctx, pid, addr, data, error);
		break;
	case SHIVA_TRACE_OP_CONT:
		res = shiva_trace_op_cont(ctx, pid, addr, data, error);
		break;
	case SHIVA_TRACE_OP_POKE:
		res = shiva_trace_op_poke(ctx, pid, addr, data, error);
		break;
#if 0
	case SHIVA_TRACE_OP_PEEK:
		res = shiva_trace_op_peek(ctx, pid, op, addr, data);
		break;
	case SHIVA_TRACE_OP_GETREGS:
		res = shiva_trace_op_getregs(ctx, pid, op, addr, data);
		break;
	case SHIVA_TRACE_OP_SETREGS:
		res = shiva_trace_op_setregs(ctx, pid, op, addr, data);
		break;
	case SHIVA_TRACE_OP_GETSIGINFO:
		res = shiva_trace_op_getsiginfo(ctx, pid, op, addr, data);
		break;
	case SHIVA_TRACE_OP_SETSIGINFO:
		res = shiva_trace_op_setsiginfo(ctx, pid, op, addr, data);
		break;
	case SHIVA_TRACE_OP_SETFPREGS:
		res = shiva_trace_op_setfpregs(ctx, pid, op, addr, data);
		break;
#endif
	default:
		break;
	}
	return res;
}
