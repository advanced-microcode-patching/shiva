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

static bool
shiva_trace_op_poke(struct shiva_ctx *ctx, pid_t pid,
    void *addr, void *data, shiva_error_t *error)
{
	uint64_t aligned_vaddr;
	uint64_t v = (uint64_t)data;
	size_t pokelen = 0;
	int o_prot, ret;

	if (shiva_maps_validate_addr(ctx, (uint64_t)addr) == false) {
		shiva_error_set(error, "poke pid (%d) at %#lx failed: "
		   "cannot write to debugger memory\n", pid, (uint64_t)addr);
		return false;
	}
	pokelen = (v >= 0x00000000 && v < ~(uint8_t)0x00)  ? 1 : 0;
	pokelen = (v >= 0x000000ff && v < ~(uint16_t)0x00) ? 2 : 0;
	pokelen = (v >= 0x0000ffff && v < ~(uint32_t)0x00) ? 4 : 0;
	pokelen = (v >= 0xffffffff && v < ~(uint64_t)0x00) ? 8 : 0;

	if (shiva_maps_prot_by_addr(ctx, (uint64_t)addr, &o_prot) == false) {
		shiva_error_set(error, "poke pid (%d) at %#lx failed: "
		    "cannot find memory protection\n", pid, (uint64_t)addr);
		return false;
	}
	aligned_vaddr = (uint64_t)addr;
	aligned_vaddr &= ~4095;
	/*
	 * Make virtual address writable if it is not.
	 */
	ret = mprotect((void *)aligned_vaddr, 4096, PROT_READ|PROT_WRITE);
	if (ret < 0) {
		shiva_error_set(error, "poke pid (%d) at %#lx failed: "
		    "mprotect failure: %s\n", pid, (uint64_t)addr, strerror(errno));
		return false;
	}
	/*
	 * Copy data to target addr
	 */
	memcpy(addr, data, pokelen);
	/*
	 * Reset memory protection
	 */
	ret = mprotect((void *)aligned_vaddr, 4096, o_prot);
	if (ret < 0) {
		shiva_error_set(error, "poke pid (%d) at %#lx failed: "
		    "mprotect failure: %s\n", pid, (uint64_t)addr, strerror(errno));
		return false;
	}

	return true;
}

static bool
shiva_trace_op_peek(struct shiva_ctx *ctx, pid_t pid,
    void *addr, void *data, shiva_error_t *error)
{

	if (shiva_maps_validate_addr(ctx, (uint64_t)addr) == false) {
		shiva_error_set(error, "peek pid (%d) at %#lx failed: "
		    "cannot read from debugger memory\n", pid, (uint64_t)addr);
		return false;
	}
	memcpy(data, addr, sizeof(uint64_t));
	return true;
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
	case SHIVA_TRACE_OP_PEEK:
		res = shiva_trace_op_peek(ctx, pid, addr, data, error);
		break;
#if 0
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
	printf("Returning: %d\n", res);
	return res;
}
