#include "shiva.h"

/*
 * This function is a wrapper around shiva_trace_op_poke
 */
bool
shiva_trace_write(struct shiva_ctx *ctx, pid_t pid, void *dst,
    const void *src, size_t len, shiva_error_t *error)
{
	size_t rem = len % sizeof(void *);
	size_t quot = len / sizeof(void *);
	uint8_t *s = (uint8_t *)src;
	uint8_t *d = (uint8_t *)dst;
	uint64_t aligned_vaddr;
	uint64_t addr = (uint64_t)dst;
	bool res;
	int ret, o_prot;

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
	memcpy(d, s, len);
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

bool
shiva_trace_register_handler(struct shiva_ctx *ctx, void * (*handler_fn)(void *, void *, void *, void *),
    shiva_trace_bp_type_t bp_type, shiva_error_t *error)
{

	struct shiva_trace_handler *handler_struct;
	/*
	 * Let's confirm that the specified handler doesn't exist in the debugger
	 * memory.
	 */
#if 0
	if (shiva_maps_validate_addr(ctx, (uint64_t)handler_fn) == false) {
		shiva_error_set(error, "failed to register handler (%p): "
		   "cannot write to debugger memory\n", handler_fn);
		return false;
	}
#endif
	handler_struct = calloc(1, sizeof(*handler_struct));
	if (handler_struct == NULL) {
		shiva_error_set(error, "memory allocation failed: %s\n", strerror(errno));
		return false;
	}
	handler_struct->handler_fn = handler_fn;
	handler_struct->type = bp_type;
	TAILQ_INIT(&handler_struct->bp_tqlist);

	shiva_debug("INSTALLED BP HANDLER: %p\n", handler_fn);
	TAILQ_INSERT_TAIL(&ctx->tailq.trace_handlers_tqlist, handler_struct, _linkage);
	return true;
}

bool
shiva_trace_set_breakpoint(struct shiva_ctx *ctx, void * (*handler_fn)(struct shiva_ctx *),
    uint64_t bp_addr, shiva_error_t *error)
{
	struct shiva_trace_handler *current;
	struct shiva_trace_bp *bp;
	uint8_t *inst_ptr = (uint8_t *)bp_addr;
	int bits;
	size_t insn_len;
	struct elf_symbol symbol;
	uint8_t call_inst[5] = "\xe8\x00\x00\x00\x00";
	uint64_t call_offset, call_site;
	bool res;
	int pid;
	uint64_t o_call_offset;

	TAILQ_FOREACH(current, &ctx->tailq.trace_handlers_tqlist, _linkage) {
		if (current->handler_fn == handler_fn) {
			shiva_debug("found handler: %p\n", handler_fn);
			switch(current->type) {
			case SHIVA_TRACE_BP_JMP:
				break;
			case SHIVA_TRACE_BP_INT3:
				break;
			case SHIVA_TRACE_BP_CALL:
				/*
				 * Get the original inst
				 */
				ud_set_input_buffer(&ctx->disas.ud_obj, inst_ptr, SHIVA_MAX_INST_LEN);
				bits = elf_class(&ctx->elfobj) == elfclass64 ? 64 : 32;
				insn_len = ud_insn_len(&ctx->disas.ud_obj);
				assert(insn_len <= 15);
				bp = calloc(1, sizeof(*bp));
				if (bp == NULL) {
					shiva_error_set(error, "memory allocation failed: %s\n",
					    strerror(errno));
					return false;
				}
				/*
				 * backup the original instruction.
				 */
				/*
				 * XXX look into why insn_len is 0 after ud_insn_len.
				 */
				memcpy(&bp->insn.o_insn[0], (void *)bp_addr, 5);
				bp->o_call_offset = *(uint32_t *)&bp->insn.o_insn[1];
				shiva_debug("bp_addr: %#lx\n", bp_addr);
				bp->o_target = (int64_t)bp_addr + (int64_t)bp->o_call_offset + 5;
				bp->o_target &= 0xffffffff;
				shiva_debug("old call target: %#lx\n", bp->o_target);
				bp->bp_type = current->type;
				bp->bp_addr = bp_addr;
				bp->bp_len = 5; // length of breakpoint is size of imm call insn
				bp->retaddr = bp_addr + bp->bp_len;

				if (elf_symbol_by_value(&ctx->elfobj, bp->o_target - SHIVA_TARGET_BASE, &symbol) == true) {
					bp->symbol_location = true;
					memcpy(&bp->symbol, &symbol, sizeof(symbol));
					bp->call_target_symname = symbol.name;
				} else {
					elf_plt_iterator_t plt_iter;
					struct elf_plt plt_entry;

					elf_plt_iterator_init(&ctx->elfobj, &plt_iter);
					shiva_debug("PLT iterator\n");
					while (elf_plt_iterator_next(&plt_iter, &plt_entry) == ELF_ITER_OK) {
						if ((bp->o_target - SHIVA_TARGET_BASE) == plt_entry.addr) {
							bp->call_target_symname = plt_entry.symname;
						}
					}
					if (bp->call_target_symname == NULL) {
						bp->call_target_symname = shiva_xfmtstrdup("fn_%#lx\n",
						    bp->o_target);
					}
				}
				call_site = bp_addr;
				call_offset = (uint64_t)current->handler_fn - call_site - 5;
				//printf("calloff = %p - %#lx - 5 = %#lx\n",
				 //   current->handler_fn, call_site, call_offset);
				*(uint32_t *)&call_inst[1] = call_offset;
				res = shiva_trace_write(ctx, pid, (void *)bp_addr, call_inst, bp->bp_len,
				    error);
				if (res == false) {
					free(bp);
					return false;
				}
				shiva_debug("Inserted breakpoint: %#lx\n", bp->bp_addr);
				TAILQ_INSERT_TAIL(&current->bp_tqlist, bp, _linkage);
				break;
			}
		}
	}
	return true;
}

bool
shiva_trace_op_attach(struct shiva_ctx *ctx, pid_t pid,
    void *addr, void *data, size_t len, shiva_error_t *error)
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
    void *addr, void *data, size_t len, shiva_error_t *error)
{

	return true;
}

static bool
shiva_trace_op_peek(struct shiva_ctx *ctx, pid_t pid,
    void *addr, void *data, size_t len, shiva_error_t *error)
{

	if (shiva_maps_validate_addr(ctx, (uint64_t)addr) == false) {
		shiva_error_set(error, "peek pid (%d) at %#lx failed: "
		    "cannot read from debugger memory\n", pid, (uint64_t)addr);
		return false;
	}
        if (shiva_maps_validate_addr(ctx, (uint64_t)addr + len) == false) {
		shiva_error_set(error, "peek pid (%d) at %#lx failed: "
		    "cannot read from debugger memory\n", pid, (uint64_t)addr);
		return false;
	}
	memcpy(data, addr, len);
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
    void *addr, void *data, size_t len, shiva_error_t *error)
{
	bool res;

	switch(op) {
	case SHIVA_TRACE_OP_ATTACH:
		res = shiva_trace_op_attach(ctx, pid, addr, data, len, error);
		break;
	case SHIVA_TRACE_OP_CONT:
		res = shiva_trace_op_cont(ctx, pid, addr, data, len, error);
		break;
	case SHIVA_TRACE_OP_POKE:
		res = shiva_trace_write(ctx, pid, addr, data, len, error);
		break;
	case SHIVA_TRACE_OP_PEEK:
		res = shiva_trace_op_peek(ctx, pid, addr, data, len, error);
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
	return res;
}
