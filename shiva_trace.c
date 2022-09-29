#include "shiva.h"

static bool shiva_trace_op_peek(struct shiva_ctx *, pid_t,
    void *, void *, size_t, shiva_error_t *);

/*
 * XXX FIXME
 * temporary version.
 */
void __attribute__((naked)) shiva_trace_getregs_x86_64(struct shiva_trace_regset_x86_64 *regs)
{
	__asm__ __volatile__(
		"movq %rax, (%rdi)\n\t"
		"movq %rbx, 8(%rdi)\n\t"
		"movq %rcx, 16(%rdi)\n\t"
		"movq %rdx, 24(%rdi)\n\t"
		"movq %rsi, 32(%rdi)\n\t"
		"movq %r8,  48(%rdi)\n\t"
		"movq %r9,  56(%rdi)\n\t"
		"movq %r10, 64(%rdi)\n\t"
		"movq %r11, 72(%rdi)\n\t"
		"movq %r12, 80(%rdi)\n\t"
		"movq %r13, 88(%rdi)\n\t"
		"movq %r14, 96(%rdi)\n\t"
		"movq %r15, 104(%rdi)\n\t"
		"ret\n\t"
		);
}

/*
 * This is primarily designed for handler functions. This will save the state
 * of the code execution location that triggered the breakpoint handler to run.
 * so that the handler can return execution back to the location where the breakpoint
 * was after it replaces the original instruction.
 */
void __attribute__ ((naked)) shiva_trace_setjmp_x86_64(shiva_trace_jumpbuf_t *jmpbuf)
{
	__asm__ __volatile__(
		"movq %rax, 0(%rdi)\n\t"
		"movq %rbx, 8(%rdi)\n\t"
		"movq %rcx, 16(%rdi)\n\t"
		"movq %rdx, 24(%rdi)\n\t"
		"movq %rsi, 32(%rdi)\n\t"
		"movq %rbp, 48(%rdi)\n\t"
		"lea 8(%rsp), %rdx\n\t"
		"movq %rdx, 56(%rdi)\n\t"
		"movq %r8,  72(%rdi)\n\t"
		"movq %r9,  80(%rdi)\n\t"
		"movq %r10, 88(%rdi)\n\t"
		"movq %r11, 96(%rdi)\n\t"
		"movq %r12, 104(%rdi)\n\t"
		"movq %r13, 112(%rdi)\n\t"
		"movq %r14, 120(%rdi)\n\t"
		"movq %r15, 128(%rdi)\n\t"
		"xor  %rax, %rax\n\t"
		"ret\n\t"
		);
}

void shiva_trace_longjmp_x86_64(shiva_trace_jumpbuf_t *jumpbuf, uint64_t ip)
{

	__asm__ __volatile__(
		"movq 0(%rdi), %rax\n\t"
		"movq 8(%rdi), %rbx\n\t"
		"movq 16(%rdi), %rcx\n\t"
		"movq 24(%rdi), %rdx\n\t"
		"movq 32(%rdi), %rsi\n\t"
		"movq 48(%rdi), %rbp\n\t"
		"movq 56(%rdi), %rsp\n\t"
		"movq 72(%rdi), %r8\n\t"
		"movq 80(%rdi), %r9\n\t"
		"movq 88(%rdi), %r10\n\t"
		"movq 96(%rdi), %r11\n\t"
		"movq 104(%rdi), %r12\n\t"
		"movq 112(%rdi), %r13\n\t"
		"movq 120(%rdi), %r14\n\t"
		"movq 128(%rdi), %r15\n\t");

	__asm__ __volatile__ (
			"movq %0, %%rdx\n\t"
			"jmp *%%rdx" :: "r"(ip));
}

uint64_t
shiva_trace_base_addr(struct shiva_ctx *ctx)
{

	return ctx->ulexec.base_vaddr;
}

/*
 * This function is a wrapper around shiva_trace_op_poke
 */
bool
shiva_trace_write(struct shiva_ctx *ctx, pid_t pid, void *dst,
    const void *src, size_t len, shiva_error_t *error)
{
	size_t aligned_len;
	uint8_t *s = (uint8_t *)src;
	uint8_t *d = (uint8_t *)dst;
	uint64_t aligned_vaddr;
	uint64_t addr = (uint64_t)dst;
	int ret, o_prot;

	if (shiva_maps_prot_by_addr(ctx, (uint64_t)addr, &o_prot) == false) {
	    shiva_error_set(error, "shiva_trace_write pid(%d) at %#lx failed: "
	    "cannot find memory protection\n", pid, (uint64_t)addr);
		return false;
	}
	aligned_vaddr = ELF_PAGESTART((uint64_t)addr);
	aligned_len = ELF_PAGEALIGN(len, PAGE_SIZE);
	if (addr + len > aligned_vaddr + aligned_len) {
		aligned_len += PAGE_SIZE;
	}
	/*
	 * Make virtual address writable if it is not.
	 */
	ret = mprotect((void *)aligned_vaddr, aligned_len, o_prot|PROT_WRITE);
	if (ret < 0) {
		shiva_error_set(error, "poke pid (%d) at %#lx failed: "
		    "mprotect failure: %s\n", pid, (uint64_t)addr, strerror(errno));
		return false;
	}
	shiva_debug("copying %zu bytes from %p to %p\n", len, s, d);
	/*
	 * Copy data to target addr
	 */
	memcpy(d, s, len);
	/*
	 * Reset memory protection
	 */
	ret = mprotect((void *)aligned_vaddr, aligned_len, o_prot);
	if (ret < 0) {
		shiva_error_set(error, "shiva_trace_write_pid(%d) at %#lx failed: "
		    "mprotect failure: %s\n", pid, (uint64_t)addr, strerror(errno));
		return false;
	}
	return true;
}

struct shiva_trace_handler *
shiva_trace_find_handler(struct shiva_ctx *ctx, void *handler)
{
	struct shiva_trace_handler *current = NULL;

	shiva_debug("ctx: %p, handler: %p handler_tqlist: %p\n", ctx, handler,
	    &ctx->tailq.trace_handlers_tqlist);
	TAILQ_FOREACH(current, &ctx->tailq.trace_handlers_tqlist, _linkage) {
		shiva_debug("Testing current: %p handler_fn %p handler %p\n", current, current->handler_fn,
		    handler);
		if (current->handler_fn == handler)
			return current;
	}
	return NULL;
}

bool
shiva_trace_register_handler(struct shiva_ctx *ctx, void * (*handler_fn)(void *),
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

	shiva_debug("Registering handler %p\n", handler_struct->handler_fn);
	TAILQ_INSERT_TAIL(&ctx->tailq.trace_handlers_tqlist, handler_struct, _linkage);
	return true;
}

#define MAX_PLT_RETADDR_COUNT 4096

bool
shiva_trace_set_breakpoint(struct shiva_ctx *ctx, void * (*handler_fn)(void *),
    uint64_t bp_addr, void *option, shiva_error_t *error)
{
	struct shiva_trace_handler *current;
	struct shiva_trace_bp *bp;
	uint8_t *inst_ptr = (uint8_t *)bp_addr;
	size_t insn_len;
	struct elf_symbol symbol;
	uint8_t call_inst[5] = "\xe8\x00\x00\x00\x00";
	uint8_t tramp_inst[12] = "\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x50\xc3";
	uint64_t call_offset, call_site;
	bool res;
	uint64_t trap, qword;
	bool found_handler = false;
	struct elf_plt plt_entry;
	elf_plt_iterator_t plt_iter;
	elf_pltgot_iterator_t pltgot_iter;
	struct elf_pltgot_entry pltgot_entry;
	char *symname;
	int i, signum, bits;
	elf_relocation_iterator_t rel_iter;
	struct elf_relocation rel;
	size_t jmprel_count = 0;
	struct shiva_branch_site *branch_site;

	TAILQ_FOREACH(current, &ctx->tailq.trace_handlers_tqlist, _linkage) {
		if (current->handler_fn == handler_fn) {
			found_handler = true;
			shiva_debug("found handler: %p\n", handler_fn);
			switch(current->type) {
			case SHIVA_TRACE_BP_JMP:
				break;
			case SHIVA_TRACE_BP_SEGV:
				/*
				 * This type of breakpoint is 5 bytes and installs an invalid jmp instruction:
				 * jmp 0xdeadbeef
				 * This triggers a segfault and invokes a handler for SIGSEGV
				 */
				signum = SIGSEGV;
				break;
			case SHIVA_TRACE_BP_SIGILL:
				/*
				 * This breakpoint inserts a two byte ud2 (undefined instruction) to trigger
				 * a SIGILL. \x0f\x0b\
				 */
				signum = SIGILL;
				if (TAILQ_EMPTY(&current->bp_tqlist)) {
					struct sigaction sa;
					/*
					 * Create SIGILL handler out of handler_fn
					 * XXX: future calls to sigaction() within the
					 * target program must be hooked. We can prevent
					 * sigaction from overwriting our debug handler
					 * this way.
					 */
					sa.sa_sigaction = (void *)handler_fn;
					sigemptyset(&sa.sa_mask);
					sa.sa_flags = SA_RESTART | SA_SIGINFO;
					sigaction(SIGILL, &sa, NULL);
					memcpy(&current->sa, &sa, sizeof(sa));
				}
				if (shiva_trace_op_peek(ctx, 0, (void *)bp_addr,
				    &qword, sizeof(uint64_t), error) == false) {
					shiva_error_set(error,
					    "shiva_trace_op_peek() failed to read %#lx\n", bp_addr);
					return false;
				}
				trap = 0x0b0f;
				if (shiva_trace_write(ctx, 0,
				    (void *)bp_addr, &trap, 4, error) == false) {
					shiva_error_set(error,
					    "shiva_trace_write() failed to write to %#lx\n", bp_addr);
					return false;
				}
				bp = calloc(1, sizeof(*bp));
				if (bp == NULL) {
					shiva_error_set(error, "memory allocation failed: %s\n",
					    strerror(errno));
					return false;
				}
				bp->bp_addr = bp_addr;
				bp->bp_len = 2;
				bp->bp_type = current->type;
				shiva_debug("Inserted SIGILL breakpoint: %#lx\n", bp->bp_addr);
				TAILQ_INSERT_TAIL(&current->bp_tqlist, bp, _linkage);
				break;
			case SHIVA_TRACE_BP_INT3:
				/*
				 * Install 0xcc on MSB of 64bit value
				 * i.e. 0xdeadbeef becomes 0xdeadbecc
				 */
				if (TAILQ_EMPTY(&current->bp_tqlist)) {
					struct sigaction sa;
					/*
					 * Create SIGTRAP handler out of handler_fn
					 * XXX: future calls to sigaction() within the
					 * target program must be hooked. We can prevent
					 * sigaction from overwriting our debug handler
					 * this way.
					 */
					sa.sa_sigaction = (void *)handler_fn;
					sigemptyset(&sa.sa_mask);
					sa.sa_flags = SA_RESTART | SA_SIGINFO;
					sigaction(SIGTRAP, &sa, NULL);
					memcpy(&current->sa, &sa, sizeof(sa));
				}
				if (shiva_trace_op_peek(ctx, 0, (void *)bp_addr, &qword, sizeof(uint64_t), error) == false) {
					shiva_error_set(error, "shiva_trace_op_peek() failed to read %#lx\n", bp_addr);
					return false;
				}
				trap = (qword & ~0xff) | 0xcc;
				//*(uint64_t *)&bp->insn.o_insn[0] = qword;
				//*(uint64_t *)&bp->insn.n_insn[0] = trap;

				if (shiva_trace_write(ctx, 0, (void *)bp_addr, &trap, sizeof(uint64_t), error) == false) {
					shiva_error_set(error, "shiva_trace_write() failed to write to %#lx\n", bp_addr);
					return false;
				}
				bp = calloc(1, sizeof(*bp));
				if (bp == NULL) {
					shiva_error_set(error, "memory allocation failed: %s\n",
					    strerror(errno));
					return false;
				}
				bp->bp_addr = bp_addr;
				bp->bp_len = 1;
				bp->bp_type = current->type;
				shiva_debug("Inserted int3 breakpoint: %#lx\n", bp->bp_addr);
				TAILQ_INSERT_TAIL(&current->bp_tqlist, bp, _linkage);
				break;
			case SHIVA_TRACE_BP_PLTGOT:
				if (elf_plt_by_name(&ctx->elfobj, (char *)option, &plt_entry) == false) {
					shiva_error_set(error, "elf_plt_by_name(%p, %s, ...) failed\n",
					    &ctx->elfobj, (char *)option);
					return false;
				}
				elf_pltgot_iterator_init(&ctx->elfobj, &pltgot_iter);
				while (elf_pltgot_iterator_next(&pltgot_iter, &pltgot_entry) == ELF_ITER_OK) {
					if (pltgot_entry.flags & ELF_PLTGOT_PLT_STUB_F) {
						/*
						 * XXX IMPORTANT XXX
						 * If the target binary has a .plt with bound instructions
						 * then the + 6 calculation will not work. Currently our
						 * 'test' target binary is built with -fcf-protection=none
						 * We must add code for compatibility, and libelfmaster's plt
						 * API needs to be updated to handle as well.
						 */
						if (pltgot_entry.value != (plt_entry.addr + 6))
							continue;
						shiva_debug("Patching GOT entry %#lx\n",
						    pltgot_entry.offset + ctx->ulexec.base_vaddr);
						shiva_debug("plt_entry.addr: %#lx\n", plt_entry.addr);
						bp = calloc(1, sizeof(*bp));
						if (bp == NULL) {
							shiva_error_set(error, "memory allocation failed: %s\n",
							    strerror(errno));
							return false;
						}
						/*
						 * This is a PLTGOT hook. So we are actually modifying an fptr (The GOT)
						 * in the data segment. bp_addr is assigned the address of the GOT entry
						 * that we are patching (Instead of a code location like usual).
						 * We may change this convention in the future...
						 */
						shiva_debug("pltgot.offset: %#lx base_vaddr: %#lx\n",
						    pltgot_entry.offset, ctx->ulexec.base_vaddr);
						elf_relocation_iterator_init(&ctx->elfobj, &rel_iter);
						for (i = 0; elf_relocation_iterator_next(&rel_iter, &rel) == ELF_ITER_OK;) {
							if (rel.type != R_X86_64_JUMP_SLOT)
								continue;
							if (rel.offset != pltgot_entry.offset)
								continue;
							symname = rel.symname;
							break;
						}
						if (symname == NULL) {
							shiva_error_set(error, "failed to find symbol for got offset: %#lx\n",
							    pltgot_entry.offset);
							return false;
						}
						bp->bp_type = SHIVA_TRACE_BP_PLTGOT;
						bp->bp_addr = pltgot_entry.offset + ctx->ulexec.base_vaddr;
						uint64_t *gotptr = (uint64_t *)bp->bp_addr;
						memcpy(&bp->o_target, gotptr, sizeof(uint64_t));
						/*
						 * This gotptr value will be an offset, and we must add the base
						 * address to it, atleast with PIE binaries.
						 */
						if (elf_type(&ctx->elfobj) == ET_DYN) {
							bp->o_target += ctx->ulexec.base_vaddr;
						}
						shiva_debug("*gotptr old value: %#lx\n", *gotptr);
						shiva_debug("Setting gotptr(%p) to %p\n", gotptr, handler_fn);
						/*
						 * Currently we only handle PIE target binaries (We must fix this).
						 * Anyway, PIE binaries have GOT values that are computed with the
						 * baes address at runtime. We must patch the GOT with an offset from
						 * the base, and not an absolute address.
						 *
						 * XXX:
						 * Actually scratch this last note out somewhat... yes we normally would
						 * put an offset from the base so that the RTLD could then patch it with
						 * the base offset at runtime, but we are going to instruct RTLD to not
						 * touch this got entry ever again by removing the JUMP_SLOT relocation
						 * record for it.
						 */
						*(uint64_t *)&gotptr[0] = (uint64_t)handler_fn;
						/*
						 * STRICT LINKING (flags: PIE NOW) can be a problem for us since it
						 * will overwrite any PLT hooks that are set.
						 *
						 * Our solution is to create an alternate .rela.plt that excludes the
						 * JUMP_SLOT relocation entry for the symbol we are hooking.
						 *
						 * Update DT_JMPREL to point to our new symbol table.
						 *
						 * Update DT_PLTRELASZ with the updated size of .rela.plt
						 */

						struct elf_section rela_plt;
						Elf64_Rela *rela_plt_ptr;
						struct elf_symbol symbol;

						if (elf_section_by_name(&ctx->elfobj, ".rela.plt", &rela_plt) == false) {
							shiva_error_set(error, "unable to find .rela.plt section\n");
							return false;
						}

						/*
						 * Find the relocation record that we want to modify. It is the JUMP_SLOT
						 * relocation for the symbol related to the .got.plt entry that we are hijacking.
						 */
						memset(&symbol, 0, sizeof(symbol));
						rela_plt_ptr = (Elf64_Rela *)((char *)ctx->ulexec.base_vaddr + rela_plt.offset);
						shiva_debug("rela_plt_ptr: %p\n", rela_plt_ptr);
						if (ctx->altrelocs.jmprel == NULL)
							ctx->altrelocs.jmprel = shiva_malloc(rela_plt.size);
						for (i = 0, jmprel_count = 0; i < rela_plt.size / rela_plt.entsize; i++) {
							if (ELF64_R_TYPE(rela_plt_ptr[i].r_info) != R_X86_64_JUMP_SLOT)
								continue;
							if (elf_symbol_by_index(&ctx->elfobj,
							    ELF64_R_SYM(rela_plt_ptr[i].r_info),
							    &symbol,
							    SHT_DYNSYM) == true) {
								if (strcmp(symbol.name, (char *)option) == 0) {
									memcpy(&bp->symbol, &symbol, sizeof(symbol));
									bp->symbol_location = true;
									continue;
								} else {
									memcpy(ctx->altrelocs.jmprel + jmprel_count,
									    &rela_plt_ptr[i], sizeof(Elf64_Rela));
									jmprel_count++;
								}
							} else {
								shiva_error_set(error, "unable to find dynamic symbol index: %d\n",
								    ELF64_R_SYM(rela_plt_ptr[i].r_info));
								return false;
							}
						}
						if (jmprel_count >= rela_plt.size / rela_plt.entsize) {
							shiva_error_set(error, "unable to properly de-activate relocation record"
							    " '%s'\n", (char *)option);
							return false;
						}
						shiva_debug("Setting DT_JMPREL to %#lx - %#lx = %#lx\n",
						    (uint64_t) ctx->altrelocs.jmprel, ctx->ulexec.base_vaddr,
						   (uint64_t) ctx->altrelocs.jmprel - ctx->ulexec.base_vaddr);

						(void) shiva_target_dynamic_set(ctx, DT_JMPREL,
						    (uint64_t)ctx->altrelocs.jmprel - ctx->ulexec.base_vaddr);
						(void) shiva_target_dynamic_set(ctx, DT_PLTRELSZ,
						    jmprel_count * sizeof(Elf64_Rela));
						shiva_debug("Inserted .got.plt hook breakpoint: %#lx\n", bp->bp_addr);
						/*
						 * We must also set all possible return addresses
						 * for this call <symname>@plt -- keeping track of
						 * this in the 'struct shiva_trace_bp->plt_retaddrs
						 * -- This is important information, because when we
						 *  are within a PLTGOT breakpoint handler we can find
						 *  the associated shiva_trace_bp struct by seeing if
						 *  the current return address (At the top of the stack)
						 *  matches one of the valid retaddrs for the plt call
						 *  associated with the PLT/GOT breakpoint. If the
						 *  retaddr at the top of the stack matches one of
						 *  the addresses in the handlers current_bp->retaddrs_tqlist
						 *  then the handlers current bp struct is the correct
						 *  one and correlates to PLT symbol bp->symbol.name.
						 */
						TAILQ_INIT(&bp->retaddr_list);
						(void) hcreate_r(MAX_PLT_RETADDR_COUNT, &bp->valid_plt_retaddrs);
						TAILQ_FOREACH(branch_site, &ctx->tailq.branch_tqlist, _linkage) {
							char *p;
							size_t copy_len;

							if (strstr(branch_site->symbol.name, "@plt") == NULL)
								continue;
							if (branch_site->branch_type != SHIVA_BRANCH_CALL)
								continue;
							p = strchr(branch_site->symbol.name, '@');
							copy_len = p - branch_site->symbol.name;
							if (strncmp((char *)option, branch_site->symbol.name,
							    copy_len) == 0) {
								struct shiva_addr_struct *addr = shiva_malloc(sizeof(*addr));
								/*
								 * We found a branch site (A call) that calls
								 * the PLT symbol that we are hooking via
								 * PLTGOT. Add the retaddr to the the current
								 * breakpoints 'valid_plt_retaddrs' cache.
								 */
								addr->addr = branch_site->retaddr + shiva_trace_base_addr(ctx);
								TAILQ_INSERT_TAIL(&bp->retaddr_list, addr, _linkage);
								/*
								 * Set the PLT address that corresponds to our PLTGOT hook
								 */
								bp->plt_addr = branch_site->target_vaddr;
								
#if 0
								/*
								 * We cannot use an hcreate cache because there's
								 * some incompatibility when using it cross module
								 * execution.
								 */
								val = branch_site->retaddr + ctx->ulexec.base_vaddr;
								sprintf(tmp, "%#lx", val);
								memcpy(ptr_val, &val, sizeof(val));
								e.key = (char *)tmp;
								e.data = (void *)ptr_val;
								printf("Adding PLT retaddr %s to cache\n", e.key);
								printf("data: %#lx\n", *(uint64_t *)e.data);
								if (hsearch_r(e, ENTER, &ep, &bp->valid_plt_retaddrs) == 0) {
									shiva_error_set(error, "hsearch_r failed: %s\n",
									    strerror(errno));
									return false;
								}
								if (hsearch_r(e, FIND, &ep, &bp->valid_plt_retaddrs) != 0) {
									printf("FOUND IT: data: %#lx\n", *(uint64_t *)e.data);
								}
#endif
							}
						}
						TAILQ_INSERT_TAIL(&current->bp_tqlist, bp, _linkage);
						return true;
					}
				}
				break;
			case SHIVA_TRACE_BP_TRAMPOLINE:
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
				if (elf_symbol_by_value_lookup(&ctx->elfobj,
				    bp_addr - shiva_trace_base_addr(ctx), &symbol) == true) {
					bp->symbol_location = true;
					memcpy(&bp->symbol, &symbol, sizeof(symbol));
					bp->call_target_symname = (char *)symbol.name;
				}
				memcpy(&bp->insn.o_insn[0], (void *)bp_addr, sizeof(tramp_inst));
				*(uint64_t *)&tramp_inst[2] = (uint64_t)handler_fn;
				memcpy(&bp->insn.n_insn[0], tramp_inst, sizeof(tramp_inst));
				bp->bp_addr = bp_addr;
				bp->bp_len = sizeof(tramp_inst);
				bp->bp_type = current->type;
				res = shiva_trace_write(ctx, 0, (void *)bp_addr, tramp_inst, bp->bp_len,
				    error);
				if (res == false) {
					free(bp);
					return false;
				}
				/*
				 * Set a valid list of return addresses for the function we are
				 * setting a trampoline hook on. This control flow information is
				 * created by shiva_analyze.c:shiva_analyze_find_calls()
				 */
				TAILQ_INIT(&bp->retaddr_list);
				TAILQ_FOREACH(branch_site, &ctx->tailq.branch_tqlist, _linkage) {
					if (branch_site->branch_type != SHIVA_BRANCH_CALL)
						continue;
					if ((branch_site->target_vaddr + shiva_trace_base_addr(ctx)) ==
					    (uint64_t)bp_addr) {
						struct shiva_addr_struct *addr = shiva_malloc(sizeof(*addr));

						addr->addr = branch_site->retaddr + shiva_trace_base_addr(ctx);
						shiva_debug(
						    "Setting trampoline retaddr for call to %#lx: retaddr: %lx\n",
						    (uint64_t)bp_addr, addr->addr);

						TAILQ_INSERT_TAIL(&bp->retaddr_list, addr, _linkage);
					}
				}
				shiva_debug("Inserted breakpoint: %#lx\n", bp->bp_addr);
				TAILQ_INSERT_TAIL(&current->bp_tqlist, bp, _linkage);
				break;
			case SHIVA_TRACE_BP_CALL: /* This hooks imm32 calls, and only works in mcmodel=small scenarios */
#ifndef SHIVA_STANDALONE
				shiva_error_set(error, "SHIVA_TRACE_BP_CALL incompatible with Shiva-LDSO. Please use"
				    " Shiva in standalone mode.");
				return false;
#endif
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
				bp->o_target = (int64_t)bp_addr + (int64_t)bp->o_call_offset + 5;
				bp->o_target &= 0xffffffff;
				bp->bp_type = current->type;
				bp->bp_addr = bp_addr;
				bp->bp_len = 5; // length of breakpoint is size of imm call insn
				bp->callsite_retaddr = bp_addr + bp->bp_len;

				/*
				 * XXX when we start handling non-PIE binaries we will be passing
				 * bp->o_target to find the symbol by absolute symbol name, whereas
				 * right now we are passing o_target - base_addr to get the symbols
				 * offset to look up within the binary.
				 */
				if (elf_symbol_by_value_lookup(&ctx->elfobj,
				    bp->o_target - shiva_trace_base_addr(ctx), &symbol) == true) {
					bp->symbol_location = true;
					memcpy(&bp->symbol, &symbol, sizeof(symbol));
					bp->call_target_symname = (char *)symbol.name;
				} else {
					elf_plt_iterator_init(&ctx->elfobj, &plt_iter);
					while (elf_plt_iterator_next(&plt_iter, &plt_entry) == ELF_ITER_OK) {
						if ((bp->o_target - shiva_trace_base_addr(ctx)) == plt_entry.addr) {
							bp->call_target_symname = shiva_xfmtstrdup("%s@plt", plt_entry.symname);
						}
					}
					if (bp->call_target_symname == NULL) {
						bp->call_target_symname = shiva_xfmtstrdup("fn_%#lx",
						    bp->o_target);
					}
				}
				call_site = bp_addr;
				call_offset = ((uint64_t)current->handler_fn - call_site - 5);
				call_offset &= 0xffffffff;
				*(uint32_t *)&call_inst[1] = call_offset;
				shiva_debug("call_offset = %#lx - %#lx - 5: %#lx\n", current->handler_fn,
				    call_site, call_offset);
				res = shiva_trace_write(ctx, 0, (void *)bp_addr, call_inst, bp->bp_len,
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
	if (found_handler == false) {
		shiva_error_set(error, "unable to find handler %p\n", handler_fn);
		return false;
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
#if 0
	if (shiva_maps_validate_addr(ctx, (uint64_t)addr) == false) {
		shiva_error_set(error, "peek pid (%d) at %#lx failed: "
		    "cannot read from debugger memory\n", pid, (uint64_t)addr);
		return false;
	}
#endif
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
