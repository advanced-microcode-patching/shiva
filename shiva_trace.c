#include "shiva.h"

static bool shiva_trace_op_peek(struct shiva_ctx *, pid_t,
    void *, void *, size_t, shiva_error_t *);

/*
 * XXX FIXME
 * temporary version.
 */
#if __x86_64__
void __attribute__((naked))
shiva_trace_getregs_x86_64(struct shiva_trace_regset_x86_64 *regs)
{
	__asm__ __volatile__(
		"movq %rax, 0(%rdi)\n\t"
		"movq %rbx, 8(%rdi)\n\t"
		"movq %rcx, 16(%rdi)\n\t"
		"movq %rdx, 24(%rdi)\n\t"
		"movq %rsi, 32(%rdi)\n\t"
		/* 40(%rdi) is rdi; */
		"movq %rbp, 48(%rdi)\n\t"
		"leaq 8(%rsp), %rax\n\t"
		"movq %rax, 56(%rdi)\n\t"	   /* caller rsp */
		"movq (%rsp), %rax\n\t"
		"movq %rax, 64(%rdi)\n\t"	   /* return rip */
		"movq %r8,  72(%rdi)\n\t"
		"movq %r9,  80(%rdi)\n\t"
		"movq %r10, 88(%rdi)\n\t"
		"movq %r11, 96(%rdi)\n\t"
		"movq %r12, 104(%rdi)\n\t"
		"movq %r13, 112(%rdi)\n\t"
		"movq %r14, 120(%rdi)\n\t"
		"movq %r15, 128(%rdi)\n\t"
		"pushfq\n\t"
		"popq %rax\n\t"
		"movq %rax, 136(%rdi)\n\t"	   /* flags */
		"xorl %eax, %eax\n\t"
		"movw %cs, %ax\n\t"
		"movq %rax, 144(%rdi)\n\t"
		"movw %ss, %ax\n\t"
		"movq %rax, 152(%rdi)\n\t"
		"movw %fs, %ax\n\t"
		"movq %rax, 160(%rdi)\n\t"
		"movw %ds, %ax\n\t"
		"movq %rax, 168(%rdi)\n\t"
		"movq 0(%rdi), %rax\n\t"	   /* put the saved rax back */
		"ret\n\t"
	);
}

void __attribute__((naked))
shiva_trace_setregs_x86_64(struct shiva_trace_regset_x86_64 *regs)
{
	__asm__ __volatile__(
		"movq 136(%rdi), %rax\n\t"
		"pushq %rax\n\t"
		"popfq\n\t"		       /* flags */
		"movq 0(%rdi), %rax\n\t"
		"movq 8(%rdi), %rbx\n\t"
		"movq 16(%rdi), %rcx\n\t"
		"movq 24(%rdi), %rdx\n\t"
		"movq 32(%rdi), %rsi\n\t"
		"movq 48(%rdi), %rbp\n\t"
		"movq 72(%rdi), %r8\n\t"
		"movq 80(%rdi), %r9\n\t"
		"movq 88(%rdi), %r10\n\t"
		"movq 96(%rdi), %r11\n\t"
		"movq 104(%rdi), %r12\n\t"
		"movq 112(%rdi), %r13\n\t"
		"movq 120(%rdi), %r14\n\t"
		"movq 128(%rdi), %r15\n\t"
		"movq 56(%rdi), %rsp\n\t"      /* caller rsp from getregs */
		"jmp *64(%rdi)\n\t"	       /* saved rip From getregs */
	);
}

void __attribute__((naked))
shiva_trace_setregs_x86_64_rip(struct shiva_trace_regset_x86_64 *regs, uint64_t rip)
{
    __asm__ __volatile__(
        "movq %rsi, %r11\n\t"		/* MUST be first — save the argument */
        "movq 136(%rdi), %rax\n\t"
        "pushq %rax\n\t"
        "popfq\n\t"
        "movq 0(%rdi), %rax\n\t"
        "movq 8(%rdi), %rbx\n\t"
        "movq 16(%rdi), %rcx\n\t"
        "movq 24(%rdi), %rdx\n\t"
        "movq 32(%rdi), %rsi\n\t"	/* safe to clobber %rsi now */
        "movq 48(%rdi), %rbp\n\t"
        "movq 72(%rdi), %r8\n\t"
        "movq 80(%rdi), %r9\n\t"
        "movq 88(%rdi), %r10\n\t"
        "movq 104(%rdi), %r12\n\t"
        "movq 112(%rdi), %r13\n\t"
        "movq 120(%rdi), %r14\n\t"
        "movq 128(%rdi), %r15\n\t"
        "movq 56(%rdi), %rsp\n\t"
        "jmp *%r11\n\t"			/* jump to the stashed RIP */
    );
}

/*
 * This is primarily designed for handler functions. This will save the state
 * of the code execution location that triggered the breakpoint handler to run.
 * so that the handler can return execution back to the location where the breakpoint
 * was after it replaces the original instruction.
 */
void __attribute__ ((naked))
shiva_trace_setjmp_x86_64(shiva_trace_jumpbuf_t *jmpbuf)
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

void __attribute__((naked))
shiva_trace_longjmp_x86_64(shiva_trace_jumpbuf_t *jmpbuf, uint64_t ip)
{
	__asm__ __volatile__(
		"movq %rsi, 40(%rdi)\n\t"      /* ip stored stored at [rdi + 40] */
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
		"movq 128(%rdi), %r15\n\t"
		"jmp *40(%rdi)\n\t"	       /* rdi still points at the buffer */
		);
}
#endif

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

static bool
shiva_trace_disable_jumpslot_record(struct shiva_ctx *ctx, struct shiva_trace_bp *bp, const char *symname, shiva_error_t *error)
{

	struct elf_section rela_plt;
	Elf64_Rela *rela_plt_ptr;
	struct elf_symbol symbol;
	size_t jmprel_count = 0;
	size_t i;

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
	/*
	 * We create an entirely new copy of the JUMPSLOT relocation table
	 * in memory, as pointed to by the dynamic tag: DT_JMPREL .
	 * If jmprel == NULL then allocate one on the heap.
	 */
	if (ctx->altrelocs.jmprel == NULL)
		ctx->altrelocs.jmprel = shiva_malloc(rela_plt.size);
	for (i = 0, jmprel_count = 0; i < rela_plt.size / rela_plt.entsize; i++) {
		if (ELF64_R_TYPE(rela_plt_ptr[i].r_info) != R_X86_64_JUMP_SLOT)
			continue;
		if (elf_symbol_by_index(&ctx->elfobj,
		    ELF64_R_SYM(rela_plt_ptr[i].r_info),
		    &symbol,
		    SHT_DYNSYM) == true) {
			if (strcmp(symbol.name, symname) == 0) {
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
		    " '%s'\n", symname);
		return false;
	}
	shiva_debug("Setting DT_JMPREL to %#lx - %#lx = %#lx\n",
	    (uint64_t) ctx->altrelocs.jmprel, ctx->ulexec.base_vaddr,
	    (uint64_t) ctx->altrelocs.jmprel - ctx->ulexec.base_vaddr);

	shiva_target_dynamic_set(ctx, DT_JMPREL,
	    (uint64_t)ctx->altrelocs.jmprel - ctx->ulexec.base_vaddr);
	shiva_debug("Now to DT_PLTRELSZ\n");
	shiva_target_dynamic_set(ctx, DT_PLTRELSZ, jmprel_count * sizeof(Elf64_Rela));
	return true;
}

static bool
shiva_trace_set_handlers_valid_plt_retaddrs(struct shiva_ctx *ctx, struct shiva_trace_bp *bp,
    const char *symname)
{
	struct shiva_branch_site *branch_site;

	TAILQ_INIT(&bp->retaddr_list);

#if 0
	if (hcreate_r(MAX_PLT_RETADDR_COUNT, &bp->valid_plt_retaddrs) != 0)
		return false;
#endif

	TAILQ_FOREACH(branch_site, &ctx->tailq.branch_tqlist, _linkage) {
		char *p;
		size_t copy_len;

		if (branch_site->branch_type != SHIVA_BRANCH_CALL)
			continue;
		if (strstr(branch_site->symbol.name, "@plt") == NULL)
			continue;
		p = strchr(branch_site->symbol.name, '@');
		copy_len = p - branch_site->symbol.name;
		if (strncmp((char *)symname, branch_site->symbol.name,
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
			/*
			 * FIXME: We cannot use an hcreate cache because there's
			 * some incompatibility when using it cross module
			 * execution. Due most likely to hcreate_r() using TLS
			 * before libc has set it up. Do more experimentation
			 */
		}
	}
	return true;
}

static bool
shiva_trace_patch_bp_addr(struct shiva_ctx *ctx, unsigned int type, uint64_t addr,
    char *symname, void * (*handler_fn)(void *), uint64_t *orig_value)
{
	bool valid_address = false;
	int i;
	elf_relocation_iterator_t rel_iter;
	struct elf_relocation rel;
	uint64_t *gotptr = NULL;

	if (type == SHIVA_TRACE_BP_PLTGOT) {
		elf_pltgot_iterator_t pltgot_iter;
		struct elf_pltgot_entry pltgot_entry;

		/*
		 * NOTE: Shiva allows PLTGOT breakpoints on PLT GOT entries
		 * and the reserved entry of __dl_resolve (Incase someone
		 * wants to experimentally hook the __dl_resolve routine).
		 */

		elf_pltgot_iterator_init(&ctx->elfobj, &pltgot_iter);
		while (elf_pltgot_iterator_next(&pltgot_iter, &pltgot_entry) == ELF_ITER_OK) {
			if ((pltgot_entry.flags & ELF_PLTGOT_PLT_STUB_F) ||
			    (pltgot_entry.flags & ELF_PLTGOT_RESERVED_DL_RESOLVE_F)) {
				if (symname == NULL) {
					if (RUNTIME_BASE(pltgot_entry.offset) == addr) {
						valid_address = true;
						gotptr = (uint64_t *)addr;
						*orig_value = *(uint64_t *)gotptr;
						if (mprotect(gotptr, 4096, PROT_READ|PROT_WRITE) != 0) {
							shiva_debug("mprotect failed\n");
							return false;
						}
						*(uint64_t *)gotptr = (uintptr_t)handler_fn;
						break;
					}
				} else {
					elf_relocation_iterator_init(&ctx->elfobj, &rel_iter);
					for (i = 0; elf_relocation_iterator_next(&rel_iter, &rel) == ELF_ITER_OK;) {
						if (rel.type != R_X86_64_JUMP_SLOT)
							continue;
						if (rel.offset == pltgot_entry.offset) {
							gotptr = (uint64_t *)RUNTIME_BASE(pltgot_entry.offset);
							*orig_value = *(uint64_t *)addr;
							mprotect(gotptr, 4096, PROT_READ|PROT_WRITE);
							*(uint64_t *)gotptr = (uintptr_t)handler_fn;
							valid_address = true;
							break;
						}
					}
				}
			}
		}
	}
	if (gotptr != NULL) {
		if (mprotect(addr, 4096, PROT_READ) != 0) {
			shiva_debug("mprotect failed\n");
			return false;
		}
	}

	return valid_address;
}

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
	shiva_error_t error2;

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
				if (option == NULL) {
					struct elf_symbol dsym;
					uint64_t o_target;

					shiva_debug("setting PLTGOT breakpoint by address: %#lx\n", bp_addr);
					/*
					 * If option == NULL, then we are setting a PLTGOT breakpoint by the GOT address
					 * rather than it's symbol name.
					 */
					if (elf_relocation_iterator_init(&ctx->elfobj, &rel_iter) == false) {
						shiva_error_set(error, "elf_relocation_iterator_init failed\n");
						return false;
					}
					for (i = 0; elf_relocation_iterator_next(&rel_iter, &rel) == ELF_ITER_OK;) {
						if (rel.type != R_X86_64_JUMP_SLOT)
							continue;
						if (RUNTIME_BASE(rel.offset) != bp_addr)
							continue;
						symname = rel.symname;
						break;
					}
					if (symname == NULL) {
						shiva_error_set(error, "unable to find symbol for GOT entry at %#lx\n",
						    pltgot_entry.offset);
						return false;
					}
					shiva_debug("symname for PLTGOT address: %s\n", symname);
					shiva_debug("calling shiva_trace_patch_bp_addr()\n");

					if (shiva_trace_patch_bp_addr(ctx, SHIVA_TRACE_BP_PLTGOT, bp_addr, NULL,
					    handler_fn, &o_target) == false) {
						shiva_error_set(error, "%#lx is an invalid pltgot breakpoint address\n", bp_addr);
						return false;
					}
					shiva_debug("allocating breakpoint struct\n");
					bp = calloc(1, sizeof(*bp));
					if (bp == NULL) {
						shiva_error_set(error, "memory allocation failed: %s\n",
						    strerror(errno));
						return false;
					}
					bp->bp_type = SHIVA_TRACE_BP_PLTGOT;
					bp->bp_addr = bp_addr;
					bp->o_target = o_target; // save original GOT value
					shiva_debug("elf_symbol_by_name: %s\n", symname);
					if (elf_symbol_by_name(&ctx->elfobj, symname, &dsym) == false) {
						shiva_error_set(error, "elf_symbol_by_name() failed on %s\n", symname);
						free(bp);
						return false;
					}
					memcpy(&bp->symbol, &dsym, sizeof(struct elf_symbol));
					bp->symbol.name = shiva_strdup(symname);
					bp->symbol_location = true;
				} else {
					/*
					 * option != NULL, so we are setting the breakpoint by the symbol name
					 * in 'char *option' which should be a symbol name from .dynsym that corresponds
					 * to a JUMPSLOT relocation record (GOT entry).
					 */
					uint64_t o_target;
					struct elf_symbol dsym;
					shiva_debug("setting pltgot breakpoint by name: %s\n", symname);
					symname = option;

					if (shiva_trace_patch_bp_addr(ctx, SHIVA_TRACE_BP_PLTGOT, 0, symname,
					    handler_fn, &o_target) == false) {
						shiva_error_set(error, "%#lx is an invalid pltgot breakpoint symbol: %s\n", symname);
						return false;
					}
					bp = calloc(1, sizeof(*bp));
					if (bp == NULL) {
						shiva_error_set(error, "memory allocation failed: %s\n",
						    strerror(errno));
						return false;
					}
					/*
					 * SET bp_addr
					 */
					bp->bp_type = SHIVA_TRACE_BP_PLTGOT;
					bp->o_target = o_target; // save original GOT value
					/*
					 * TODO Set bp->bp_addr
					 */
					if (elf_symbol_by_name(&ctx->elfobj, symname, &dsym) == false) {
						shiva_error_set(error, "elf_symbol_by_name() failed on %s\n", symname);
						free(bp);
						return false;
					}
					memcpy(&bp->symbol, &dsym, sizeof(struct elf_symbol));
					bp->symbol.name = shiva_strdup(symname);
					bp->symbol_location = true;

				}
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

				if (shiva_trace_disable_jumpslot_record(ctx, bp, symname, &error2) == false) {
					shiva_error_set(error, "shiva_trace_disable_jumpslot_record() failed: %s",
					    shiva_error_msg(&error2));
					free(bp);
					return false;
				}
				shiva_debug("Setting valid PLT ret addresses\n");
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
				if (shiva_trace_set_handlers_valid_plt_retaddrs(ctx, bp, symname) == false) {
					shiva_error_set(error, "shiva_trace_set_handler_retaddrs() failed\n");
					return false;
				}
				shiva_debug("Add to breakpoint list\n");
				/*
				 * Insert breakpoint
				 */
				TAILQ_INSERT_TAIL(&current->bp_tqlist, bp, _linkage);
				break;
			case SHIVA_TRACE_BP_TRAMPOLINE:
				bits = elf_class(&ctx->elfobj) == elfclass64 ? 64 : 32;
				insn_len = sizeof(tramp_inst);
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
				/*
				 * Get the original inst
				 */
				bits = elf_class(&ctx->elfobj) == elfclass64 ? 64 : 32;
				insn_len = 5;
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
				memcpy(&bp->insn.o_insn[0], (void *)bp_addr, 5);
				/*
				 * If this is not an immediate call, then we can't set a
				 * immediate call breakpoint using e8.
				 */
				if (bp->insn.o_insn[0] != 0xe8) {
					free(bp);
					continue;
				}
				bp->o_call_offset = *(int32_t *)&bp->insn.o_insn[1];
				bp->o_target = (int64_t)bp_addr + (int64_t)bp->o_call_offset + 5;
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
	case SHIVA_TRACE_OP_GETSIGINFO:
		//res = shiva_trace_op_getsiginfo(ctx, pid, op, addr, data);
		break;
	case SHIVA_TRACE_OP_SETSIGINFO:
		//res = shiva_trace_op_setsiginfo(ctx, pid, op, addr, data);
		break;
	default:
		break;
	}
	return res;
}
