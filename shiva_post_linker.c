#include "shiva.h"

#define TRANSFER_TO_X86_64_START(addr) __asm__ __volatile__("push %0\n" \
							    "ret" :: "g"(addr));
/*
 * The aarch64 post linker in Shiva works by hooking AT_ENTRY early on (In
 * shiva_module.c:apply_relocation), so that it is set to &shiva_post_linker()
 * instead of the &_start() of the target program. Let's look at the few lines of
 * code leading up to 'br _&start' in ld-linux.so:
 *
 * ld-linux.so code:
 *
 * 0x1001240:	bl	0x100dab8 ; branch with a link sets x30 to 0x1001244
 * 0x1001244:	adrp	x0, 0x100d000
 * 0x1001248:	add	x0, x0, #0xc08
 * 0x100124c:	br	x21  ; jump to _start() has been hooked to jump to &shiva_post_linker
 *
 * Control is transferred to our function below, which runs after ld-linux.so has loaded
 * and linked it's libaries, therefore we use shiva_maps_get_so_base() to acquire the
 * base address of the library for the symbol we are resolving. We resolve the symbol
 * value by applying the delayed relocation value to the rel_unit.
 *
 * Once we are done, we reset $x21 directly with the value of the real &_start.
 * shiva_post_linker() returns... not to the instruction after '0x100124c:   br      x21'
 * because no branch-link was set. Therefore we return to 0x1001244, and with
 * an updated $x21 we now jump to &_start
 *
 * shiva_post_linker() must specifically handle each linker architecture.
 */

void
shiva_post_linker(void)
{
	static struct shiva_module_delayed_reloc *delay_rel;
	static uint64_t base;

	TAILQ_FOREACH(delay_rel, &ctx_global->module.runtime->tailq.delayed_reloc_list, _linkage) {
		printf("Passing so_path: %s\n", delay_rel->so_path);
		if (shiva_maps_get_so_base(ctx_global, delay_rel->so_path, &base) == false) {
			fprintf(stderr, "Failed to locate base address of loaded module '%s'\n",
			    delay_rel->so_path);
			exit(EXIT_FAILURE);
		}
		shiva_debug("Post linking '%s'\n", delay_rel->symname);
		/*
		 * Apply the final relocation value on our delayed
		 * relocation entry.
		 */
		*(uint64_t *)delay_rel->rel_unit = delay_rel->symval + base;

		shiva_debug("%#lx:rel_unit = %#lx + %#lx (%#lx)\n", delay_rel->rel_addr,
		    delay_rel->symval, base, delay_rel->symval + base);
	}

	shiva_debug("Transfering control to %#lx\n", ctx_global->ulexec.entry_point);
	test_mark();

	/*
	 * Mark the text segment as read-only now that there won't
	 * be any final fixups in the modules .text.
	 */
	if (mprotect(ctx_global->module.runtime->text_mem,
	    ELF_PAGEALIGN(ctx_global->module.runtime->text_size,
	    PAGE_SIZE),
	    PROT_READ|PROT_EXEC) < 0) {
		fprintf(stderr, "shiva_post_linker() Unable to mark text as read-only\n");
		perror("mprotect");
		exit(EXIT_FAILURE);
	}
#ifdef __x86_64__
	__asm__ __volatile__("mov %0, %%r12" :: "r"(ctx_global->ulexec.entry_point));
	TRANSFER_TO_X86_64_START(ctx_global->ulexec.entry_point);
#elif __aarch64__
	__asm__ __volatile__ ("mov x21, %0" :: "r"(ctx_global->ulexec.entry_point));
#endif
	return;
}

