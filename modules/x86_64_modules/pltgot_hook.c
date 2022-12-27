/*
 * This module demonstrates the pltgot hooking mechanism.
 * The symbol 'puts@plt' is hijacked via the GOT pointer
 * and redirected to (*n_puts)() handler. This is does using
 * the Shiva trace API.
 */

#include "../shiva.h"

int n_puts(const char *s)
{
	char buf[PATH_MAX];
	/*
	 * Modify the string passed to puts()
	 */
	snprintf(buf, sizeof(buf), "hijacked your string: '%s'", s);

	/*
	 * Call the original puts with our modified string.
	 * NOTE: We hijacked puts from libc.so via the PLT hook,
	 * but we are actually invoking puts() from inside the
	 * body of code in the Shiva executable, since relocations
	 * are mapped between the module and shiva. So we are
	 * invoking the musl-libc puts() that is already built into
	 * /bin/Shiva.
	 */
	return puts(buf);
}

int
shakti_main(shiva_ctx_t *ctx)
{
	bool res;
	shiva_error_t error;

	res = shiva_trace(ctx, 0, SHIVA_TRACE_OP_ATTACH,
	    NULL, NULL, 0, &error);
	if (res == false) {
		printf("shiva_trace failed: %s\n", shiva_error_msg(&error));
		return -1;
	}
	res = shiva_trace_register_handler(ctx, (void *)&n_puts,
	    SHIVA_TRACE_BP_PLTGOT, &error);
	if (res == false) {
		printf("shiva_register_handler failed: %s\n",
		    shiva_error_msg(&error));
		return -1;
	}
	res = shiva_trace_set_breakpoint(ctx, (void *)&n_puts,
	    0, "puts", &error);
	if (res == false) {
		printf("shiva_trace_set_breakpoint failed: %s\n", shiva_error_msg(&error));
		return -1;
	}
	return 0;
}

