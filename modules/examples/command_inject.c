/*
 * This module demonstrates the pltgot hooking mechanism.
 * The symbol 'puts@plt' is hijacked via the GOT pointer
 * and redirected to (*n_puts)() handler. This is does using
 * the Shiva trace API.
 */

#include "../shiva.h"

int n_system(const char *s)
{

	printf("s: %s\n", s);
	if (strstr(s, ";") != NULL || strstr(s, "|") != NULL) {
		printf("Detected possible OS command injection attack '%s'\n", s);
		abort();
	}
	return system(s);
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
	res = shiva_trace_register_handler(ctx, (void *)&n_system,
	    SHIVA_TRACE_BP_PLTGOT, &error);
	if (res == false) {
		printf("shiva_register_handler failed: %s\n",
		    shiva_error_msg(&error));
		return -1;
	}
	res = shiva_trace_set_breakpoint(ctx, (void *)&n_system,
	    0, "system", &error);
	if (res == false) {
		printf("shiva_trace_set_breakpoint failed: %s\n", shiva_error_msg(&error));
		return -1;
	}
	return 0;
}

