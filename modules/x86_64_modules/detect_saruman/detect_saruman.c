/*
 * Arcana Research, 2026
 * Shiva module that runs directly after ld-linux.so finishes
 * Detects and prevents potentially malicious thread injection (i.e. Saruman)
 * Elfmaster [at] Arcana-Research.io
 */

#define _GNU_SOURCE
#include "shiva_module.h"
#include "shiva.h"
#include "libelfmaster.h"

#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <sched.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stddef.h>

#ifndef SECCOMP_IOCTL_NOTIF_RECV
#define SECCOMP_IOCTL_NOTIF_RECV SECCOMP_IOWR(0, struct seccomp_notif)
#define SECCOMP_IOCTL_NOTIF_SEND SECCOMP_IOWR(1, struct seccomp_notif_resp)
#endif
#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1U << 0)
#endif

#define SARUMAN_CORE (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND)

#define PTHREAD_HINT \
    (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | \
     CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS | \
     CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID)

pid_t listener_tid;
struct shiva_ctx *g_ctx;
volatile int notify_fd = -1;

#ifndef __NR_clone3
#define __NR_clone3 435
#endif

struct clone_args {
	uint64_t flags;
	uint64_t pidfd;
	uint64_t child_tid;
	uint64_t parent_tid;
	uint64_t exit_signal;
	uint64_t stack;
	uint64_t stack_size;
	uint64_t tls;
};

#include <stdint.h>
#include <linux/prctl.h>

#define __NR_prctl 157

#define __NR_seccomp 317

#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif

#define __NR_process_vm_readv 310
#define __NR_exit	      60

struct iovec_raw {
    void  *iov_base;
    unsigned long iov_len;
};


static long
write_raw(int fd, const void *buf, unsigned long n)
{
        long r;

        asm volatile("syscall"
            : "=a"(r)
            : "a"(1L), "D"((long)fd), "S"((long)buf), "d"(n)
            : "rcx", "r11", "memory");
        return (r);
}

void
print_msg(const char *fmt, ...)
{
        char buf[512];
        va_list ap;
        int n;

        va_start(ap, fmt);
        n = vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        if (n > (int)sizeof(buf) - 1)
                n = (int)sizeof(buf) - 1;
        if (n > 0)
                write_raw(2, buf, (unsigned long)n);
}

long
process_vm_readv_raw(long pid,
		     const struct iovec_raw *local, unsigned long liovcnt,
		     const struct iovec_raw *remote, unsigned long riovcnt,
		     unsigned long flags)
{
	long ret;
	register long r10 asm("r10") = (long)remote;
	register long r8  asm("r8")  = (long)riovcnt;
	register long r9  asm("r9")  = (long)flags;

	asm volatile(
	"syscall"
	: "=a"(ret)
	: "a"((long)__NR_process_vm_readv),
	  "D"(pid),
	  "S"((long)local),
	  "d"(liovcnt),
	  "r"(r10), "r"(r8), "r"(r9)
	: "rcx", "r11", "memory"
	);
	return ret;
}

long
seccomp_raw(unsigned int op, unsigned int flags, void *args)
{
	long ret;
	asm volatile("syscall"
	    : "=a"(ret)
	    : "a"(317L), "D"((long)op), "S"((long)flags), "d"((long)args)
	    : "rcx", "r11", "r8", "r9", "r10", "memory");
	return ret;
}

long
raw_prctl(long option, long a2, long a3, long a4, long a5)
{
	long ret;
	register long r10 asm("r10") = a4;
	register long r8  asm("r8")  = a5;
	register long r9  asm("r9")  = 0;

	asm volatile(
	"syscall"
	: "=a"(ret)
	: "a"((long)__NR_prctl),
	  "D"(option),
	  "S"(a2),
	  "d"(a3),
	  "r"(r10),
	  "r"(r8),
	  "r"(r9)
	: "rcx", "r11", "memory"
	);
	return ret;
}

pid_t
gettid_raw(void)
{
	return (pid_t)syscall(SYS_gettid);
}

static int
install_filter(void)
{
	static struct sock_filter filt[] = {
		BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS,
		 offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

		BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS,
		 offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 56,  2, 0),   /* clone */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 435, 1, 0),   /* clone3 */
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
	};
	static struct sock_fprog prog;
	long r;

	prog.len = (unsigned short)(sizeof(filt) / sizeof(filt[0]));
	prog.filter = filt;

	r = raw_prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	if (r < 0) {
		fprintf(stderr, "prctl() failed\n");
		return -1;
	}

	r = seccomp_raw(1, 8, &prog);
	if (r <= 0) {
		fprintf(stderr, "seccomp() failed\n");
		return -1;
	}

	notify_fd = (int)r;
	return 0;
}

bool
read_clone3_args(pid_t pid, uint64_t uaddr, size_t sz, struct clone_args *out)
{
	struct iovec local = { .iov_base = out, .iov_len = sizeof(*out) };
	struct iovec remote = { .iov_base = (void *)uaddr,
	    .iov_len = sz < sizeof(*out) ? sz : sizeof(*out) };
	ssize_t n;

	memset(out, 0, sizeof(*out));
	n = process_vm_readv_raw(pid, (void *)&local, 1, (void *)&remote, 1, 0);
	return n == (ssize_t)remote.iov_len;
}

/*
 * The flags of the clone we do ourselves in shiva_init()
 */
#define SARUMAN_FLAGS \
	(CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | \
	 CLONE_THREAD | CLONE_SYSVSEM)

bool
classify_clone(uint64_t flags, uint64_t stack, uint64_t tls)
{
	if (stack == 0)
		return false;

	if ((flags & PTHREAD_HINT) == PTHREAD_HINT)
		return false;

	/*
	 * Does this call to clone use the flags that Saruman uses?
	 */
	if ((flags & SARUMAN_FLAGS) == SARUMAN_FLAGS)
		return true;

	(void)tls;
	return false;
}

/*
 * handle_notification runs heuristics to detect whether or not the
 * clone is suspicious.
 */
void
handle_notification(struct seccomp_notif *req, struct seccomp_notif_resp *resp)
{
	uint64_t flags = 0, stack = 0, tls = 0;
	struct clone_args c3;
	bool detected = false;

	resp->id = req->id;
	resp->val = 0;
	resp->error = 0;
	resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;

	if (req->pid == (uint32_t)listener_tid)
		return;

	if (req->data.nr == __NR_clone) {
		flags = req->data.args[0];
		stack = req->data.args[1];
		tls   = req->data.args[4];
		detected = classify_clone(flags, stack, tls);
	} else if (req->data.nr == __NR_clone3) {
		if (read_clone3_args((pid_t)req->pid,
		    req->data.args[0],
		    (size_t)req->data.args[1],
		    &c3)) {
			flags = c3.flags;
			stack = c3.stack;
			tls   = c3.tls;
			detected = classify_clone(flags, stack, tls);
		}
	}

	if (detected == true) {
		print_msg("Detected and prevented suspicious thread injection!"
		    " pid=%d nr=%d flags=0x%lx stack=0x%lx tls=0x%lx\n",
		(int)req->pid, req->data.nr,
		(unsigned long)flags,
		(unsigned long)stack,
		(unsigned long)tls);
		resp->error = -EPERM;
		resp->flags = 0;
	}
	return;
}

long
ioctl_raw(int fd, unsigned long cmd, void *arg)
{
    long r;
    asm volatile("syscall"
	: "=a"(r)
	: "a"(16L), "D"((long)fd), "S"(cmd), "d"((long)arg)
	: "rcx", "r11", "memory");
    return r;
}

int
listener_loop(void *arg)
{
	struct seccomp_notif req;
	struct seccomp_notif_resp resp;

	(void)arg;

	while (notify_fd < 0)
		;
	for (;;) {
		if (ioctl_raw(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0)
			continue;
		handle_notification(&req, &resp);
		(void)ioctl_raw(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, &resp);
	}
}

#define __NR_clone 56

typedef int (*clone_fn_t)(void *);

long
clone_raw(unsigned long flags, void *stack,
    int *parent_tid, int *child_tid, unsigned long tls,
    clone_fn_t fn, void *arg)
{
	long ret;
	register long r10 asm("r10") = (long)child_tid;
	register long r8  asm("r8")  = (long)tls;
	register long rbx_fn asm("rbx") = (long)fn;
	register long r12_arg asm("r12") = (long)arg;

	asm volatile(
	"syscall\n\t"
	"testq %%rax, %%rax\n\t"
	"jnz   1f\n\t"
	"xorq  %%rbp, %%rbp\n\t"
	"andq  $-16, %%rsp\n\t"
	"movq  %%r12, %%rdi\n\t"
	"call  *%%rbx\n\t"
	"movq  %%rax, %%rdi\n\t"
	"movq  $60, %%rax\n\t"
	"syscall\n"
	"1:"
	: "=a"(ret)
	: "a"((long)__NR_clone),
	  "D"((long)flags),
	  "S"((long)stack),
	  "d"((long)parent_tid),
	  "r"(r10), "r"(r8),
	  "r"(rbx_fn), "r"(r12_arg)
	: "rcx", "r11", "r9", "memory"
	);
	return ret;
}

#define STACK_SIZE 4096 * 10

int
shiva_init(struct shiva_ctx *ctx)
{
	long child;
	uint8_t *stack;
	g_ctx = ctx;

	printf("shiva_init invoked\n");

	stack = (uint8_t *)mmap(0, STACK_SIZE,
	    PROT_READ | PROT_WRITE,
	    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if ((long)stack <= 0) {
		fprintf(stderr, "mmap failed to allocate stack\n");
		return -1;
	}

	int ptid = 0;

	child = clone_raw(
	    CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND |
	    CLONE_THREAD | CLONE_SYSVSEM,
	    stack + STACK_SIZE, 0, 0, 0, listener_loop, 0);

	if (child <= 0) {
		fprintf(stderr, "clone failed, child: %ld\n", child);
		return -1;
	}

	if (install_filter() < 0) {
		fprintf(stderr, "install_filter failed!\n");
		return -1;
	}

	return 0;
}
