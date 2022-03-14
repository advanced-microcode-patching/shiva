#include "shiva.h"

static bool
shiva_trace_thread_status(struct shiva_ctx *ctx, pid_t pid,
    struct shiva_trace_thread *thread)
{
	struct shiva_trace_thread *current;
	char filepath[64], buf[PATH_MAX];
	FILE *fp;

	TAILQ_FOREACH(current, &ctx->tailq.thread_tqlist, _linkage) {
		if (current->pid == pid) {
			memcpy(thread, current, sizeof(*thread));
			return true;
		}
	}
	snprintf(filepath, 64, "/proc/%d/status", pid);
	fp = fopen(filepath, "r");
	if (fp == NULL) {
		perror("fopen");
		return false;
	}
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		char *p;

		p = strchr(buf, ':') + 1;
		while (*p == ' ')
			p++;
		if (strncmp(buf, "Name:", 5) == 0) {
			thread->name = strdup(buf);
			if (thread->name == NULL) {
				perror("strdup");
				return false;
			}
		} else if (strncmp(buf, "Gid", 3) == 0) {
			thread->gid = strtoul(buf, NULL, 10);
		} else if (strncmp(buf, "TracerPid", 9) == 0) {
			thread->external_tracer_pid = strtoul(buf, NULL, 10);
			if (thread->external_tracer_pid != 0) {
				thread->flags |= SHIVA_TRACE_THREAD_F_EXTERN_TRACER;
			} else {
				thread->flags |= SHIVA_TRACE_THREAD_F_TRACED;
			}
		} else if (strncmp(buf, "Uid", 3) == 0) {
			thread->uid = strtoul(buf, NULL, 10);
		} else if (strncmp(buf, "PPid", 4) == 0) {
			thread->ppid = strtoul(buf, NULL, 10);
		} else if (strncmp(buf, "CoreDumping", 11) == 0) {
			thread->flags |= SHIVA_TRACE_THREAD_F_COREDUMPING;
		}
	}
	return true;
}
				
bool
shiva_trace_thread_insert(struct shiva_ctx *ctx, pid_t pid)
{
	struct shiva_trace_thread *thread;

	thread = calloc(1, sizeof(*thread));
	if (thread == NULL) {
		perror("calloc");
		return false;
	}
	if (shiva_trace_thread_status(ctx, pid, thread) == false) {
		fprintf(stderr, "shiva_pthread_thread_status() failed on pid: %d\n", pid);
		return false;
	}
	/*
	 * If the pid is coredumping or is already being traced by sys_ptrace
	 * then we cannot insert it into the threadlist (Unless it is pid 0).
	 * Any threads other than pid 0 require ptrace. In single threaded
	 * processes we only use in-process tracing (No sys_ptrace) which
	 * means that we can shiva_trace() the main debuggee process even
	 * if it is being ptrace'd.
	 */
	if (pid != 0) {
		if ((thread->flags & SHIVA_TRACE_THREAD_F_EXTERN_TRACER) ||
		    (thread->flags & SHIVA_TRACE_THREAD_F_COREDUMPING))
			return false;
	}
	TAILQ_INSERT_TAIL(&ctx->tailq.thread_tqlist, thread, _linkage);
	return true;
}
