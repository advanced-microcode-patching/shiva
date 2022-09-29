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
	if (pid == 0) {
		snprintf(filepath, 64, "/proc/self/status");
	} else {
		snprintf(filepath, 64, "/proc/%d/status", pid);
	}
	shiva_debug("Opening: %s\n", filepath);
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
			shiva_debug("Thread name: %s\n", p);
			thread->name = shiva_strdup(p);
			if (thread->name == NULL) {
				perror("strdup");
				return false;
			}
		} else if (strncmp(buf, "Gid", 3) == 0) {
			thread->gid = strtoul(p, NULL, 10);
			shiva_debug("Thread gid: %d\n", thread->gid);
		} else if (strncmp(buf, "TracerPid", 9) == 0) {
			thread->external_tracer_pid = strtoul(p, NULL, 10);
			shiva_debug("Thread tracer pid: %d\n", thread->external_tracer_pid);
			if (thread->external_tracer_pid != 0) {
				thread->flags |= SHIVA_TRACE_THREAD_F_EXTERN_TRACER;
			} else {
				thread->flags |= SHIVA_TRACE_THREAD_F_TRACED;
			}
		} else if (strncmp(buf, "Uid", 3) == 0) {
			thread->uid = strtoul(p, NULL, 10);
			shiva_debug("Thread uid: %d\n", thread->uid);
		} else if (strncmp(buf, "PPid", 4) == 0) {
			thread->ppid = strtoul(p, NULL, 10);
			shiva_debug("Thread ppid: %d\n", thread->ppid);
		} else if (strncmp(buf, "CoreDumping", 11) == 0) {
			thread->flags |= SHIVA_TRACE_THREAD_F_COREDUMPING;
		}
	}
	thread->flags |= SHIVA_TRACE_THREAD_F_NEW;
	shiva_debug("Returning true\n");
	return true;
}
				
bool
shiva_trace_thread_insert(struct shiva_ctx *ctx, pid_t pid, uint64_t *out)
{
	struct shiva_trace_thread *thread;

	thread = calloc(1, sizeof(*thread));
	if (thread == NULL) {
		perror("calloc");
		return false;
	}
	if (shiva_trace_thread_status(ctx, pid, thread) == false) {
		fprintf(stderr, "shiva_pthread_thread_status() failed on pid: %d\n", pid);
		free(thread);
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
	*out = 0;
	if (pid != 0) {
		if (thread->flags & SHIVA_TRACE_THREAD_F_EXTERN_TRACER) {
			if (out != NULL) {
				*out |= SHIVA_TRACE_THREAD_F_EXTERN_TRACER;
				free(thread);
				shiva_debug("has external tracer, ret false\n");
				return false;
			}
		} else if (thread->flags & SHIVA_TRACE_THREAD_F_COREDUMPING) {
			if (out != NULL) {
				*out |= SHIVA_TRACE_THREAD_F_COREDUMPING;
				free(thread);
				shiva_debug("coredumping, ret false\n");
				return false;
			}
		}
	}
	if (thread->flags & SHIVA_TRACE_THREAD_F_NEW) {
		shiva_debug("Inserting new thread\n");
		TAILQ_INSERT_TAIL(&ctx->tailq.thread_tqlist, thread, _linkage);
		thread->flags &= ~SHIVA_TRACE_THREAD_F_NEW;
	}
	shiva_debug("Returning true\n");
	return true;
}
