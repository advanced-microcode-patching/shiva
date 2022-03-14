#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <stdint.h>
#include <signal.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/queue.h>
#include <elf.h>
#include <errno.h>

typedef enum shiva_trace_op {
	SHIVA_TRACE_OP_CONT = 0,
	SHIVA_TRACE_OP_POKE,
	SHIVA_TRACE_OP_PEEK,
	SHIVA_TRACE_OP_GETREGS,
	SHIVA_TRACE_OP_SETREGS,
	SHIVA_TRACE_OP_SETFPREGS,
	SHIVA_TRACE_OP_GETSIGINFO,
	SHIVA_TRACE_OP_SETSIGINFO
} shiva_trace_op_t;

