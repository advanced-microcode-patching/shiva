GCC_OPTS= -fPIC -c -ggdb
OBJ_LIST=shiva.o shiva_util.o shiva_signal.o shiva_ulexec.o shiva_auxv.o	\
    shiva_module.o shiva_trace.o shiva_trace_thread.o shiva_error.o shiva_maps.o shiva_analyze.o \
    shiva_callsite.o

STATIC_LIBS=/opt/elfmaster/lib/libelfmaster.a udis86/libudis86/.libs/libudis86.a

all:
	$(CC) $(GCC_OPTS) shiva.c -o		shiva.o
	$(CC) $(GCC_OPTS) shiva_util.c -o 	shiva_util.o
	$(CC) $(GCC_OPTS) shiva_signal.c -o	shiva_signal.o
	$(CC) $(GCC_OPTS) shiva_ulexec.c -o	shiva_ulexec.o
	$(CC) $(GCC_OPTS) shiva_auxv.c -o	shiva_auxv.o
	$(CC) $(GCC_OPTS) shiva_module.c -o	shiva_module.o
	$(CC) $(GCC_OPTS) shiva_trace.c -o	shiva_trace.o
	$(CC) $(GCC_OPTS) shiva_trace_thread.c -o shiva_trace_thread.o
	$(CC) $(GCC_OPTS) shiva_error.c	-o	shiva_error.o
	$(CC) $(GCC_OPTS) shiva_maps.c -o	shiva_maps.o
	$(CC) $(GCC_OPTS) shiva_analyze.c -o	shiva_analyze.o
	$(CC) $(GCC_OPTS) shiva_callsite.c -o 	shiva_callsite.o
	$(CC) -static -Wl,-undefined=putchar $(OBJ_LIST) $(STATIC_LIBS) -o shiva
test:
	gcc test.c -o test -fcf-protection=none
clean:
	rm -f test
	rm -f *.o
	rm -f shiva
