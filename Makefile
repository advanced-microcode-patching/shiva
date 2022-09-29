STANDALONE_DIR = './standalone'
LDSO_DIR = './ldso'

GCC_OPTS_STANDALONE= -fPIC -Wall -ggdb -c -DSHIVA_STANDALONE
GCC_OPTS_LDSO= -fPIC -c -ggdb
OBJ_LIST=shiva.o shiva_util.o shiva_signal.o shiva_ulexec.o shiva_auxv.o	\
    shiva_module.o shiva_trace.o shiva_trace_thread.o shiva_error.o shiva_maps.o shiva_analyze.o \
    shiva_callsite.o shiva_target.o
INTERP_PATH="/home/elfmaster/git/shiva/ldso/shiva"
STATIC_LIBS=/opt/elfmaster/lib/libelfmaster.a libudis86.a

CC=gcc
MUSL=musl-gcc

all: interp standalone
interp:
	[ -d $(LDSO_DIR) ] || mkdir -p $(LDSO_DIR)
	$(CC) $(GCC_OPTS_LDSO) shiva.c -o		shiva.o
	$(CC) $(GCC_OPTS_LDSO) shiva_util.c -o	shiva_util.o
	$(CC) $(GCC_OPTS_LDSO) shiva_signal.c -o	shiva_signal.o
	$(CC) $(GCC_OPTS_LDSO) shiva_ulexec.c -o	shiva_ulexec.o
	$(CC) $(GCC_OPTS_LDSO) shiva_auxv.c -o	shiva_auxv.o
	$(CC) $(GCC_OPTS_LDSO) shiva_module.c -o	shiva_module.o
	$(CC) $(GCC_OPTS_LDSO) shiva_trace.c -o	shiva_trace.o
	$(CC) $(GCC_OPTS_LDSO) shiva_trace_thread.c -o shiva_trace_thread.o
	$(CC) $(GCC_OPTS_LDSO) shiva_error.c	-o	shiva_error.o
	$(CC) $(GCC_OPTS_LDSO) shiva_maps.c -o	shiva_maps.o
	$(CC) $(GCC_OPTS_LDSO) shiva_analyze.c -o	shiva_analyze.o
	$(CC) $(GCC_OPTS_LDSO) shiva_callsite.c -o	shiva_callsite.o
	$(CC) $(GCC_OPTS_LDSO) shiva_target.c -o	shiva_target.o
	$(MUSL) -static-pie -Wl,-undefined=system -Wl,-undefined=prctl -Wl,-undefined=pause -Wl,-undefined=puts -Wl,-undefined=putchar $(OBJ_LIST) $(STATIC_LIBS) -o ./ldso/shiva
standalone:
	[ -d $(STANDALONE_DIR) ] || mkdir -p $(STANDALONE_DIR)
	$(CC) $(GCC_OPTS_STANDALONE) shiva.c -o		shiva.o
	$(CC) $(GCC_OPTS_STANDALONE) shiva_util.c -o	shiva_util.o
	$(CC) $(GCC_OPTS_STANDALONE) shiva_signal.c -o	shiva_signal.o
	$(CC) $(GCC_OPTS_STANDALONE) shiva_ulexec.c -o	shiva_ulexec.o
	$(CC) $(GCC_OPTS_STANDALONE) shiva_auxv.c -o	shiva_auxv.o
	$(CC) $(GCC_OPTS_STANDALONE) shiva_module.c -o	shiva_module.o
	$(CC) $(GCC_OPTS_STANDALONE) shiva_trace.c -o	shiva_trace.o
	$(CC) $(GCC_OPTS_STANDALONE) shiva_trace_thread.c -o shiva_trace_thread.o
	$(CC) $(GCC_OPTS_STANDALONE) shiva_error.c -o	shiva_error.o
	$(CC) $(GCC_OPTS_STANDALONE) shiva_maps.c -o	shiva_maps.o
	$(CC) $(GCC_OPTS_STANDALONE) shiva_analyze.c -o	shiva_analyze.o
	$(CC) $(GCC_OPTS_STANDALONE) shiva_callsite.c -o	shiva_callsite.o
	$(CC) $(GCC_OPTS_STANDALONE) shiva_target.c -o	shiva_target.o
	$(MUSL) -DSHIVA_STANDALONE -static -Wl,-undefined=system -Wl,-undefined=prctl -Wl,-undefined=pause -Wl,-undefined=puts -Wl,-undefined=putchar $(OBJ_LIST) $(STATIC_LIBS) -o ./standalone/shiva

test:
	gcc test.c -o test -fcf-protection=none
	gcc -Wl,--dynamic-linker=$(INTERP_PATH) test.c -o test2 -fcf-protection=none
	gcc -Wl,--dynamic-linker=$(INTERP_PATH) test_vuln.c -o test_vuln -fno-stack-protector -fcf-protection=none
	gcc test_vuln.c -o test_vuln2 -fno-stack-protector -fcf-protection=none
	gcc -Wl,--dynamic-linker=$(INTERP_PATH) test_inject.c -o test_inject -fcf-protection=none
	gcc test_inject.c -o test_inject2 -fcf-protection=none
	gcc test_antidebug.c -o test_antidebug -fcf-protection=none
	gcc crackme.c -o crackme -fcf-protection=none
	gcc test_stripped.c -o test_stripped -fcf-protection=none
	gcc test.c -o test_cfc
clean:
	rm -f test
	rm -f test2
	rm -f test_vuln
	rm -f test_vuln2
	rm -f *.o
	rm -f shiva
	rm -rf ./ldso
	rm -rf ./standalone
