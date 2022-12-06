BUILD_DIR = './build'
INTERP_PATH = $(PWD)/build/shiva
GCC_OPTS= -fPIC -ggdb -c -DDEBUG
OBJ_LIST=shiva.o shiva_util.o shiva_signal.o shiva_ulexec.o shiva_auxv.o	\
    shiva_module.o shiva_trace.o shiva_trace_thread.o shiva_error.o shiva_maps.o shiva_analyze.o \
    shiva_callsite.o shiva_target.o shiva_xref.o
STATIC_LIBS=/opt/elfmaster/lib/libelfmaster.a libcapstone.a
CC=gcc
MUSL=musl-gcc

all: interp test_aarch64
interp:
	[ -d $(BUILD_DIR) ] || mkdir -p $(BUILD_DIR)
	$(CC) $(GCC_OPTS) shiva.c -o		shiva.o
	$(CC) $(GCC_OPTS) shiva_util.c -o	shiva_util.o
	$(CC) $(GCC_OPTS) shiva_signal.c -o	shiva_signal.o
	$(CC) $(GCC_OPTS) shiva_ulexec.c -o	shiva_ulexec.o
	$(CC) $(GCC_OPTS) shiva_auxv.c -o	shiva_auxv.o
	$(CC) $(GCC_OPTS) shiva_module.c -o	shiva_module.o
	$(CC) $(GCC_OPTS) shiva_trace.c -o shiva_trace.o
	$(CC) $(GCC_OPTS) shiva_trace_thread.c -o shiva_trace_thread.o
	$(CC) $(GCC_OPTS) shiva_error.c	-o	shiva_error.o
	$(CC) $(GCC_OPTS) shiva_maps.c -o	shiva_maps.o
	$(CC) $(GCC_OPTS) shiva_analyze.c -o	shiva_analyze.o
	$(CC) $(GCC_OPTS) shiva_callsite.c -o	shiva_callsite.o
	$(CC) $(GCC_OPTS) shiva_target.c -o	shiva_target.o
	$(CC) $(GCC_OPTS) shiva_xref.c -o		shiva_xref.o
	$(MUSL) -static -Wl,-undefined=system -Wl,-undefined=prctl -Wl,-undefined=pause -Wl,-undefined=puts -Wl,-undefined=putchar $(OBJ_LIST) $(STATIC_LIBS) -o $(BUILD_DIR)/shiva
test_aarch64:
	gcc -g test.c -o test
	gcc -g -Wl,--dynamic-linker=$(INTERP_PATH) test.c -o test2
.PHONY: install
install:
	cp build/shiva /lib/shiva
	ln -s build/shiva shiva


