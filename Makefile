BUILD_DIR = './build'
INTERP_PATH = $(PWD)/build/shiva
PATCH_PATH = "modules/aarch64_patches"
GCC_OPTS= -fPIC -ggdb -I ./ -DDEBUG -c 

OBJ_LIST=shiva.o shiva_util.o shiva_signal.o shiva_ulexec.o shiva_auxv.o	\
    shiva_module.o shiva_trace.o shiva_trace_thread.o shiva_error.o shiva_maps.o shiva_analyze.o \
    shiva_callsite.o shiva_target.o shiva_xref.o shiva_transform.o shiva_so.o shiva_post_linker.o
STATIC_LIBS=/opt/elfmaster/lib/libelfmaster.a libcapstone_x86_64.a
CC=musl-gcc
MUSL=musl-gcc

all: interp shiva-ld
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
	$(CC) $(GCC_OPTS) shiva_transform.c -o	shiva_transform.o
	$(CC) $(GCC_OPTS) shiva_so.c -o		shiva_so.o
	$(CC) $(GCC_OPTS) -fno-stack-protector shiva_post_linker.c -o shiva_post_linker.o
	$(MUSL) -static $(OBJ_LIST) $(STATIC_LIBS) -o $(BUILD_DIR)/shiva

shiva-ld:
	make -C tools/shiva-ld
patches:
	make -C modules/aarch64_patches

.PHONY: install
install:
	cp build/shiva /lib/shiva
	ln -sf build/shiva shiva
	ln -sf /lib/shiva /usr/bin/shiva
	cp tools/shiva-ld/shiva-ld /usr/bin
	mkdir -p /opt/shiva/modules

#	cp $(PATCH_PATH)/*interposing*/*.o /opt/shiva/modules
#	cp $(PATCH_PATH)/cfs_patch1/*.o /opt/shiva/modules
	cat shiva.ansi
#
clean:
	make -C tools/shiva-ld clean
	#make -C modules/aarch64_patches clean
	rm -f *.o shiva
