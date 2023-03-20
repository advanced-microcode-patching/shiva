INTERP_PATH="/lib/shiva"
SHIVA-LD_PATH="../../../tools/shiva-ld/shiva-ld"
all:
	# Build the module ro_patch.c with a large code model
	gcc -mcmodel=large -fno-pic -I ../ -fno-stack-protector -c ro_patch.c

	# Build the program we are patching
	gcc -O0 test_rodata.c -o test_rodata

	# Pre-link the program we are patching with the proper interpreter and patch meta-data
	$(SHIVA-LD_PATH) -e test_rodata -p ro_patch.o -i /lib/shiva -s /opt/shiva/modules -o test_rodata.patched

clean:
	rm -f test_rodata test_rodata.patched ro_patch.o

