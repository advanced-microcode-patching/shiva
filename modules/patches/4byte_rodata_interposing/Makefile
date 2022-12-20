INTERP_PATH="/lib/shiva"
all:
	gcc -Wno-warning -mcmodel=large -fno-pic -I ../ -fno-stack-protector -c rodata4b_patch.c
	gcc -mcmodel=large -fno-pic -I ../ -fno-stack-protector -c rodata4b_patch2.c -o rodata4b_patch2.o
	gcc -O0 test_4byte_rodata.c -o test_4byte_rodata
	gcc -Wl,--dynamic-linker=$(INTERP_PATH) test_4byte_rodata.c -o test_4byte_rodata_linked
clean:
	rm -f test_4byte_rodata rodata4b_patch.o test_4byte_rodata_linked

