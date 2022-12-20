INTERP_PATH="/lib/shiva"
all:
	gcc -mcmodel=large -fno-pic -I ../ -fno-stack-protector -c bss_patch.c
	gcc -O0 test_bss.c -o test_bss
	gcc -Wl,--dynamic-linker=$(INTERP_PATH) test_bss.c -o test_bss_linked
clean:
	rm -f test_bss test_bss_linked bss_patch.o

