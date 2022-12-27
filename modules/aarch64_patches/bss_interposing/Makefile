INTERP_PATH="/lib/shiva"
all:
	gcc -mcmodel=large -fno-pic -I ../ -fno-stack-protector -c bss_patch.c
	gcc -O0 test_bss.c -o test_bss
	shiva-ld -e test_bss -p bss_patch.o -i /lib/shiva -s /opt/shiva/modules -o test_bss.patched
clean:
	rm -f test_bss test_bss.patched bss_patch.o

