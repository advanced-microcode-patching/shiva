INTERP_PATH="/lib/shiva"
all:
	gcc -mcmodel=large -fno-pic -I ../ -fno-stack-protector -c ro_patch.c
	gcc -O0 test_rodata.c -o test_rodata
	shiva-ld -e test_rodata -p ro_patch.o -i /lib/shiva -s /opt/shiva/modules -o test_rodata.patched

clean:
	rm -f test_rodata test_rodata.patched ro_patch.o

