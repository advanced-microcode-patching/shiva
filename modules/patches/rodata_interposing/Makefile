INTERP_PATH="/lib/shiva"
all:
	gcc -mcmodel=large -fno-pic -I ../ -fno-stack-protector -c ro_patch.c
	gcc -O0 test_rodata.c -o test_rodata
clean:
	rm -f test_rodata ro_patch.o

