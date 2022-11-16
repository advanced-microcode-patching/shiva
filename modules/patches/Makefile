INTERP_PATH="/home/elfmaster/amp/shiva/ldso/shiva"
all:
	gcc -mcmodel=large -fno-pic -I ../ -fno-stack-protector -c p1.c
	gcc -mcmodel=large -fno-pic -I ../ -fno-stack-protector -c fpatch.c
	gcc -mcmodel=large -fno-pic -I ../ -fno-stack-protector -c cfs_patch1.c
	gcc test_function_patch.c -o test_function_patch
	gcc -Wl,--dynamic-linker=$(INTERP_PATH) test_function_patch.c -o test_function_patch2
	gcc test_p1.c -o test_p1
clean:
	rm -f test
	rm -f p1.o

