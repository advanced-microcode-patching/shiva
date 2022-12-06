INTERP_PATH="/lib/shiva"
all:
	gcc -mcmodel=large -fno-pic -I ../ -fno-stack-protector -c fpatch.c
	gcc test_function_patch.c -o test_function_patch
	gcc -Wl,--dynamic-linker=$(INTERP_PATH) test_function_patch.c -o test_function_patch2
clean:
	rm -f test_function_patch test_function_patch2

