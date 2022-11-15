all:
	gcc -mcmodel=large -fno-pic -I ../ -fno-stack-protector -c p1.c
	gcc -mcmodel=large -fno-pic -I ../ -fno-stack-protector -c fpatch.c
	gcc test_function_patch.c -o test_function_patch
	gcc test_p1.c -o test_p1
clean:
	rm -f test
	rm -f p1.o

