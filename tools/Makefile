all:
32bit:
	gcc -m32 add_elf_interp.c -o add_elf_interp32
64bit:
	gcc -ggdb add_elf_interp.c -o add_elf_interp64
test:
	gcc -static-pie test.c -o test
clean:
	rm -f add_elf_interp32
	rm -f add_elf_interp64
	rm test

