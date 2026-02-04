INTERP_PATH="/lib/shiva"
SHIVA-LD_PATH="../../../tools/shiva-ld/shiva-ld"
all:
	gcc -mcmodel=large -I ../ -fno-stack-protector -c fuck_version.c
	gcc -shared -fPIC -o strtol.so strtol.c
prelink:
	$(SHIVA-LD_PATH) -e prog -p fuck_version.o -i /lib/shiva -s $(PWD) -o prog.patched
clean:
	rm -f fuck_version.o strtol.so prog.patched

