INTERP_PATH="/lib/shiva"
SHIVA-LD_PATH="../../../../tools/shiva-ld/shiva-ld"
all:
	gcc -Wl,--emit-relocs -mcmodel=large test.c -o test
	gcc -I ../../../include -fno-stack-protector -fomit-frame-pointer -mcmodel=large -c aslr.c
install:
	cp aslr.o /opt/shiva/modules/
clean:
	rm -f aslr.o
