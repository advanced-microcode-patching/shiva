INTERP_PATH="/lib/shiva"
SHIVA-LD_PATH="../../../../tools/shiva-ld/shiva-ld"
all:
	gcc -Wl,--emit-relocs -mcmodel=large test.c -o test
	gcc -O2 -Wl,--emit-relocs -mcmodel=large test.c -o test2
	gcc -I ../../../include -fno-stack-protector -fomit-frame-pointer -mcmodel=large -c gASLR.c
install:
	cp gASLR.o /opt/shiva/modules/
clean:
	rm -f gASLR.o
