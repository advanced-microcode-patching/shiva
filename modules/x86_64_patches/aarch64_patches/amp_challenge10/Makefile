INTERP_PATH="/lib/shiva"
SHIVA_LD_PATH="../../../tools/shiva-ld/shiva-ld"
all:
	gcc -fomit-frame-pointer -mcmodel=large -fno-pic -I ../ -I ../../include -fno-stack-protector -c patch10.c
	$(SHIVA_LD_PATH) -e program_c -p patch10.o -i /lib/shiva -s /opt/shiva/modules -o program_c.patched

clean:
	rm *.o

