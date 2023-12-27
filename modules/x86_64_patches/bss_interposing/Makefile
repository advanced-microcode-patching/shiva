INTERP_PATH="/lib/shiva"
SHIVA-LD_PATH="../../../tools/shiva-ld/shiva-ld"

all:
	gcc -mcmodel=large -I ../ -fno-stack-protector -c bss_patch.c
	gcc -O0 -fno-stack-protector test_bss.c -o test_bss
	$(SHIVA-LD_PATH) -e test_bss -p bss_patch.o -i /lib/shiva -s /opt/shiva/modules -o test_bss.patched 
install:
	cp bss_patch.o /opt/shiva/modules/
clean:
	rm -f test_bss test_bss.patched bss_patch.o

