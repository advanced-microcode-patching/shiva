INTERP_PATH="/lib/shiva"
SHIVA-LD_PATH="../../../../tools/shiva-ld/shiva-ld"
all:
	gcc  -I ../../../include -fno-stack-protector -fomit-frame-pointer -mcmodel=large -c fsplice_patch.c
	gcc -O0 fsplice_host.c -o fsplice_host
	#$(SHIVA-LD_PATH) -e fsplice_host -p fsplice_patch.o -i /lib/shiva -s /opt/shiva/modules -o fsplice_host.patched
install:
	cp fsplice_patch.o /opt/shiva/modules/
clean:
	rm -f fsplice_host fsplice_host.patched fsplice_patch.o
