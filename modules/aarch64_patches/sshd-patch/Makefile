INTERP_PATH="/lib/shiva"
SHIVA-LD_PATH="../../../tools/shiva-ld/shiva-ld"
all: patch prelink
patch:
	# Build the module ro_patch.c with a large code model
	gcc -Wno-implicit-function-declaration -mcmodel=large -fno-pic -I ../../include -fno-stack-protector -c sshd_patch.c
	gcc -Wno-implicit-function-declaration -mcmodel=large -fno-pic -I ../../include -fomit-frame-pointer -fno-stack-protector -c sshd_patch2.c

prelink:
	$(SHIVA-LD_PATH) -e sshd -p sshd_patch.o -i /lib/shiva -s /opt/shiva/modules -o sshd.patched
	$(SHIVA-LD_PATH) -e sshd -p sshd_patch2.o -i /lib/shiva -s /opt/shiva/modules -o sshd.patched2
install:
	cp sshd_patch.o /opt/shiva/modules/
	cp sshd_patch2.o /opt/shiva/modules/
clean:
	rm -f sshd.patched sshd_patch.o

