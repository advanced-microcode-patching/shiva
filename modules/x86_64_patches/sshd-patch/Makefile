INTERP_PATH="/lib/shiva"
SHIVA-LD_PATH="../../../tools/shiva-ld/shiva-ld"
all: patch prelink
patch:
	# Build the module ro_patch.c with a large code model
	gcc -Wno-implicit-function-declaration -mcmodel=large -I ../../include -fno-stack-protector -c sshd_patch.c

prelink:
	$(SHIVA-LD_PATH) -e sshd.x86_64 -p sshd_patch.o -i /lib/shiva -s /opt/shiva/modules -o sshd.patched
install:
	cp sshd_patch.o /opt/shiva/modules/
clean:
	rm -f sshd.x86_64.patched sshd_patch.o

