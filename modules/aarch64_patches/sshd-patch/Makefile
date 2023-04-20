INTERP_PATH="/lib/shiva"
SHIVA-LD_PATH="../../../tools/shiva-ld/shiva-ld"
patch:
	# Build the module ro_patch.c with a large code model
	gcc -mcmodel=large -fno-pic -I ../ -fno-stack-protector -c sshd_patch.c

prelink:
	# Pre-link the program we are patching with the proper interpreter and patch meta-data
	$(SHIVA-LD_PATH) -e sshd -p sshd_patch.o -i /lib/shiva -s /opt/shiva/modules -o sshd.patched

clean:
	rm -f sshd.patched sshd_patch.o

