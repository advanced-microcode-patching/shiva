INTERP_PATH="/lib/shiva"
SHIVA-LD_PATH="/usr/bin/shiva-ld"
all: patch prog prelink
patch:
	# Build the module patch.c with a large code model
	gcc -fno-builtin -mcmodel=large -I ../ -fno-stack-protector -c patch.c
	gcc -fno-builtin -mcmodel=large -I ../ -fno-stack-protector -c patch2.c
prog:
	# Build the program we are patching
	gcc -fno-builtin -fno-stack-protector -O0 prog.c -o prog
prelink:
	# Pre-link the program we are patching with the proper interpreter and patch meta-data
	$(SHIVA-LD_PATH) -e prog -p patch.o -i /lib/shiva -s /opt/shiva/modules -o prog.patched -d

install:
	sudo cp patch.o /opt/shiva/modules/
clean:
	rm -f prog patch.o prog.patched

