all: patch 
patch:
	gcc -mcmodel=large -I ../ -fno-stack-protector -c nc_patch.c
prelink:
	shiva-ld -e /usr/bin/nc2 -p nc_patch.o -i /lib/shiva -s $(PWD) -o nc.patched
install:
	sudo cp nc_patch.o /opt/shiva/modules/
clean:
	rm -f nc_patch.o

