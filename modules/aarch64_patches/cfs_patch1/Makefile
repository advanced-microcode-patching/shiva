INTERP_PATH="/lib/shiva""
all:
	gcc -mcmodel=large -fno-pic -I ../ -fno-stack-protector -c cfs_patch1.c
	shiva-ld -e core-cpu1 -p cfs_patch1.o -i /lib/shiva -s /opt/shiva/modules -o core-cpu1.patched

clean:
	rm -f cfs_patch1.o core-cpu1.patched

