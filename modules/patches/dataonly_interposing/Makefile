INTERP_PATH="/lib/shiva"
all:
	gcc -mcmodel=large -fno-pic -I ../ -fno-stack-protector -c dataonly_patch.c
	gcc test_data.c -o test_data
	shiva-ld -e test_data -p dataonly_patch.o -i /lib/shiva -s /opt/shiva/modules -o test_data.patched
clean:
	rm -f test_data test_data.patched dataonly_patch.o

