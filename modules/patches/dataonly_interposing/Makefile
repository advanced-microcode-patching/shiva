INTERP_PATH="/lib/shiva"
all:
	gcc -mcmodel=large -fno-pic -I ../ -fno-stack-protector -c dataonly_patch.c
	gcc test_data.c -o test_data
	gcc -Wl,--dynamic-linker=$(INTERP_PATH) test_data.c -o test_data_linked
clean:
	rm -f test_data test_data_linked dataonly_patch.o

