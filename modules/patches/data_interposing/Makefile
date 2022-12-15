INTERP_PATH="/lib/shiva"
all:
	gcc -mcmodel=large -fno-pic -I ../ -fno-stack-protector -c data_patch.c
	gcc -O0 test_data.c -o test_data
	gcc -Wl,--dynamic-linker=$(INTERP_PATH) test_data.c -o test_data_linked
clean:
	rm -f test_data test_data_linked data_patch.o

