INTERP_PATH="/lib/shiva"
SHIVA-LD_PATH="../../../tools/shiva-ld/shiva-ld"
all:
	gcc -mcmodel=large -fno-pic -I ../ -fno-stack-protector -c data_patch.c
	gcc -O0 test_data.c -o test_data
	$(SHIVA-LD_PATH) -e test_data -p data_patch.o -i /lib/shiva -s /opt/shiva/modules -o test_data.patched
clean:
	rm -f test_data test_data.patched data_patch.o

