INTERP_PATH="/lib/shiva"
SHIVA-LD_PATH="../../../tools/shiva-ld/shiva-ld"
all: prog patch prelink
patch:
	gcc -mcmodel=large -I ../ -fno-stack-protector -c data_patch.c
	gcc -mcmodel=large -I ../ -fno-stack-protector -S data_patch.c
prog:
	gcc -O0 test_data.c -o test_data
prelink:
	$(SHIVA-LD_PATH) -e test_data -p data_patch.o -i /lib/shiva -s /opt/shiva/modules -o test_data.patched
clean:
	rm -f test_data test_data.patched data_patch.o

