all:
	gcc -O2 -fno-inline -fno-tree-dce -fno-tree-tail-merge -fno-ipa-cp test2.c -o test
	gcc -mcmodel=large -c patch.c
clean:
	rm -f patch.o test
