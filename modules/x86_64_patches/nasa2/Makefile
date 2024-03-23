all: patch
patch:
	gcc -Wno-implicit-function-declaration -mcmodel=large -I ../../include -fno-stack-protector -c nasa_patch.c
	gcc -Wno-implicit-function-declaration -mcmodel=large -I ../../include -fno-stack-protector -c nasa_patch_optimized.c
clean:
	rm -f *.o

