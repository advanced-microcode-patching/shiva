all: patch
patch:
	gcc -Wno-implicit-function-declaration -mcmodel=large -I ../../include -fno-stack-protector -c nasa_patch3.c
	gcc -Wno-implicit-function-declaration -mcmodel=large -I ../../include -fno-stack-protector -c nasa_patch.c
	gcc -Wno-implicit-function-declaration -mcmodel=large -I ../../include -fno-stack-protector -c nasa_patch_optimized.c
	gcc -Wno-implicit-function-declaration -mcmodel=large -I ../../include -fno-stack-protector -c nasa_splice.c 
	gcc -Wno-implicit-function-declaration -mcmodel=large -I ../../include -fno-stack-protector -c nasa_splice2.c 

clean:
	rm -f *.o

