all: patch
patch:
	gcc -Wno-implicit-function-declaration -mcmodel=large -I ../../include -fno-stack-protector -c nasa_patch.c
clean:
	rm -f *.o

