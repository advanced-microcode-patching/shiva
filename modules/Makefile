all:
	gcc -c shakti_init/shakti_init.c -o shakti_init.o
	gcc -c shakti_runtime.c -o shakti_runtime.o
	./build_int3_handler.sh
	gcc -c trap_handler.c -o trap_handler.o
clean:
	rm -f *.o

