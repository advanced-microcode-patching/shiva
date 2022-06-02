all:
	gcc -I ../ -fno-stack-protector -c func_tracer.c
	gcc -mcmodel=large -I ../ -fno-stack-protector -c trampoline.c
	gcc -mcmodel=large -I ../ -fno-stack-protector -c pltgot_hook.c
clean:
	rm -f *.o
