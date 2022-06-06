all:
	gcc -I ../ -fno-stack-protector -c func_tracer.c
	gcc -mcmodel=large -I ../ -fno-stack-protector -c trampoline.c
	gcc -mcmodel=large -I ../ -fno-stack-protector -c pltgot_hook.c
	gcc -mcmodel=large -I ../ -fno-stack-protector -c int3_bp.c
	gcc -mcmodel=large -I ../ -fno-stack-protector -c sigill_bp.c
clean:
	rm -f *.o
