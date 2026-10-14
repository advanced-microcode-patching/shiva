all: int3_bp ftracer
int3_bp:
	gcc -I /opt/shiva/include -mcmodel=large -fno-stack-protector -c int3_bp.c
ftracer:
	gcc -I /opt/shiva/include -mcmodel=large -fno-stack-protector -c func_tracer.c
clean:
	rm *.o
