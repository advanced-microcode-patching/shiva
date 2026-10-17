all: int3_bp ftracer command_injection.c
int3_bp:
	gcc -I /opt/shiva/include -mcmodel=large -fno-stack-protector -c int3_bp.c

ftracer:
	gcc -I /opt/shiva/include -mcmodel=large -fno-stack-protector -c func_tracer.c
command_injection:
	gcc -I /opt/shiva/include -mcmodel=large -fno-stack-protector -c command_injection.c
clean:
	rm *.o
