all: int3_bp ftracer plt_cfi
int3_bp:
	gcc -I /opt/shiva/include -mcmodel=large -fno-stack-protector -c int3_bp.c

ftracer:
	gcc -I /opt/shiva/include -mcmodel=large -fno-stack-protector -c func_tracer.c
plt_cfi:
	gcc -I /opt/shiva/include -mcmodel=large -fno-stack-protector -c plt_cfi.c

command_injection:
	gcc -I /opt/shiva/include -mcmodel=large -fno-stack-protector -c command_injection.c
clean:
	rm *.o
