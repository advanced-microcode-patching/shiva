all: main testprog host
main:
	gcc -D_GNU_SOURCE -fno-stack-protector -I/opt/elfmaster/include -O0 launcher.c /opt/elfmaster/lib/libelfmaster.a  \
	       	-o saruman
testprog:
	gcc -g -pie -o test test.c -Wl,-E
host:
	gcc host.c -o host

clean:
	rm -f saruman test host
