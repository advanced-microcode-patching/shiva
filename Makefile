all:
	gcc -static shiva.c util.c signal.c shiva_ulexec.c shiva_iter.c -o shiva /opt/elfmaster/lib/libelfmaster.a libcapstone.a
clean:
	rm -f ftrace
