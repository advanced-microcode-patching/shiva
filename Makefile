all:
	gcc shiva.c util.c signal.c shiva_ulexec.c -o shiva /opt/elfmaster/lib/libelfmaster.a capstone/libcapstone.a
clean:
	rm -f ftrace
