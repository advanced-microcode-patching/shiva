all:
	gcc -ggdb -DDEBUG -static shiva.c shiva_util.c shiva_signal.c shiva_ulexec.c shiva_iter.c shiva_module.c shiva_trace.c shiva_trace_thread.c shiva_error.c -o shiva /opt/elfmaster/lib/libelfmaster.a libcapstone.a
clean:
	rm -f ftrace
