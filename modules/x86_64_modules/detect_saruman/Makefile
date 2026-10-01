all: module
module:
	gcc -I /opt/shiva/include -I /opt/elfmaster/include -mcmodel=large -I ../ -fno-stack-protector -mcmodel=large -c detect_saruman.c
clean:
	rm -f *.o
