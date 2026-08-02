INTERP_PATH="/lib/shiva"
SHIVA-LD_PATH="../../../tools/shiva-ld/shiva-ld"
all: prog module prelink
prog:
	gcc -O0 prog.c -o prog
module:
	gcc -I /opt/shiva/include -I /opt/elfmaster/include -mcmodel=large -I ../ -fno-stack-protector -c sections.c
prelink:
	$(SHIVA-LD_PATH) -e prog -p sections.o -i /lib/shiva -s $(PWD) -o prog.new
clean:
	rm -f prog.new sections.o prog
