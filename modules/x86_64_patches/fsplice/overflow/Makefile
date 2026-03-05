INTERP_PATH="/lib/shiva"
SHIVA-LD_PATH="../../../../tools/shiva-ld/shiva-ld"
all:
	gcc  -I ../../../include -fno-stack-protector -fomit-frame-pointer -mcmodel=large -c patch.c
	gcc -O0 -fno-stack-protector vuln.c -o vuln
	$(SHIVA-LD_PATH) -e vuln -p patch.o -i /lib/shiva -s $(PWD) -o vuln.fixed
install:
	cp patch.o /opt/shiva/modules/
clean:
	rm -f *.o vuln.fixed
