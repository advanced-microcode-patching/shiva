all:
	gcc  -ggdb shiva-ld.c -o shiva-ld /opt/elfmaster/lib/libelfmaster.a ../../libcapstone.a
test:
	gcc test.c -o test
install:
	cp shiva-ld /usr/bin
clean:
	rm -f shiva-ld
