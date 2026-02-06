all:
patch:
	gcc -c -mcmodel=large -fno-stack-protector -I ../../include pacman_patch1.c
	gcc -c -mcmodel=large -fno-stack-protector -I ../../include pacman_patch2.c
	gcc -c -mcmodel=large -fno-stack-protector -I ../../include pacman_patch3.c

clean:
	rm -f *.o
