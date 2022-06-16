#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <elf.h>
#include <sys/types.h>
#include <stdint.h>

int main(int argc, char **argv)
{
	uint8_t *mem;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	int i, fd;
	struct stat st;

	fd = open(argv[1], O_RDWR);
	if (fd < 0) {
		perror("open");
		return false;
	}
	fstat(fd, &st);
	mem = mmap(addr, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		return false;
	}
	ehdr = (Elf64_Ehdr *)mem;
	
