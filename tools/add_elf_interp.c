#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdint.h>
#include <elf.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <link.h>

int main(int argc, char **argv)
{
	ElfW(Ehdr) *ehdr;
	ElfW(Phdr) *phdr;
	struct stat st;
	int i, fd;
	uint8_t *mem;

	if (argc < 3) {
		printf("Usage: %s <binary> <linker_path>\n", argv[0]);
		exit(0);
	}

	fd = open(argv[1], O_RDWR);
	if (fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}

	if (fstat(fd, &st) < 0) {
		perror("fstat");
		exit(EXIT_FAILURE);
	}

	mem = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		exit(EXIT_FAILURE);
	}

	ehdr = (ElfW(Ehdr) *)mem;
	phdr = (ElfW(Phdr) *)&mem[ehdr->e_phoff];
	for (i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_NOTE) {
			if (strlen(argv[2]) >= phdr[i].p_filesz) {
				printf("PT_NOTE segment is only %zu bytes\n", phdr[i].p_filesz);
				exit(0);
			}
			strncpy((char *)&mem[phdr[i].p_offset], argv[2], phdr[i].p_filesz);
			mem[phdr[i].p_offset + phdr[i].p_filesz - 1] = '\0';
			phdr[i].p_type = PT_INTERP;
			phdr[i].p_filesz = strlen(argv[2]) + 1;
			msync(mem, MS_SYNC, st.st_size);
			munmap(mem, st.st_size);
			printf("Done.\n");
			break;
		}
	}
	exit(0);
}
