#include "shiva.h"

#define LINKER_BASE 0x600000

bool
shiva_build_auxv_stack(struct shiva_ctx *ctx)
{
	uint64_t *esp, *envp, *argv;
	uint64_t esp_start;
	int i, count, totalsize, stroffset, len, argc;
	void *stack;
	Elf64_auxv_t *auxv;

	count += sizeof(argc);
	count += ctx->argc * sizeof(char *);
	count += sizeof(void *);
}

void
shiva_save_stack(struct shiva_ctx *ctx)
{
	size_t sz, i, j, tmp;
	char **envpp = ctx->envp;
	char *s;

	for (i = 0, sz = 0, tmp = ctx->argc; tmp > 0; tmp--, i++)
		sz += strlen(ctx->argv[i]) + 1;
	ctx->ulexec.arglen = sz;

	for (i = 0, sz = 0; *envpp != NULL; envpp++, i++)
		sz += strlen(*envpp) + 1;

	ctx->ulexec.envpcount = i;
	ctx->ulexec.envplen = sz;
	assert((ctx->ulexec.envstr = malloc(ctx->ulexec.envplen)) != NULL);
	assert((ctx->ulexec.argstr = malloc(ctx->ulexec.arglen)) != NULL);

	for (s = ctx->ulexec.argstr, j = 0, i = 0; i < ctx->argc; i++) {
		while (j < strlen(ctx->argv[i]))
			s[j] = ctx->argv[i][j++];
		s[j] = '\0';
		s += strlen(ctx->argv[i]) + 1;
		j = 0;
	}
	for (i = 0; *ctx->envp != NULL; ctx->envp++) {
		strcpy(&ctx->ulexec.envstr[i], *ctx->envp);
		i += strlen(*ctx->envp) + 1;
	}
	return;
}

static inline int
shiva_ulexec_make_prot(uint32_t p_flags)
{
        int prot = 0;

        if (p_flags & PF_R)
                prot |= PROT_READ;
        if (p_flags & PF_W)
                prot |= PROT_WRITE;
        if (p_flags & PF_X)
                prot |= PROT_EXEC;
        return prot;
}

/*
 * Copy p_filesz bytes of the PT_LOAD segment (3rd arg) into
 * the buffer specified by dst (2nd arg).
 */
static bool
shiva_ulexec_segment_copy(elfobj_t *elfobj, uint8_t *dst,
    struct elf_segment segment)
{
        size_t len = segment.filesz / sizeof(uint64_t);
        size_t rem = len % sizeof(uint64_t);
        uint64_t qword;
        bool res;
        uint8_t byte;
        size_t i = 0;

        shiva_debug("Reading from address %#lx - %#lx\n", segment.vaddr,
            segment.vaddr + segment.filesz);
        for (i = 0; i < segment.filesz; i += sizeof(uint64_t)) {
		if (i + sizeof(uint64_t) >= segment.filesz) {
			size_t j;

			for (j = 0; j < rem; j++) {
				res = elf_read_address(elfobj, segment.vaddr + i + j,
				    &qword, ELF_BYTE);
				if (res == false) {
					shiva_debug("shiva_ulexec_segment_copy "
					    "failed at %#lx\n", segment.vaddr + i + j);
					return false;
				}
				dst[i + j] = (uint8_t)qword;
			}
			break;
		}
                res = elf_read_address(elfobj, segment.vaddr + i, &qword, ELF_QWORD);
                if (res == false) {
                        shiva_debug("elf_read_address failed at %#lx\n", segment.vaddr + i);
                        return false;
                }
                *(uint64_t *)&dst[i] = qword;
        }
	return true;
}

static uint8_t *
shiva_ulxec_allocstack(struct shiva_ctx *ctx)
{
	ctx->ulexec.stack = mmap(NULL, SHIVA_STACK_SIZE, PROT_READ|PROT_WRITE,
	    MAP_PRIVATE|MAP_ANONYMOUS|MAP_GROWSDOWN, -1, 0);
	assert(ctx->ulexec.stack != MAP_FAILED);
	return ctx->ulexec.stack;
}

bool
shiva_load_elf_binary(struct shiva_ctx *ctx, elfobj_t *elfobj, bool interpreter)
{
	uint64_t vaddr;
	bool res;
	elf_iterator_res_t ires;
	elf_segment_iterator_t phdr_iter;
	struct elf_segment phdr;
	bool load_addr_set = false;
	uint64_t elf_bss = 0, last_bss = 0;
	uint64_t load_addr, map_addr, mapped;
	uint64_t last_vaddr, last_memsz, last_offset, base_vaddr;
	uint8_t *mem;
	struct elf_symbol sym;

	elf_segment_iterator_init(elfobj, &phdr_iter);
	for (;;) {
		uint32_t elfprot, bss_prot;

		ires = elf_segment_iterator_next(&phdr_iter, &phdr);
		if (ires == ELF_ITER_DONE)
			break;
		if (ires == ELF_ITER_ERROR)
			return false;
		if (phdr.type != PT_LOAD)
			continue;
		elfprot = shiva_ulexec_make_prot(phdr.flags);
		if (elfprot & PROT_READ)
			shiva_debug("PROT_READ\n");
		if (elfprot & PROT_WRITE)
			shiva_debug("PROT_WRITE\n");
		if (elfprot & PROT_EXEC)
			shiva_debug("PROT_EXEC\n");
		if (phdr.offset == 0) {
			base_vaddr = SHIVA_TARGET_BASE;
			shiva_debug("Attempting to map %#lx\n", base_vaddr);
			mem = mmap((void *)base_vaddr, phdr.memsz, PROT_READ|PROT_WRITE, MAP_PRIVATE|
			    MAP_ANONYMOUS|MAP_FIXED, -1, 0);
			shiva_debug("Mapped at %p\n", mem);

			if (mem == MAP_FAILED) {
				perror("mmap");
				exit(EXIT_FAILURE);
			}
			mem = (uint8_t *)base_vaddr;
			shiva_debug("Mapped segment at %p\n", mem);
					   if (mem == MAP_FAILED) {
				perror("mmap");
				exit(EXIT_FAILURE);
			}
			mem = (uint8_t *)base_vaddr;
			shiva_debug("Mapped segment at %p\n", mem);
			res = shiva_ulexec_segment_copy(elfobj, mem, phdr);
			if (res == false) {
				shiva_debug("shiva_ulexec_segment_copy(%p, %p, %p) failed\n",
				    elfobj, mem, &phdr);
				return false;
			}
			if (mprotect(mem,
			    phdr.memsz + 4095 & ~4095, elfprot) < 0) {
				shiva_debug("mprotect: %s\n", strerror(errno));
				return false;
			}
			shiva_debug("mprotect succeeded at %p %zu bytes\n", mem, phdr.memsz);
			last_vaddr = base_vaddr + phdr.vaddr;
			last_memsz = phdr.memsz;
			last_offset = phdr.offset;
			continue;
		}
		load_addr = base_vaddr + phdr.vaddr;
		load_addr = ELF_PAGESTART(load_addr);
		shiva_debug("Mapping segment: %#lx of size %zu\n", load_addr, phdr.memsz);
		unsigned long memsz = phdr.memsz;
		if (phdr.flags == (PF_R|PF_W)) {
			/*
			 * If this is the data segment map enough room for
			 * the .bss segment.
			 */
			memsz = ELF_PAGEALIGN(phdr.memsz, 0x1000) +
			    ELF_PAGEALIGN(phdr.memsz - phdr.filesz, 0x1000);
		}
		mem = mmap((void *)load_addr, memsz, PROT_READ|PROT_WRITE,
		    MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
		if (mem == MAP_FAILED) {
			shiva_debug("mmap failed: %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		shiva_ulexec_segment_copy(elfobj, &mem[phdr.vaddr & (PAGE_SIZE - 1)], phdr);
		if (mprotect(mem, phdr.memsz + 4095 & ~4095,
		    elfprot) < 0) {
			shiva_debug("mprotect: %s\n", strerror(errno));
			return false;
		}
		last_vaddr = load_addr;
		last_memsz = phdr.memsz;
		last_offset = phdr.offset;
	}
	if (interpreter == false) {
		ctx->ulexec.entry_point = base_vaddr + elf_entry_point(elfobj);
		ctx->ulexec.base_vaddr = base_vaddr;
		ctx->ulexec.phdr_vaddr = base_vaddr + elf_phoff(elfobj);
	} else {
		ctx->ulexec.ldso.entry_point = base_vaddr + elf_entry_point(elfobj);
		ctx->ulexec.ldso.base_vaddr = base_vaddr;
		ctx->ulexec.ldso.phdr_vaddr = base_vaddr + elf_phoff(elfobj);
	}
	return true;
}
