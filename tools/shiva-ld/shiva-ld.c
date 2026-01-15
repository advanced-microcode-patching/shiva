/*
 * Shiva Prelinker v1. AMP (Advanced microcode patching)
 *
 * The Shiva Prelinker "/bin/shiva-ld" applies patch meta-data to the executable that
 * is being patched. The actual microcode patching doesn't take place until runtime.
 * Features:
 * 1. Modifies PT_INTERP on ELF executable and replaces the path to Shiva interpreter "/lib/shiva" (Or other specified path).
 * 2. Creates a new PT_LOAD segment by overwriting PT_NOTE.
 * 3. Creates a new PT_DYNAMIC segment within the new PT_LOAD segment. It has two additional entries:
 *	3.1. SHIVA_DT_NEEDED holds the address of the string to the patch basename, i.e. "amp_patch1.o"
 *	3.2. SHIVA_DT_SEARCH holds the address of the string to the patch search path, i.e. "/opt/shiva/modules"
 *
 * The Shiva linker parses these custom dynamic segment values to locate the patch object at runtime.
 * In the future shiva-ld will be able to generate ELF relocation data for the external linking process
 * at runtime. This meta-data will be stored in the executable and parsed at runtime, giving Shiva
 * a rich source of patching information. Currently Shiva has to perform runtime analysis to determine
 * where external linking patches go, and this can be slow for some programs.
 *
 * See https://github.com/advanced-microcode-patching/shiva/issues/4
 *
 * Author: ElfMaster
 * ryan@bitlackeys.org
 */

#define _GNU_SOURCE

#include <assert.h>
#include <stdarg.h>
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
#include <getopt.h>
#include <errno.h>

#include "/opt/elfmaster/include/libelfmaster.h"
#include "../../include/capstone/capstone.h"

#define SHIVA_LD_F_NO_CFG		(1UL << 0)
#define SHIVA_LD_F_NEEDED_INJECTION	(1UL << 1)
#define SHIVA_LD_F_CFS_BINARY		(1UL << 2) // super edge-case

#define SHIVA_DT_NEEDED	DT_LOOS + 10
#define SHIVA_DT_SEARCH DT_LOOS + 11
#define SHIVA_DT_ORIG_INTERP DT_LOOS + 12

#define SHIVA_SIGNATURE 0x31f64 /* elf64 */

#define ELF_MIN_ALIGN 4096
#define ELF_PAGESTART(_v) ((_v) & ~(unsigned long)(ELF_MIN_ALIGN-1))
#define ELF_PAGEOFFSET(_v) ((_v) & (ELF_MIN_ALIGN-1))
#define ELF_PAGEALIGN(_v, _a) (((_v) + _a - 1) & ~(_a - 1))

#if defined DEBUG
	#define shiva_pl_debug(...) {\
	do {\
		fprintf(stderr, "[%s:%s:%d] ", __FILE__, __func__, __LINE__); \
		fprintf(stderr, __VA_ARGS__);	\
	} while(0); \
}
#else
	#define shiva_pl_debug(...)
#endif

#define shiva_debug shiva_pl_debug

#define BIT_MASK(n)	((1U << n) - 1)
#define ARM_INSN_LEN 4

/*
 * NOTE: 
 * Regarding struct elf_symbol
 * Usually the first 8 bytes are taken up by
 * a pointer to the symbol name, i.e.
 * char *name;
 * Instead we are using a 32bit index into a string
 * table when storing this struct onto disk. Notice the
 * uint32_t name; and the uint32_t __pad1 member next, 
 * to account for the entire 64bit 'char *name' ptr.
 */
struct __elf_symbol {
	uint64_t name;
	uint64_t value;
	uint64_t shndx;
	uint8_t bind;
	uint8_t type;
	uint8_t visibility;
	uint8_t __pad2;
};

static char *shiva_strtab = NULL;

/*
 * xref sites: code that references other code or data
 * within the program. We don't consider a branch/call
 * and xref, instead those are stored in shiva_branch_site
 * structs. An xref is a reference to any code or data such
 * as a memory access.
 *
 * In our aarch64 implementation of Shiva we utilize this
 * xref information to figure out what objects (i.e. a variable
 * in the .data section) are being referenced, and which of
 * those xrefs need to be patched to reflect updated object information
 * from a loaded patch. Often times these xrefs span over several
 * instructions that need to be patched, i.e.
 *
 * adrp x0, #data_segment_offset
 * add x0, x0, #variable_offset
 */
#ifdef __aarch64__
#define SHIVA_XREF_TYPE_ADRP_LDR 1
#define SHIVA_XREF_TYPE_ADRP_STR 2
#define SHIVA_XREF_TYPE_ADRP_ADD 3
#define SHIVA_XREF_TYPE_UNKNOWN 4
#elif __x86_64__
#define SHIVA_XREF_TYPE_IP_RELATIVE_LEA 1
#define SHIVA_XREF_TYPE_IP_RELATIVE_MOV_LDR 2
#define SHIVA_XREF_TYPE_IP_RELATIVE_MOV_STR 3
#define SHIVA_XREF_TYPE_IP_RELATIVE_MOVAPS_LDR 4
#define SHIVA_XREF_TYPE_IP_RELATIVE_MOVAPS_STR 5
#define SHIVA_XREF_TYPE_UNKNOWN 6
#endif


#define SHIVA_XREF_F_INDIRECT		(1UL << 0) /* i.e. got[entry] holds address to .bss variable */
#define SHIVA_XREF_F_SRC_SYMINFO	(1UL << 1) /* we have src func symbol of xref */
#define SHIVA_XREF_F_DST_SYMINFO	(1UL << 2) /* we have dst symbol info */
#define SHIVA_XREF_F_DEREF_SYMINFO	(1UL << 3)
#define SHIVA_XREF_F_TO_SECTION		(1UL << 4) /* xref to a section (i.e. .rodata) with no syminfo */
#define SHIVA_XREF_F_TO_JUMPTABLE	(1UL << 5) /* xref to jumptable */

/*
 * NOTE: This is different than the struct in shiva.h notice that we use
 * struct __elf_symbol instead of struct elf_symbol.
 */
struct shiva_xref_site {
	int type;
	uint64_t flags;
	uint64_t *got; // indirect xrefs use a .got to hold a symbol value.
#ifdef __aarch64__
	uint64_t adrp_imm; /* imm value of adrp */
	uint64_t adrp_site; /* site address of adrp */
	uint64_t adrp_o_insn; /* original instruction bytes of adrp */
	uint64_t next_imm; /* imm value of the add/str/ldr instruction */
	uint64_t next_site; /* site address of the add/str/ldr instruction */
	uint64_t next_o_insn; /* original instruction bytes of instruction after adrp */
#elif __x86_64__
	/*
	 * IP relative instructions for loading/storing, getting pointer vlaues etc.
	 * i.e.
	 * lea reg, qword ptr[rip + offset]
	 * mov qword ptr[rip + offset], reg
	 */
	int64_t rip_rel_disp; /* imm value of: <insn> <reg>, qword ptr[rip + <offset>] */
	uint64_t rip_rel_site; /* site address of ip relative instruction */
	uint8_t rip_rel_o_insn[16]; /* original instruction bytes */
	size_t insn_len;
	uint32_t addr_size; /* width of address being written/read */
	size_t jumptable_count; /* only relevant if it's an xref to a jumptable */
#endif
	uint32_t reloc_type;
	uint64_t target_vaddr; /* addr that is being xref'd. add to base_vaddr at runtime */
	struct __elf_symbol deref_symbol; /* Indirect symbol value pointed to by symbol.value */
	struct __elf_symbol symbol; /* symbol info for the symbol the xref goes to */
	struct __elf_symbol current_function; /* syminfo for src function if syminfo flag is set */
	TAILQ_ENTRY(shiva_xref_site) _linkage;
} shiva_xref_site_t;

typedef enum shiva_branch_type {
	SHIVA_BRANCH_JMP = 0,
	SHIVA_BRANCH_CALL,
	SHIVA_BRANCH_RET
} shiva_branch_type_t;

#define MAX_MNEMONIC_LEN 32

#define SHIVA_BRANCH_F_PLTCALL		(1UL << 0)
#define SHIVA_BRANCH_F_SRC_SYMINFO	(1UL << 1) /* symbol info of the source function is present */
#define SHIVA_BRANCH_F_DST_SYMINFO	(1UL << 2) /* symbol info of the dest function is present  */
#define SHIVA_BRANCH_F_INDIRECT		(1UL << 3) /* Indirect jmp or call (i.e. func pointer) */

struct shiva_branch_site {
	/* Original instruction */
#if __x86_64__
	uint8_t o_insn[15];
#elif __aarch64__
	uint32_t o_insn;
#endif
	struct __elf_symbol current_function; // source function of the branch
	struct __elf_symbol symbol; // symbol/func that is being called
	shiva_branch_type_t branch_type;
	uint64_t branch_flags;
	uint64_t target_vaddr;
	uint64_t branch_site;
	uint64_t retaddr; /*
			   * If this is a SHIVA_BRANCH_CALL then
			   * retaddr will point to the return address
			   * of the function being called. For now
			   * retaddr is not used in any other branch
			   * site type.
			   */
	uint64_t insn_string; /* Index into .shiva_strtab of mnemonic name */ 
	TAILQ_ENTRY(shiva_branch_site) _linkage;
} shiva_branch_site_t;

typedef enum shiva_pl_iterator_res {
	SHIVA_PL_ITER_OK = 0,
	SHIVA_PL_ITER_DONE,
	SHIVA_PL_ITER_ERROR
} shiva_pl_iterator_res_t;

/*
 * Shiva prelink context
 */
struct shiva_prelink_ctx {
	char *input_exec;
	char *input_patch;
	char *output_exec;
	char *search_path;
	char *interp_path;
	char *orig_interp_path;
	struct {
		elfobj_t elfobj;
	} bin;
	struct {
		elfobj_t elfobj;
	} patch;
	uint64_t flags;
	struct {
		uint64_t vaddr;
		uint64_t offset;
		uint64_t write_offset;
		size_t filesz;
		size_t memsz;
		size_t dyn_size; /* size of new PT_DYNAMIC */
		uint64_t dyn_offset; /* offset of PT_DYNAMIC */
		uint64_t search_path_offset; /* offset of module search path string */
		uint64_t needed_offset; /* offset of module basename path's */
	} new_segment; // a new PT_LOAD segment for our new PT_DYNAMIC to point into
	struct {
		csh handle;
		cs_insn *insn;
		uint8_t *textptr;
		uint64_t base;
	} disas;
	struct {
		TAILQ_HEAD(, shiva_xref_site) xref_tqlist;
		TAILQ_HEAD(, shiva_branch_site) branch_tqlist;
	} tailq;
	struct {
		char *strtab;
		size_t current_offset, max_size;
	} shiva_strtab;
	size_t xref_entry_totlen; /* total size of xref entries after CFG analysis */
	size_t branch_entry_totlen; /* total size of branch entries after CFG analysis */
	uint8_t *jmptab; // pointer to data in .llvm_jump_table_sizes section
	size_t jmptab_size; // size of jump table section
} shiva_prelink_ctx;

typedef struct jumptable_iterator {
	unsigned int index;
	struct shiva_prelink_ctx *ctx;
	uint8_t *jmptab;
	size_t entry_count;
} jumptable_iterator_t;

typedef struct jumptable_entry {
	uint64_t base; // base 0f jump table
	uint64_t entries; // number of jump targets from the base
} jumptable_entry_t;

static size_t get_shiva_strtab_offset(struct shiva_prelink_ctx *);
static bool set_shiva_strtab_string(struct shiva_prelink_ctx *, const char *, size_t *);
/*
 * TODO
 * shiva_strdup, shiva_xfmtstrdup, and shiva_malloc are copied from 
 * They should be put into a shiva common util library
 */

char *
shiva_strdup(const char *s)
{
	char *p = strdup(s);
	if (p == NULL) {
		perror("strdup");
		exit(EXIT_FAILURE);
	}
	return p;
}

char *
shiva_xfmtstrdup(char *fmt, ...)
{
	char buf[512];
	char *s;
	va_list va;

	va_start(va, fmt);
	vsnprintf(buf, sizeof(buf), fmt, va);
	s = shiva_strdup(buf);
	return s;
}

void *
shiva_malloc(size_t len)
{
	uint8_t *mem = malloc(len);
	if (mem == NULL) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	return mem;
}

void
jumptable_iterator_init(struct shiva_prelink_ctx *ctx, struct jumptable_iterator *iter)
{
	int i = 0;

	iter->index = 0;
	iter->ctx = ctx;
	iter->jmptab = ctx->jmptab;
	iter->entry_count = ctx->jmptab_size / 16;
	return;
}

shiva_pl_iterator_res_t
jumptable_iterator_next(struct jumptable_iterator *iter,
    struct jumptable_entry *entry)
{
	struct jmptab_struct {
		uint64_t base;
		uint64_t entries;
	};

	struct jmptab_struct *jptr = (struct jmptab_struct *)iter->jmptab;

	if (iter->index >= iter->entry_count)
		return SHIVA_PL_ITER_DONE;

	entry->base = jptr[iter->index].base;
	entry->entries = jptr[iter->index].entries;

	iter->index++;
	return SHIVA_PL_ITER_OK;
}

bool
elf_segment_copy(elfobj_t *elfobj, uint8_t *dst, struct elf_segment segment)
{
	size_t rem = segment.filesz % sizeof(uint64_t);
	uint64_t qword;
	bool res;
	size_t i = 0;

	for (i = 0; i < segment.filesz; i += sizeof(uint64_t)) {
		if (i + sizeof(uint64_t) >= segment.filesz) {
			size_t j;

			for (j = 0; j < rem; j++) {
				res = elf_read_address(elfobj, segment.vaddr + i + j,
				    &qword, ELF_BYTE);
				if (res == false) {
					fprintf(stderr, "elf_segment_copy "
					    "failed at %#lx\n", segment.vaddr + i + j);
					return false;
				}
				dst[i + j] = (uint8_t)qword;
			}
			break;
		}
		res = elf_read_address(elfobj, segment.vaddr + i, &qword, ELF_QWORD);
		if (res == false) {
			fprintf(stderr, "elf_read_address failed at %#lx\n", segment.vaddr + i);
			return false;
		}
		*(uint64_t *)&dst[i] = qword;
	}
	return true;
}

bool
elf_section_copy(elfobj_t *elfobj, uint8_t *dst, struct elf_section section)
{
	size_t rem = section.size % sizeof(uint64_t);
	uint64_t qword;
	bool res;
	size_t i = 0;

	for (i = 0; i < section.size; i += sizeof(uint64_t)) {
		if (i + sizeof(uint64_t) >= section.size) {
			size_t j;

			for (j = 0; j < rem; j++) {
				res = elf_read_address(elfobj, section.address + i + j,
				    &qword, ELF_BYTE);
				if (res == false) {
					fprintf(stderr, "elf_section_copy "
					    "failed at %#lx\n", section.address + i + j);
					return false;
				}
				dst[i + j] = (uint8_t)qword;
			}
			break;
		}
		res = elf_read_address(elfobj, section.address + i, &qword, ELF_QWORD);
		if (res == false) {
			fprintf(stderr, "elf_read_address failed at %#lx\n", section.address + i);
			return false;
		}
		*(uint64_t *)&dst[i] = qword;
	}
	return true;
}

static bool
set_dtag(struct shiva_prelink_ctx *ctx, ElfW(Dyn) *dyn, int d_tag, uint64_t value)
{
	int i;

	for (i = 0; dyn[i].d_tag != DT_NULL; i++) {
		if (dyn[i].d_tag == d_tag) {
			shiva_debug("Setting DTAG ptr to %#lx\n", value);
			dyn[i].d_un.d_val = value;
			return true;
		}
	}
	return false;
}

#define NEW_DYN_COUNT 3

bool
shiva_prelink(struct shiva_prelink_ctx *ctx)
{
	int fd, tmp_fd;
	struct elf_segment segment, n_segment;
	elf_segment_iterator_t phdr_iter;
	elf_error_t error;
	uint64_t last_load_vaddr, last_load_offset, last_load_size;
	uint64_t last_load_align;
	bool res;
	bool found_note = false, found_dynamic = false;
	uint8_t *mem;
	char *target_path;
	char template[] = "/tmp/elf.XXXXXX";
	char null = 0;
	struct stat st;
	uint8_t *old_dynamic_segment;
	size_t old_dynamic_size, dynamic_index;
	size_t old_shstrtab_len, old_e_shoff, old_e_shnum;
	struct elf_section dynstr_shdr, last_shdr;
	size_t appended_shstrtab_len;

	/*
	 * Get the last section header
	 */
	if (elf_section_by_index(&ctx->bin.elfobj, elf_shnum(&ctx->bin.elfobj) - 1,
	    &last_shdr) == false) {
		fprintf(stderr, "elf_section_by_index(%p, %d, ...) failed\n",
		    &ctx->bin.elfobj, elf_shnum(&ctx->bin.elfobj) - 1);
		return false;
	}
	if (strcmp(last_shdr.name, ".note.ABI-tag") == 0) {
		/*
		 * The last section header should be .shstrtab... ???
		 * except in rare edge-cases such as with the x86_64 NASA cFS binary
		 */
		shiva_debug("Enabling support for NASA cFS binary\n");
		ctx->flags |= SHIVA_LD_F_CFS_BINARY;
	}
	ctx->orig_interp_path = elf_interpreter_path(&ctx->bin.elfobj);
	if (ctx->orig_interp_path == NULL) {
		fprintf(stderr, "elf_interpreter_path() failed\n");
		return false;
	}
	/*
	 * We must do this or it will get overwritten later by an strcpy
	 */
	ctx->orig_interp_path = strdup(ctx->orig_interp_path);
	if (ctx->orig_interp_path == NULL) {
		perror("strdup");
		return false;
	}
	if (elf_flags(&ctx->bin.elfobj, ELF_DYNAMIC_F) == false) {
		fprintf(stderr, "Currently we do not support static ELF executable\n");
		return false;
	}
	/*
	 * XXX:
	 * We rely on the fact that by convention PT_DYNAMIC is typically before
	 * PT_NOTE, but there is nothing enforcing this. This code should be more
	 * robust in the future.
	 */
	elf_segment_iterator_init(&ctx->bin.elfobj, &phdr_iter);
	while (elf_segment_iterator_next(&phdr_iter, &segment) == ELF_ITER_OK) {
		if (segment.type == PT_LOAD) {
			last_load_vaddr = segment.vaddr;
			last_load_offset = segment.offset;
			last_load_size = segment.memsz;
			last_load_align = 4096; //segment.align;
		} else if (segment.type == PT_DYNAMIC) {
			found_dynamic = true;
			ctx->new_segment.dyn_size = elf_dtag_count(&ctx->bin.elfobj) * sizeof(ElfW(Dyn));
			if (ctx->flags & SHIVA_LD_F_NEEDED_INJECTION) {
				ctx->new_segment.dyn_size += sizeof(ElfW(Dyn));
				if (elf_section_by_name(&ctx->bin.elfobj, ".dynstr", &dynstr_shdr) == false) {
					fprintf(stderr, "elf_section_by_name() failed on .dynstr\n");
					return false;
				}
			} else {
				ctx->new_segment.dyn_size += (sizeof(ElfW(Dyn)) * (NEW_DYN_COUNT + 1));
			}
			ctx->new_segment.dyn_offset = 0;

			old_dynamic_size = (elf_dtag_count(&ctx->bin.elfobj) + 1) * sizeof(ElfW(Dyn));
			old_dynamic_segment = calloc(1, segment.filesz);
			if (old_dynamic_segment == NULL) {
				perror("calloc");
				return false;
			}
			if (elf_segment_copy(&ctx->bin.elfobj, old_dynamic_segment,
			    segment) == false) {
				fprintf(stderr, "Failed to copy original dynamic segment\n");
				return false;
			}
			Elf64_Dyn *dptr = (Elf64_Dyn *)old_dynamic_segment;
			while (dptr->d_tag != DT_NULL) {
				dptr++;
			}
			ctx->new_segment.filesz = segment.filesz;

			/*
			 * Make room for the 3 new additional dynamic entries
			 * Make room for the string lens of the patch path, search path, and interp path
			 * Make room for the string lens of the 3 new sections
			 * Make room for the Shdr structs of the 3 new sections
			 */
			ctx->new_segment.filesz += sizeof(ElfW(Dyn)) * NEW_DYN_COUNT;
			ctx->new_segment.filesz += get_shiva_strtab_offset(ctx);
			if ((ctx->flags & SHIVA_LD_F_NO_CFG) == 0) {
				ctx->new_segment.filesz += ctx->xref_entry_totlen;
				ctx->new_segment.filesz += ctx->branch_entry_totlen;
				ctx->new_segment.filesz += sizeof(ElfW(Shdr)) * 3;
			}
			if (ctx->flags & SHIVA_LD_F_NEEDED_INJECTION) {
				printf(".dynstr original size: %zu\n", dynstr_shdr.size);
				ctx->new_segment.filesz += dynstr_shdr.size;
				ctx->new_segment.filesz += strlen(ctx->input_patch) + 1;
			}
			/*
			 * Mark the index of this segment so that we can modify it
			 * to match the new dynamic segment location once we know it.
			 */
			dynamic_index = phdr_iter.index - 1;
		} else if (segment.type == PT_NOTE) {
			if (found_dynamic == false) {
				fprintf(stderr, "Failed to find PT_DYNAMIC before PT_NOTE\n");
				return false;
			}
			n_segment.type = PT_LOAD;
			/*
			 * Make room for the strings of 3 new section headers: .shiva.strtab, .shiva.xref and .shiva.branch
			 * And for 3 section headers (i.e. Elf64_Shdr) entries being added. This will effect the file offset
			 * to where our new segment lives. (Only if we are generating CFG data for xrefs and branches)
			 */
			if ((ctx->flags & SHIVA_LD_F_NO_CFG) == 0) {
				size_t new_lens = sizeof(ElfW(Shdr)) * 3;
				new_lens += strlen(".shiva.strtab") + 1 + strlen(".shiva.xref") + 1 + strlen(".shiva.branch") + 1;
				new_lens += sizeof(ElfW(Shdr)) * 3;
				n_segment.offset =
				    ELF_PAGEALIGN(ctx->bin.elfobj.size + new_lens, last_load_align);
			} else {
				n_segment.offset =
					ELF_PAGEALIGN(ctx->bin.elfobj.size, last_load_align);
			}
			n_segment.filesz = ctx->new_segment.filesz;
			n_segment.memsz = ctx->new_segment.filesz;
			n_segment.vaddr = ELF_PAGEALIGN(last_load_vaddr +
			    last_load_size, last_load_align);
			n_segment.paddr = n_segment.vaddr;
			n_segment.align = last_load_align;
			n_segment.flags = (PF_R|PF_X|PF_W);
			res = elf_segment_modify(&ctx->bin.elfobj,
			    phdr_iter.index - 1, &n_segment, &error);
			if (res == false) {
				fprintf(stderr, "[!] elf_segment_modify "
				    "failed: %s\n", elf_error_msg(&error));
				return false;
			}
			/*
			 * Now that we know the location of our new LOAD segment
			 * we can modify PT_DYNAMIC to point to it's new location
			 */
			struct elf_segment dyn_segment;

			ctx->new_segment.vaddr = n_segment.vaddr;
			ctx->new_segment.offset = n_segment.offset;
			ctx->new_segment.filesz = n_segment.filesz;
			ctx->new_segment.memsz = n_segment.memsz;

			dyn_segment.type = PT_DYNAMIC;
			dyn_segment.flags = PF_R|PF_W;
			dyn_segment.vaddr = ctx->new_segment.vaddr;
			dyn_segment.paddr = dyn_segment.vaddr;
			dyn_segment.offset = ctx->new_segment.offset;
			dyn_segment.filesz = ctx->new_segment.dyn_size;
			dyn_segment.memsz = ctx->new_segment.dyn_size;
			dyn_segment.align = 8;

			printf("Updating dynamic segment vaddr: %#lx offset: %#lx size: %#lx\n", dyn_segment.vaddr,
			    dyn_segment.offset, dyn_segment.filesz);

			res = elf_segment_modify(&ctx->bin.elfobj,
			    dynamic_index, &dyn_segment, &error);
			if (res == false) {
				fprintf(stderr, "[!] elf_segment_modify "
				    "failed: %s\n", elf_error_msg(&error));
				return false;
			}
			found_note = true;
			break;
		}
	}
	if (found_note == false || found_dynamic == false) {
		fprintf(stderr, "Failed to create an extra load segment\n");
		return false;
	}
	/*
	 * Update the .dynamic section offset/addr/size
	 * to reflect the new dynamic segment.
	 */
	elf_section_iterator_t shdr_iter;
	struct elf_section shdr, shstrtab_shdr;

	elf_section_iterator_init(&ctx->bin.elfobj, &shdr_iter);
	while (elf_section_iterator_next(&shdr_iter, &shdr) == ELF_ITER_OK) {
		if (shdr.type == SHT_DYNAMIC) {
			struct elf_section tmp;

			memcpy(&tmp, &shdr, sizeof(tmp));
			tmp.offset = ctx->new_segment.offset;
			tmp.address = ctx->new_segment.vaddr;
			tmp.size = ctx->new_segment.dyn_size;

			res = elf_section_modify(&ctx->bin.elfobj, shdr_iter.index - 1,
			    &tmp, &error);
			if (res == false) {
				fprintf(stderr, "[!] elf_section_modify "
				    "failed: %s\n", elf_error_msg(&error));
				return false;
			}
			/*
			 * Update the .shstrtab section so that it's new size reflects
			 * the new strings added for the new sections.
			 */
		} else if ((strcmp(shdr.name, ".shstrtab") == 0) && ((ctx->flags & SHIVA_LD_F_NO_CFG) == 0)) {
			struct elf_section tmp;

			memcpy(&tmp, &shdr, sizeof(tmp));
			old_shstrtab_len = tmp.size;
			tmp.size += appended_shstrtab_len = strlen(".shiva.strtab") + 1 +
			    strlen(".shiva.xref") + 1 + strlen(".shiva.branch") + 1;
			shiva_pl_debug("Increased .shstrtab size by %zu bytes\n", tmp.size - old_shstrtab_len);
			res = elf_section_modify(&ctx->bin.elfobj, shdr_iter.index - 1,
			    &tmp, &error);
			if (res == false) {
				fprintf(stderr, "[!] elf_section_modify "
				    "failed: %s\n", elf_error_msg(&error));
				return false;
			}
		}
	}
	/*
	 * Commit the changes to the section header data on the backend.
	 */
	elf_section_commit(&ctx->bin.elfobj);

	/*
	 * Write out
	 * 1. Original ELF executable up until .shstrtab section (Or up until .note.ABI-tag section when -c is used)
	 * 2. Add additional string data for 3 new sections ".shiva.xref, .shiva.branch, .shiva.strtab"
	 * 2. New dynamic segment (With additional SHIVA_DT_ entries)
	 * 3. Strings table '.shiva.strtab' for searchpath, module, cfg symbols
	 */

	if (stat(elf_pathname(&ctx->bin.elfobj), &st) < 0) {
		perror("stat");
		return false;
	}

	fd = mkstemp(template);
	if (fd < 0) {
		perror("mkstemp");
		return false;
	}

	if ((ctx->flags & SHIVA_LD_F_NO_CFG) == 0) {
		struct elf_section note_abi_shdr;

		if ((ctx->flags & SHIVA_LD_F_CFS_BINARY)) {
			size_t shdr_size = elf_class(&ctx->bin.elfobj) == elfclass32	
			    ? sizeof(Elf32_Shdr) : sizeof(Elf64_Shdr);

			shiva_debug("Detected cFS binary re-linking\n");
			if (elf_section_by_name(&ctx->bin.elfobj, ".note.ABI-tag", &note_abi_shdr) == false) {
				fprintf(stderr, "elf_section_by_name(%p, \"%s\", ...) failed\n",
				    &ctx->bin.elfobj, ".note.ABI-tag");
				return false;
			}
			elf_section_iterator_t shdr_iter;
			struct elf_section shdr, tmp;
			bool strtab_found = false;

			/*
			 * shift .strtab forward by the new added .shstrtab bytes.
			 * shift all sections after .strtab by the new added .shstrtab bytes + (sizeof(Elf64_Shdr) * 3); to account for the
			 * new sections added to the shdr table, which in the cfs binary is strangely between the .strtab and .dynamic section
			 * rather than at the end of the file like with conventional (non-tampered with) ELF's.
			 */
			elf_section_iterator_init(&ctx->bin.elfobj, &shdr_iter);
			while (elf_section_iterator_next(&shdr_iter, &shdr) == ELF_ITER_OK) {
				if (strcmp(shdr.name, ".strtab") == 0) {
					tmp = shdr;
					tmp.offset += appended_shstrtab_len;
					res = elf_section_modify(&ctx->bin.elfobj, shdr_iter.index - 1,
					    &tmp, &error);
					if (res == false) {
						fprintf(stderr, "[!] elf_section_modify "
						    "failed: %s\n", elf_error_msg(&error));
						return false;
					}
					elf_section_commit(&ctx->bin.elfobj);
					strtab_found = true;
					continue;
				} else if (strtab_found == true) {
					if (strcmp(shdr.name, ".dynamic") == 0) // we skip shifting this section forward
						continue;			// because it has been moved to our newly added PT_LOAD
					/*
					 * The last section headers after .strtab
					 [50] .dynamic		   DYNAMIC	0000000000300000 00300000 000001d0 16 WA    51	 0  8
					 [51] .dynstr		   STRTAB	00000000002f01b0 002f01b0 000073a5  0 A      0	 0  8
					 [52] .dynsym		   DYNSYM	00000000002f7558 002f7558 000084c0 24 A     51	 1  8
					 [53] .interp		   PROGBITS	00000000002ffa18 002ffa18 0000001c  0 A      0	 0  8
					 [54] .note.ABI-tag	   NOTE		00000000002ffa38 002ffa38 00000020  0 A      0	 0  4
					*/
					tmp = shdr;
					tmp.offset += appended_shstrtab_len + (shdr_size * 3);
					tmp.address += appended_shstrtab_len + (shdr_size * 3);
					res = elf_section_modify(&ctx->bin.elfobj, shdr_iter.index - 1,
					    &tmp, &error);
					if (res == false) {
						 fprintf(stderr, "[!] elf_section_modify "
						    "failed: %s\n", elf_error_msg(&error));
						return false;
					}
					elf_section_commit(&ctx->bin.elfobj);
				}
			}
			elf_segment_iterator_t phdr_iter;
			struct elf_segment phdr, tmp_phdr;

			elf_segment_iterator_init(&ctx->bin.elfobj, &phdr_iter);
			while (elf_segment_iterator_next(&phdr_iter, &phdr) == ELF_ITER_OK) {
				if (phdr.type == PT_INTERP) {
					tmp_phdr = phdr;
					tmp_phdr.offset += appended_shstrtab_len + (shdr_size * 3);
					tmp_phdr.vaddr += appended_shstrtab_len + (shdr_size * 3);
					tmp_phdr.paddr += appended_shstrtab_len + (shdr_size * 3);
					res = elf_segment_modify(&ctx->bin.elfobj, phdr_iter.index - 1,
					    &tmp_phdr, &error);
					if (res == false) {
						fprintf(stderr, "elf_segment_modify() failed on phdr %d: %s\n",
						    phdr_iter.index - 1, elf_error_msg(&error));
						return false;
					}
					break;
				}
			}
		}
		if (elf_section_by_name(&ctx->bin.elfobj, ".shstrtab", &shstrtab_shdr) == false) {
			fprintf(stderr, "elf_section_by_name(%p, \"%s\", ...) failed\n",
			    &ctx->bin.elfobj, ".shstrtab");
			return false;
		}
		size_t shentsize;

		if (elf_class(&ctx->bin.elfobj) == elfclass32) {
			shiva_pl_debug("Increasing e_shoff by %zu bytes\n", shstrtab_shdr.size - old_shstrtab_len);
			old_e_shoff = ctx->bin.elfobj.ehdr32->e_shoff;
			ctx->bin.elfobj.ehdr32->e_shoff += shstrtab_shdr.size - old_shstrtab_len;
			old_e_shnum = ctx->bin.elfobj.ehdr32->e_shnum;
			ctx->bin.elfobj.ehdr32->e_shnum += 3;
			shentsize = sizeof(Elf32_Shdr);
		} else if (elf_class(&ctx->bin.elfobj) == elfclass64) {
			shiva_pl_debug("Increasing e_shoff by %zu bytes\n", shstrtab_shdr.size - old_shstrtab_len);
			old_e_shoff = ctx->bin.elfobj.ehdr64->e_shoff;
			ctx->bin.elfobj.ehdr64->e_shoff += shstrtab_shdr.size - old_shstrtab_len;
			old_e_shnum = ctx->bin.elfobj.ehdr64->e_shnum;
			ctx->bin.elfobj.ehdr64->e_shnum += 3;
			shentsize = sizeof(Elf64_Shdr);
		}

		/*
		 * Write up until the location of the .shstrtab string data + sh_size
		 */
		if (write(fd, ctx->bin.elfobj.mem, shstrtab_shdr.offset + old_shstrtab_len) < 0) {
			perror("write 1.");
			return false;
		}
		/*
		 * write out three new strings into .shstrtab
		 */
		if (write(fd, (char *)".shiva.strtab", strlen(".shiva.strtab") + 1) < 0) {
			perror("write 2.");
			return false;
		}

		if (write(fd, (char *)".shiva.xref", strlen(".shiva.xref") + 1) < 0) {
			perror("write 3.");
			return false;
		}

		if (write(fd, (char *)".shiva.branch", strlen(".shiva.branch") + 1) < 0) {
			perror("write 4.");
			return false;
		}

		size_t off = shstrtab_shdr.offset + old_shstrtab_len;

		/*
		 * Write up until the end of the section header table.
		 */
		if (write(fd, &ctx->bin.elfobj.mem[off],
		    old_e_shoff + (old_e_shnum * shentsize) - off) < 0) {
			perror("write 5.");
			return false;
		}
		loff_t section_offset;

		section_offset = lseek(fd, 0, SEEK_CUR);

		ElfW(Shdr) tmp_shdr;
		/*
		 * Write out shdr for .shiva.strtab
		 */
		tmp_shdr.sh_name = old_shstrtab_len;
		tmp_shdr.sh_type = SHT_PROGBITS;
		tmp_shdr.sh_flags = SHF_ALLOC;
		tmp_shdr.sh_addr = ctx->new_segment.vaddr + ctx->new_segment.dyn_size;
		tmp_shdr.sh_offset = ctx->new_segment.offset + ctx->new_segment.dyn_size;
		tmp_shdr.sh_size = get_shiva_strtab_offset(ctx);
		tmp_shdr.sh_link = 0;
		tmp_shdr.sh_info = 0;
		tmp_shdr.sh_addralign = 1;
		tmp_shdr.sh_entsize = 1;

		if (write(fd, &tmp_shdr, sizeof(ElfW(Shdr))) < 0) {
			perror("write 6");
			return false;
		}

		/*
		 * Write out shdr for .shiva.xref
		 */
		tmp_shdr.sh_name = old_shstrtab_len + strlen(".shiva.strtab") + 1;
		tmp_shdr.sh_type = SHT_PROGBITS;
		tmp_shdr.sh_flags = SHF_ALLOC;
		tmp_shdr.sh_addr = ctx->new_segment.vaddr + ctx->new_segment.dyn_size + get_shiva_strtab_offset(ctx);
		tmp_shdr.sh_offset = ctx->new_segment.offset + ctx->new_segment.dyn_size + get_shiva_strtab_offset(ctx);
		tmp_shdr.sh_size = ctx->xref_entry_totlen;
		tmp_shdr.sh_link = old_e_shnum; // This should now point to .shiva.strtab
		tmp_shdr.sh_info = 0;
		tmp_shdr.sh_addralign = 8;
		tmp_shdr.sh_entsize = sizeof(struct shiva_xref_site) - sizeof(void *);

		if (write(fd, &tmp_shdr, sizeof(ElfW(Shdr))) < 0) {
			perror("write 7");
			return false;
		}

		/*
		 * Write out shdr for .shiva.branch
		 */
		tmp_shdr.sh_name = old_shstrtab_len + strlen(".shiva.strtab") + 1 + strlen(".shiva.xref") + 1;
		tmp_shdr.sh_type = SHT_PROGBITS;
		tmp_shdr.sh_flags = SHF_ALLOC;
		tmp_shdr.sh_addr = ctx->new_segment.vaddr + ctx->new_segment.dyn_size +
		    get_shiva_strtab_offset(ctx) + ctx->xref_entry_totlen;
		tmp_shdr.sh_offset =  ctx->new_segment.offset + ctx->new_segment.dyn_size +
		    get_shiva_strtab_offset(ctx) + ctx->xref_entry_totlen;
		tmp_shdr.sh_size = ctx->branch_entry_totlen;
		tmp_shdr.sh_link = old_e_shnum; // should point to .shiva.strtab shdr index
		tmp_shdr.sh_info = 0;
		tmp_shdr.sh_addralign = 8;
		tmp_shdr.sh_entsize = sizeof(struct shiva_branch_site) - sizeof(void *);

		if (write(fd, &tmp_shdr, sizeof(ElfW(Shdr))) < 0) {
			perror("write 8");
			return false;
		}

		if (ctx->flags & SHIVA_LD_F_CFS_BINARY) {
			/*
			 * If this is the X86_64 cFS ELF binary (NASA's core-flight)
			 * the section header table is not at the end of the binary it's
			 * strangely in between .strtab and .dynamic. So at this point
			 * we must continue writing out the rest of the executable:
			 * which seems to include .dynstr, .dynsym, .interp ,and .note-ABI-.tag
			 */
			size_t shdr_size = elf_class(&ctx->bin.elfobj) == elfclass32
			    ? sizeof(Elf32_Shdr) : sizeof(Elf64_Shdr);
			size_t len = (note_abi_shdr.offset + note_abi_shdr.size) -
			    (old_e_shoff + (old_e_shnum * shentsize));
			/*
			 * Starting off at the end of the original section header table
			 * and from there writing out the rest of the original executable.
			 */
			shiva_debug("writing from out %#lx bytes in between .strtab and .dynamic\n",
			    len);
			if (write(fd,
			    &ctx->bin.elfobj.mem[old_e_shoff + (old_e_shnum * shentsize)], len) < 0) {
				perror("write 9.");
				return false;
			}
			/*
			 * Earlier in the code we updated the offset and address value of
			 * several section header (including .dynstr) moving them forward.
			 * This will get the latest (new) address for .dynstr before updating
			 * DT_STRTAB in the dynamic segment with this new value.
			 */
			if (elf_section_by_name(&ctx->bin.elfobj, ".dynstr", &dynstr_shdr) == false) {
				fprintf(stderr, "elf_section_by_name() failed on .dynstr\n");
				return false;
			}
			if (set_dtag(ctx, (ElfW(Dyn) *)old_dynamic_segment, DT_STRTAB,
			    dynstr_shdr.address) == false) {
				fprintf(stderr, "Failed to set DT_STRTAB value\n");
				return false;
			}
		}

		/*
		 * Lseek to the offset of where our new segment begins.
		 */
		if (lseek(fd, n_segment.offset, SEEK_SET) < 0) {
			perror("lseek");
			return false;
		}

		/*
		 * Write out entire old dynamic segment, except for the last entry
		 * which will be DT_NULL
		 */
		if (write(fd, old_dynamic_segment,
		    old_dynamic_size - sizeof(Elf64_Dyn)) < 0) {
			perror("write 9.");
			return false;
		}

#define NEW_DYN_ENTRY_SZ 4

		ElfW(Dyn) dyn[NEW_DYN_ENTRY_SZ];

		/*
		 * Write out new dynamic entry for SHIVA_DT_SEARCH and
		 * SHIVA_DT_NEEDED
		 */
		dyn[0].d_tag = SHIVA_DT_SEARCH;
		dyn[0].d_un.d_ptr = ctx->new_segment.vaddr + ctx->new_segment.dyn_size;
		dyn[1].d_tag = SHIVA_DT_NEEDED;
		dyn[1].d_un.d_ptr = ctx->new_segment.vaddr +
		    ctx->new_segment.dyn_size + strlen(ctx->search_path) + 1;
		dyn[2].d_tag = SHIVA_DT_ORIG_INTERP;
		dyn[2].d_un.d_ptr = ctx->new_segment.vaddr + ctx->new_segment.dyn_size +
		    strlen(ctx->search_path) + 1 + strlen(ctx->input_patch) + 1;
		dyn[3].d_tag = DT_NULL;
		dyn[3].d_un.d_ptr = 0x0;

		/*
		 * Write out custom dtags, i.e.:
		 * 1. SHIVA_DT_SEARCH
		 * 2. SHIVA_DT_NEEDED
		 * 3. SHIVA_DT_ORIG_INTERP
		 */
		if (write(fd, &dyn[0], sizeof(dyn)) < 0) {
			perror("write 10.");
			return false;
		}

		/*
		 * Write out the string data (Marked by our new
		 * section: .shiva.strtab)
		 */
		shiva_pl_debug("Writing out strtab\n");
		int i;
#if 0
#if debug
		for (i = 0; i < get_shiva_strtab_offset(ctx); i++) {
			printf("%c", ctx->shiva_strtab.strtab[i]);
			fflush(stdout);
		}
		printf("\n");
		fflush(stdout);
#endif
#endif

		if (write(fd, ctx->shiva_strtab.strtab, ctx->shiva_strtab.current_offset) < 0) {
			perror("write 11");
			return false;
		}

		/*
		 * Write out xref entries into the .shiva.xref section area.
		 */
		struct shiva_xref_site *xref_site;

		TAILQ_FOREACH(xref_site, &ctx->tailq.xref_tqlist, _linkage) {
			int ret;

			ret = write(fd, xref_site, sizeof(*xref_site) - sizeof(uintptr_t));
			if (ret < 0) {
				perror("write");
				return false;
			}
		}

		/*
		 * Write out branch entries into .shiva.branch section area.
		 */
		struct shiva_branch_site *branch_site;

		TAILQ_FOREACH(branch_site, &ctx->tailq.branch_tqlist, _linkage) {
			int ret;

			ret = write(fd, branch_site, sizeof(*branch_site) - sizeof(uintptr_t));
			if (ret < 0) {
				perror("write");
				return false;
			}
		}
	} else {
		 /* 
		  *  We are not generating a CFG... so we re-write the ELF binary
		  *  with all of the changes, except without adding in the .shiva.xref, .shiva.branch
		  *  and .shiva.strtab sections.
		  */
		if (write(fd, ctx->bin.elfobj.mem, ctx->bin.elfobj.size) < 0) {
			perror("write");
			return false;
		}

		if (write(fd, &null, n_segment.offset - ctx->bin.elfobj.size) < 0) {
			perror("write");
			return false;
		}
 
		/*
		 * IF this is a DT_NEEDED Injection then we handle things a bit differently.
		 */
		if (ctx->flags & SHIVA_LD_F_NEEDED_INJECTION) {
			ElfW(Dyn) dyn[1];
			size_t dynstr_n_offset = n_segment.offset + old_dynamic_size
			    + sizeof(dyn[0]) + sizeof(dyn[0]); // + strlen(ctx->input_patch) + 1;
			size_t dynstr_n_vaddr = n_segment.vaddr + old_dynamic_size
			    + sizeof(dyn[0]) + sizeof(dyn[0]) ; //+ strlen(ctx->input_patch) + 1;
			uint64_t dynstr_index;

			printf("Writing out DT_NEEDED entry for %s in new dyn segment\n", ctx->input_patch);
			dyn[0].d_tag = DT_NEEDED;
			dyn[0].d_un.d_ptr = dynstr_shdr.size;

			printf("Writing out %ld bytes\n", sizeof(dyn[0]) + old_dynamic_size + strlen(ctx->input_patch) + 1);

			if (write(fd, &dyn[0], sizeof(dyn[0])) < 0) {
				perror("write");
				return false;
			}

			if (set_dtag(ctx, (ElfW(Dyn) *)old_dynamic_segment, DT_STRTAB, dynstr_n_vaddr) == false) {
				fprintf(stderr, "Failed to set DT_STRTAB value\n");
				return false;
			}
			if (set_dtag(ctx, (ElfW(Dyn) *)old_dynamic_segment, DT_STRSZ,
			    dynstr_shdr.size + strlen(ctx->input_patch) + 1) == false) {
				fprintf(stderr, "Failed to set DT_STRSZ value\n");
				return false;
			}
			if (write(fd, old_dynamic_segment,
			    old_dynamic_size) < 0) {
				perror("write");
				return false;
			}
			dyn[0].d_tag = DT_NULL;
			dyn[0].d_un.d_ptr = 0x0;

			if (write(fd, &dyn[0], sizeof(dyn[0])) < 0) {
				perror("write");
				return false;
			}
			if (write(fd, &ctx->bin.elfobj.mem[dynstr_shdr.offset],
			    dynstr_shdr.size) < 0) {
				perror("write");
				return false;
			}
			if (write(fd, ctx->input_patch,
			    strlen(ctx->input_patch) + 1) != strlen(ctx->input_patch) + 1) {
				perror("write");
				return false;
			}
			if (fchown(fd, st.st_uid, st.st_gid) < 0) {
				perror("fchown");
				return false;
			}
			if (fchmod(fd, st.st_mode) < 0) {
				perror("fchmod");
				return false;
			}
			close(fd);

			elf_close_object(&ctx->bin.elfobj);
			rename(template, ctx->output_exec);

			printf("Opening file %s\n", ctx->output_exec);
			if (elf_open_object(ctx->output_exec, &ctx->bin.elfobj,
			    ELF_LOAD_F_MODIFY|ELF_LOAD_F_FORENSICS, &error) == false) {
				fprintf(stderr, "elf_open_object(%s, ...) failed: %s\n",
				    ctx->output_exec, elf_error_msg(&error));
				return false;
			}
			if (elf_section_index_by_name(&ctx->bin.elfobj, ".dynstr", &dynstr_index) == false) {
				fprintf(stderr, "elf_section_index_by_name() failed on .dynstr\n");
				return false;
			}

			dynstr_shdr.offset = dynstr_n_offset;
			dynstr_shdr.address = dynstr_n_vaddr;
			dynstr_shdr.size += strlen(ctx->input_patch) + 1;

			printf("dynstr_shdr offset: %#lx\n", dynstr_n_offset);
			printf("Modifying dynstr index %zu\n", dynstr_index);
			if (elf_section_modify(&ctx->bin.elfobj, dynstr_index, 
			    &dynstr_shdr, &error) == false) {
				fprintf(stderr, "elf_section_modify() failed\n");
				return false;
			}
			elf_section_commit(&ctx->bin.elfobj);
			*(uint32_t *)&ctx->bin.elfobj.mem[EI_PAD] = SHIVA_SIGNATURE;
			elf_close_object(&ctx->bin.elfobj);
			return true;
		}
		if (write(fd, old_dynamic_segment,
		    old_dynamic_size - sizeof(ElfW(Dyn))) < 0) {
			perror("write");
			return false;
		}

#define NEW_DYN_ENTRY_SZ 4

		ElfW(Dyn) dyn[NEW_DYN_ENTRY_SZ];

		/*
		 * Write out new dynamic entry for SHIVA_DT_SEARCH and
		 * SHIVA_DT_NEEDED
		 */
		dyn[0].d_tag = SHIVA_DT_SEARCH;
		dyn[0].d_un.d_ptr = ctx->new_segment.vaddr + ctx->new_segment.dyn_size;
		dyn[1].d_tag = SHIVA_DT_NEEDED;
		dyn[1].d_un.d_ptr = ctx->new_segment.vaddr +
		    ctx->new_segment.dyn_size + strlen(ctx->search_path) + 1;
		dyn[2].d_tag = SHIVA_DT_ORIG_INTERP;
		dyn[2].d_un.d_ptr = ctx->new_segment.vaddr + ctx->new_segment.dyn_size +
		    strlen(ctx->search_path) + 1 + strlen(ctx->input_patch) + 1;
		dyn[3].d_tag = DT_NULL;
		dyn[3].d_un.d_ptr = 0x0;

		/*
		 * Write out custom dtags, i.e.:
		 * 1. SHIVA_DT_SEARCH
		 * 2. SHIVA_DT_NEEDED
		 * 3. SHIVA_DT_ORIG_INTERP
		 */
		if (write(fd, &dyn[0], sizeof(dyn)) < 0) {
			perror("write");
			return false;
		}
		if (write(fd, ctx->search_path, strlen(ctx->search_path) + 1) < 0) {
			perror("write");
			return false;
		}
		if (write(fd, ctx->input_patch, strlen(ctx->input_patch) + 1) < 0) {
			perror("write");
			return false;
		}
		if (write(fd, ctx->orig_interp_path,
		    strlen(ctx->orig_interp_path) + 1) < 0) {
			perror("write 7.");
			return false;
		}
	}

	if (fchown(fd, st.st_uid, st.st_gid) < 0) {
		perror("fchown");
		return false;
	}
	if (fchmod(fd, st.st_mode) < 0) {
		perror("fchmod");
		return false;
	}
	close(fd);

	target_path = strdup(elf_pathname(&ctx->bin.elfobj));
	if (target_path == NULL) {
		perror("strdup");
		return false;
	}

	elf_close_object(&ctx->bin.elfobj);
	rename(template, ctx->output_exec);

	if (elf_open_object(ctx->output_exec, &ctx->bin.elfobj,
	    ELF_LOAD_F_MODIFY|ELF_LOAD_F_FORENSICS, &error) == false) {
		fprintf(stderr, "elf_open_object(%s, ...) failed: %s\n",
		    ctx->output_exec, elf_error_msg(&error));
		free(target_path);
		return false;
	}
	free(target_path);
	*(uint32_t *)&ctx->bin.elfobj.mem[EI_PAD] = SHIVA_SIGNATURE;

	char *path = elf_interpreter_path(&ctx->bin.elfobj);
	/*
	 * path now points to (char *)&mem[phdr[PT_INTERP].p_offset]: "/lib/ld-linux.so"
	 */
	if (strlen(ctx->interp_path) > strlen(path)) {
		fprintf(stderr, "PT_INTERP is only %zu bytes and cannot house the string %s\n",
		    (size_t)strlen(path), ctx->interp_path);
		return false;
	}
	/*
	 * Overwrite the path stored in PT_INTERP with the new
	 * interpreter path (i.e. "/lib/shiva").
	 */
	strcpy(path, ctx->interp_path);
#if 0
	if ((ctx->flags & SHIVA_LD_F_CFS_BINARY && ((ctx->flags & SHIVA_LD_F_NO_CFG) == 0))) {
		elf_section_iterator_t shdr_iter;
		struct elf_section shdr;
		bool found_shstrtab = false;

		elf_section_iterator_init(&ctx->bin.elfobj, &shdr_iter);
		while (elf_section_iterator_next(&shdr_iter, &shdr) == ELF_ITER_OK) {
			if (strcmp(shdr.name, ".shstrtab") == 0) {
				found_shstrtab = true;
				continue;
			}
			/*
			 * All other sections after .shstrtab should be shifted forward by
			 * the length of bytes added to .shstrtab (To accompany room for our new custom sections)
			 */
			if (found_shstrtab == true) {
				struct elf_section tmp = shdr;
				elf_error_t error;
				size_t shdr_size = elf_class(&ctx->bin.elfobj) == elfclass32
				    ? sizeof(Elf32_Shdr) : sizeof(Elf64_Shdr);

				shiva_debug("Shifting section %s forward by %lx bytes (updating sh_offset)\n", tmp.name, appended_shstrtab_len);
				tmp.offset += appended_shstrtab_len + (shdr_size * 3);
				res = elf_section_modify(&ctx->bin.elfobj, shdr_iter.index - 1,
				    &tmp, &error);
				if (res == false) {
					fprintf(stderr, "[!] elf_section_modify "
					    "failed: %s\n", elf_error_msg(&error));
					return false;
				}
				elf_section_commit(&ctx->bin.elfobj);
			}
		}
	}
#endif
	elf_close_object(&ctx->bin.elfobj);
	return true;
}

#ifdef __aarch64__
/*
 * TODO
 * Way to many args, turn this into a macro.
 */
static inline bool
gen_aarch64_xref(struct shiva_prelink_ctx *ctx, struct elf_symbol *symbol, struct elf_symbol *deref_symbol,
    struct elf_symbol *src_func, int xref_type, uint64_t xref_flags, uint64_t adrp_site,
    uint64_t adrp_imm, uint64_t next_imm,
    uint32_t adrp_o_bytes, uint32_t next_o_bytes)
{
	struct shiva_xref_site *xref;
	uint64_t gotaddr;

	xref = calloc(1, sizeof(*xref));
	if (xref == NULL) {
		perror("calloc");
		return false;
	}
	shiva_pl_debug("XREF (Type: %d): site: %#lx target: %s(%#lx)\n",
	    xref_type, adrp_site, symbol->name, symbol->value);
	if (xref_flags & SHIVA_XREF_F_INDIRECT) {
		memcpy(&xref->deref_symbol, deref_symbol, sizeof(struct elf_symbol));
		gotaddr = (adrp_site & ~0xfff) + adrp_imm + next_imm;
		xref->got = (uint64_t *)gotaddr;
		assert(deref_symbol->name != NULL);
		if (set_shiva_strtab_string(ctx, deref_symbol->name,
		    &xref->deref_symbol.name) == false) {
			fprintf(stderr, "Failed to insert '%s' into string table\n",
			    deref_symbol->name);
			return false;
		}
	}
	xref->type = xref_type;
	xref->flags = xref_flags;
	xref->adrp_imm = adrp_imm;
	xref->adrp_site = adrp_site;
	xref->next_imm = next_imm;
	xref->next_site = adrp_site + ARM_INSN_LEN;
	xref->adrp_o_insn = adrp_o_bytes; //*(uint32_t *)&tmp_ptr[c];
	xref->next_o_insn = next_o_bytes; //*(uint32_t *)&tmp_ptr[c + ARM_INSN_LEN];
	xref->target_vaddr = (adrp_site & ~0xfff) + adrp_imm + next_imm;
	shiva_pl_debug("ADRP(%#lx): %lx\n", adrp_site, xref->adrp_o_insn);
	shiva_pl_debug("NEXT(%#lx): %lx\n", xref->next_site, xref->next_o_insn);
	memcpy(&xref->symbol, symbol, sizeof(*symbol));
	assert(symbol->name != NULL);
	if (set_shiva_strtab_string(ctx, symbol->name,
	    &xref->symbol.name) == false) {
		fprintf(stderr, "Failed to insert '%s' into string table\n",
		    symbol->name);
		return false;
	}
	if (src_func != NULL) {
		memcpy(&xref->current_function, src_func, sizeof(*src_func));
		assert(src_func->name != NULL);
		if (set_shiva_strtab_string(ctx, src_func->name,
		    &xref->current_function.name) == false) {
			fprintf(stderr, "Failed to insert '%s' into string table\n",
			    src_func->name);
			return false;
		}
	}
	shiva_pl_debug("Generated XREF: For symbol %s(stroffset: %zu\n", symbol->name, xref->symbol.name);
	TAILQ_INSERT_TAIL(&ctx->tailq.xref_tqlist, xref, _linkage);
	/*
	 * Increase size of xref_entry_totlen by sizeof(struct shiva_xref_entry),
	 * however...
	 * We don't include the size of the last member of the struct which
	 * is a pointer to the next entry in the linked list. This isn't
	 * necesary to store in the ELF file.
	 */
	ctx->xref_entry_totlen += sizeof(struct shiva_xref_site) - sizeof(uintptr_t);
	return true;
}
#endif

static size_t 
get_shiva_strtab_offset(struct shiva_prelink_ctx *ctx)
{

	return ctx->shiva_strtab.current_offset;
}

static bool
set_shiva_strtab_string(struct shiva_prelink_ctx *ctx, const char *string, size_t *soff)
{
	size_t off = ctx->shiva_strtab.current_offset;

	shiva_pl_debug("set_shiva_strtab_string(%p, %s)\n", ctx, string);

	if (ctx->shiva_strtab.current_offset + strlen(string) + 1 >= ctx->shiva_strtab.max_size) {
		shiva_pl_debug("reallocating strtab to %u bytes\n", ctx->shiva_strtab.max_size * 2);
		ctx->shiva_strtab.strtab = realloc(ctx->shiva_strtab.strtab, ctx->shiva_strtab.max_size *= 2);
		if (ctx->shiva_strtab.strtab == NULL) {
			perror("realloc");
			return false;
		}
	}
	shiva_pl_debug("string '%s' offset %d\n", string, off);
	strcpy(&ctx->shiva_strtab.strtab[off], string);
	if (soff != NULL)
		*soff = off;
	shiva_pl_debug("strtab ptr: %s\n", &ctx->shiva_strtab.strtab[off]);
	ctx->shiva_strtab.current_offset += strlen(string) + 1;
	return true;
}

#define SHIVA_STRTAB_MAXLEN 4096

static bool
init_shiva_strtab(struct shiva_prelink_ctx *ctx)
{

	memset(&ctx->shiva_strtab, 0, sizeof(ctx->shiva_strtab));
	ctx->shiva_strtab.current_offset = 0;
	ctx->shiva_strtab.max_size = SHIVA_STRTAB_MAXLEN;
	ctx->shiva_strtab.strtab = calloc(ctx->shiva_strtab.max_size, 1);
	if (ctx->shiva_strtab.strtab == NULL) {
		perror("calloc");
		return false;
	}
	/*
	 * Store these initial strings in the string table.
	 */
	set_shiva_strtab_string(ctx, ctx->search_path, NULL);
	set_shiva_strtab_string(ctx, ctx->input_patch, NULL);
	set_shiva_strtab_string(ctx, elf_interpreter_path(&ctx->bin.elfobj), NULL);
	return true;
}

static bool
build_aarch64_jmp(struct shiva_prelink_ctx *ctx, uint64_t pc_vaddr)
{
	struct shiva_branch_site *tmp;
	struct elf_symbol tmp_sym;
	char insn_str[256];
	char *p = strchr(ctx->disas.insn->op_str, '#');
	size_t strtab_offset;

	if (p == NULL) {
		fprintf(stderr,
		    "Unforseen parsing error in build_aarch64_jmp()\n");
		return false;
	}
	tmp = calloc(1, sizeof(*tmp));
	if (tmp == NULL) {
		perror("calloc");
		return false;
	}
	tmp->target_vaddr = strtoul((p + 1), NULL, 16);
	tmp->branch_site = pc_vaddr;
	tmp->branch_type = SHIVA_BRANCH_JMP;
	tmp->insn_string = get_shiva_strtab_offset(ctx); // ??? Is this necessary? We call set_shiva_strtab_string below

	snprintf(insn_str, sizeof(insn_str), "%s %s", ctx->disas.insn->mnemonic,
	    ctx->disas.insn->op_str);
	(void)set_shiva_strtab_string(ctx, insn_str, &tmp->insn_string);

	if (elf_symbol_by_range(&ctx->bin.elfobj, pc_vaddr,
	    &tmp_sym) == true) {
		tmp->branch_flags |= SHIVA_BRANCH_F_SRC_SYMINFO;
		memcpy(&tmp->current_function, &tmp_sym, sizeof(tmp_sym));
		assert(tmp_sym.name != NULL);
		(void)set_shiva_strtab_string(ctx, tmp_sym.name, &tmp->current_function.name);
		shiva_pl_debug("Source function found: %s\n", tmp_sym.name);
	}
	/*
	 * Unconditional branch at a PC-relative offset
	 */
	shiva_pl_debug("Found branch: %#lx:(str_offset: %u)\n", pc_vaddr, tmp->insn_string);
	TAILQ_INSERT_TAIL(&ctx->tailq.branch_tqlist, tmp, _linkage);
	ctx->branch_entry_totlen += sizeof(struct shiva_branch_site) - sizeof(uintptr_t);
	return true;
}

static bool
build_x86_64_jmp(struct shiva_prelink_ctx *ctx, uint64_t pc_vaddr, uint8_t *code_ptr)
{
	struct shiva_branch_site *tmp;
	struct elf_symbol tmp_sym;
	char insn_str[256];
	size_t strtab_offset;

	tmp = calloc(1, sizeof(*tmp));
	if (tmp == NULL) {
		perror("calloc");
		return false;
	}

	tmp->target_vaddr = strtoul(ctx->disas.insn->op_str, NULL, 16);
	tmp->branch_site = pc_vaddr;
	tmp->branch_type = SHIVA_BRANCH_JMP;
	tmp->insn_string = get_shiva_strtab_offset(ctx);
	memcpy(&tmp->o_insn, code_ptr - ctx->disas.insn->size, ctx->disas.insn->size);
	shiva_debug("o_insn[0]: %02x\n", tmp->o_insn);

	snprintf(insn_str, sizeof(insn_str), "%s %s", ctx->disas.insn->mnemonic,
	    ctx->disas.insn->op_str);
	(void)set_shiva_strtab_string(ctx, insn_str, &tmp->insn_string);

	if (elf_symbol_by_range(&ctx->bin.elfobj, pc_vaddr,
	    &tmp_sym) == true) {
		tmp->branch_flags |= SHIVA_BRANCH_F_SRC_SYMINFO;
		memcpy(&tmp->current_function, &tmp_sym, sizeof(tmp_sym));
		assert(tmp_sym.name != NULL);
		(void)set_shiva_strtab_string(ctx, tmp_sym.name, &tmp->current_function.name);
		shiva_pl_debug("Source function found: %s\n", tmp_sym.name);
	}
	/*
	 * Unconditional branch at a PC-relative offset
	 */
	shiva_pl_debug("Found branch: %#lx:(str_offset: %u)\n", pc_vaddr, tmp->insn_string);
	TAILQ_INSERT_TAIL(&ctx->tailq.branch_tqlist, tmp, _linkage);
	ctx->branch_entry_totlen += sizeof(struct shiva_branch_site) - sizeof(uintptr_t);
	return true;
}

static bool
is_a_jumptable(struct shiva_prelink_ctx *ctx, uint64_t vaddr, size_t *out)
{
	struct jumptable_iterator jmptab_iter;
	struct jumptable_entry entry;

	jumptable_iterator_init(ctx, &jmptab_iter);
	while (jumptable_iterator_next(&jmptab_iter, &entry) == SHIVA_PL_ITER_OK) {
		if (vaddr == entry.base) {
			*out = entry.entries;
			return true;
		}
	}
	return false;
}

bool
process_x86_64_xref(struct shiva_prelink_ctx *ctx, size_t c, uint64_t current_vaddr)
{

       cs_x86 *x86 = &ctx->disas.insn->detail->x86;
	struct elf_symbol tmp_sym, deref_symbol;
	struct elf_symbol *src_func = NULL;
	struct elf_symbol symbol;
	uint64_t qword;
	bool found_symbol = false;
	int i;
	bool res, found_insn = false;

	struct shiva_xref_site *xref = calloc(1, sizeof(*xref));
	if (xref == NULL) {
		perror("calloc");
		return false;
	}

	xref->type = SHIVA_XREF_TYPE_UNKNOWN;

	/*
	 * TODO: Figure out why the cs_option for detail
	 * doesn't work. It crashes cs_disasm_iter() due to
	 * not initializing and setting up detail. Therefore
	 * we parse the instructions the less elegant way
	 * by parsing the mnemonic and operator strings.
	 */

	if (strcmp(ctx->disas.insn->mnemonic, "mov") == 0) {

		cs_insn *insn = ctx->disas.insn;
		char *p, *op2, *op1;
		char op_str[160]; /* from capstone.h */

		strncpy(op_str, insn->op_str, sizeof(op_str));
		op_str[sizeof(op_str) - 1] = '\0';

		op1 = op_str;
		op2 = strchr(op_str, ',') + 2;
		/*
		 * NOTE: We start at &op1[1] (Instead of just op1) to move past
		 * the 'q' or the 'd', as this operand could be "qword ptr"
		 * or "dword ptr" in the string we are analyzing.
		 */
		if (strncmp(&op1[1], "word ptr [rip +", 15) == 0) {
			xref->type = SHIVA_XREF_TYPE_IP_RELATIVE_MOV_STR;
			xref->rip_rel_site = current_vaddr;
			p = strchr(op1, '+') + 2;
			*(char *)strchr(p, ']') = '\0';
			xref->rip_rel_disp = strtoul(p, NULL, 16);
			found_insn = true;
			shiva_debug("xref->type: SHIVA_XREF_TYPE_IP_RELATIVE_MOV_STR at site: %#lx\n",
			    xref->rip_rel_site);
			xref->addr_size = (op1[0] == 'q') ? 8 : 4;
		} else if (strncmp(&op1[1], "word ptr [rip -", 15) == 0) {
			xref->type = SHIVA_XREF_TYPE_IP_RELATIVE_MOV_STR;
			xref->rip_rel_site = current_vaddr;
			p = strchr(op1, '-') + 2;
			*(char *)strchr(p, ']') = '\0';
			xref->rip_rel_disp = strtoul(p, NULL, 16);
			xref->rip_rel_disp = -xref->rip_rel_disp;
			found_insn = true;
		       shiva_debug("xref->type: SHIVA_XREF_TYPE_IP_RELATIVE_MOV_STR at site: %#lx\n",
			    xref->rip_rel_site);
			xref->addr_size = (op1[0] == 'q') ? 8 : 4;
		} else if (strncmp(&op2[1], "word ptr [rip +", 15) == 0) {
			xref->type = SHIVA_XREF_TYPE_IP_RELATIVE_MOV_LDR;
			xref->rip_rel_site = current_vaddr;
			p = strchr(op2, '+') + 2;
			*(char *)strchr(p, ']') = '\0';
			xref->rip_rel_disp = strtoul(p, NULL, 16);
			found_insn = true;
			shiva_debug("xref->type: SHIVA_XREF_TYPE_IP_RELATIVE_MOV_LDR at site: %#lx\n",
			    xref->rip_rel_site);
			xref->addr_size = (op2[0] == 'q') ? 8 : 4;
		}  else if (strncmp(&op2[1], "word ptr [rip -", 15) == 0) {
			xref->type = SHIVA_XREF_TYPE_IP_RELATIVE_MOV_LDR;
			xref->rip_rel_site = current_vaddr;
			p = strchr(op2, '-') + 2;
			*(char *)strchr(p, ']') = '\0';
			xref->rip_rel_disp = strtoul(p, NULL, 16);
			xref->rip_rel_disp = -xref->rip_rel_disp;
			found_insn = true;
			shiva_debug("xref->type: SHIVA_XREF_TYPE_IP_RELATIVE_MOV_LDR at site: %#lx\n",
			    xref->rip_rel_site);
			xref->addr_size = (op2[0] == 'q') ? 8 : 4;
		}

	} else if (strcmp(ctx->disas.insn->mnemonic, "movaps") == 0) {
		shiva_debug("movaps instruction found\n");

		cs_insn *insn = ctx->disas.insn;
		char *p, *op2, *op1;
		char op_str[160];

		strncpy(op_str, insn->op_str, sizeof(op_str));
		op_str[sizeof(op_str) - 1] = '\0';

		op1 = op_str;
		op2 = strchr(op_str, ',') + 2;

		if (strncmp(op1, "xmmword ptr [rip +", 18) == 0) {
			xref->type = SHIVA_XREF_TYPE_IP_RELATIVE_MOVAPS_STR;
			xref->rip_rel_site = current_vaddr;
			p = strchr(op1, '+') + 2;
			*(char *)strchr(p, ']') = '\0';
			xref->rip_rel_disp = strtoul(p, NULL, 16);
			found_insn = true;
			shiva_debug("xref->type: SHIVA_XREF_TYPE_IP_RELATIVE_MOVAPS_STR at site: %#lx\n",
			    xref->rip_rel_site);
			xref->addr_size = (op1[0] == 'q') ? 8 : 4;
		} else if (strncmp(op1, "xmmword ptr [rip -", 18) == 0) {
			xref->type = SHIVA_XREF_TYPE_IP_RELATIVE_MOVAPS_STR;
			xref->rip_rel_site = current_vaddr;
			p = strchr(op1, '-') + 2;
			*(char *)strchr(p, ']') = '\0';
			xref->rip_rel_disp = strtoul(p, NULL, 16);
			xref->rip_rel_disp = -xref->rip_rel_disp;
			found_insn = true;
			shiva_debug("xref->type: SHIVA_XREF_TYPE_IP_RELATIVE_MOVAPS_STR at site: %#lx\n",
			    xref->rip_rel_site);
			xref->addr_size = (op1[0] == 'q') ? 8 : 4;
		} else if (strncmp(op2, "xmmword ptr [rip +", 18) == 0) {
			xref->type = SHIVA_XREF_TYPE_IP_RELATIVE_MOVAPS_LDR;
			xref->rip_rel_site = current_vaddr;
			p = strchr(op2, '+') + 2;
			*(char *)strchr(p, ']') = '\0';
			xref->rip_rel_disp = strtoul(p, NULL, 16);
			found_insn = true;
			shiva_debug("xref->type: SHIVA_XREF_TYPE_IP_RELATIVE_MOVAPS_LDR at site: %#lx\n",
			    xref->rip_rel_site);
			xref->addr_size = (op2[0] == 'q') ? 8 : 4;
		} else if (strncmp(op2, "xmmword ptr [rip -", 18) == 0) {
			xref->type = SHIVA_XREF_TYPE_IP_RELATIVE_MOVAPS_LDR;
			xref->rip_rel_site = current_vaddr;
			p = strchr(op2, '-') + 2;
			*(char *)strchr(p, ']') = '\0';
			xref->rip_rel_disp = strtoul(p, NULL, 16);
			xref->rip_rel_disp = -xref->rip_rel_disp;
			found_insn = true;
			shiva_debug("xref->type: SHIVA_XREF_TYPE_IP_RELATIVE_MOVAPS_LDR at site: %#lx\n",
			    xref->rip_rel_site);
			xref->addr_size = (op2[0] == 'q') ? 8 : 4;
		} else {
			shiva_debug("Unknown movaps\n");
		}
	} else if (strcmp(ctx->disas.insn->mnemonic, "lea") == 0) {
		cs_insn *insn = ctx->disas.insn;
		char *p, *op2;
		char op_str[160]; /* from capstone.h */

		strncpy(op_str, insn->op_str, sizeof(op_str));
		op_str[sizeof(op_str) - 1] = '\0';
		op2 = strchr(op_str, ',') + 2;
		if (strncmp(op2, "[rip +", 6) == 0) {
			xref->type = SHIVA_XREF_TYPE_IP_RELATIVE_LEA;
			xref->rip_rel_site = current_vaddr;
			p = strchr(op2, '+') + 2;
			*(char *)strchr(p, ']') = '\0';
			xref->rip_rel_disp = strtoul(p, NULL, 16);
			xref->addr_size = 8;
			found_insn = true;
			shiva_debug("xref->type: SHIVA_XREF_TYPE_IP_RELATIVE_LEA\n");
		} else if (strncmp(op2, "[rip -", 6) == 0) {
			xref->type = SHIVA_XREF_TYPE_IP_RELATIVE_LEA;
			xref->rip_rel_site = current_vaddr;
			p = strchr(op2, '-') + 2;
			*(char *)strchr(p, ']') = '\0';
			xref->rip_rel_disp = strtoul(p, NULL, 16);
			/*
			 * Since this was a [rip - <offset>] we are making
			 * the offset negative here:
			 */
			xref->rip_rel_disp = -xref->rip_rel_disp; // ~(xref->r ip_rel_disp + 1);
			xref->addr_size = 8;
			found_insn = true;
			shiva_debug("xref->type: SHIVA_XREF_TYPE_IP_RELATIVE_LEA\n");
		}
		/*
		 * Is this LEA instruction accessing a jump table?
		 */
		xref->target_vaddr = xref->rip_rel_site + xref->rip_rel_disp + ctx->disas.insn->size;
		if (is_a_jumptable(ctx, xref->target_vaddr, &xref->jumptable_count)
		    == true) {
			shiva_debug("xref to target %#lx is a jumptable reference\n", xref->target_vaddr);
			xref->flags |= SHIVA_XREF_F_TO_JUMPTABLE;
		}
	}
	if (found_insn == false)
		return true;
	xref->target_vaddr = xref->rip_rel_site + xref->rip_rel_disp + ctx->disas.insn->size;
	shiva_debug("Searching for symbol associated with address: %#lx\n", xref->target_vaddr);

	xref->insn_len = ctx->disas.insn->size;
	shiva_debug("Instruction len: %zu\n", xref->insn_len);
	/*
	 * Here we copy the x86_64 instruction byte sequence
	 * into xref->rip_rel_o_insn[16]
	 */
	for (i = 0; i < xref->insn_len; i++) {
		uint64_t b;

		if (elf_read_address(&ctx->bin.elfobj, xref->rip_rel_site + i,
		    &b, ELF_BYTE) == false) {
			fprintf(stderr, "elf_read_address() failed reading addr %#lx\n",
			    xref->rip_rel_site);
			return false;
		}
		xref->rip_rel_o_insn[i] = (uint8_t)b;
	}
	memset(&symbol, 0, sizeof(symbol));

	/*
	 * Search, find, build symbolic information for XREF
	 */
	if (elf_symbol_by_value_lookup(&ctx->bin.elfobj, xref->target_vaddr,
	    &symbol) == true) {
		shiva_debug("Target xref symbol '%s'\n", symbol.name);
		found_symbol = true;
	}
	if (found_symbol == false) {
		struct elf_section shdr;

		res = elf_section_by_address(&ctx->bin.elfobj, xref->target_vaddr, &shdr);
		if (res == false) {
			fprintf(stderr, "Unable to find section associated with addr: %#lx\n",
			    xref->target_vaddr);
			return false;
		}
		symbol.name = shiva_xfmtstrdup("%s+%lx", shdr.name,
		    xref->target_vaddr - shdr.address);
		symbol.value = xref->target_vaddr;
		symbol.size = sizeof(uint64_t);
		symbol.bind = STB_GLOBAL;
		symbol.type = STT_OBJECT;
		symbol.visibility = STV_PROTECTED;
		if (elf_section_index_by_name(&ctx->bin.elfobj, shdr.name, (uint64_t *)&symbol.shndx)
		    == false) {
			fprintf(stderr, "Failed to find section index for %s in %s\n",
			    shdr.name, elf_pathname(&ctx->bin.elfobj));
			return true;
		}
		shiva_debug("Created custom symbol name: %s\n", symbol.name);
	}
	memcpy(&xref->symbol, &symbol, sizeof(symbol));
	/*
	 * Make sure xref->symbol.name is set to the correct
	 * string offset.
	 */
	shiva_debug("SETTING XREF SYMBOL NAME: %s (xref site: %#lx)\n", xref->symbol.name, xref->rip_rel_site);
	if (set_shiva_strtab_string(ctx, symbol.name, &xref->symbol.name) == false) {
		fprintf(stderr, "Failed to insert '%s' into string table\n",
		    symbol.name);
		return false;
	}

	struct elf_relocation rel;
	elf_relocation_iterator_t rel_iter;

	elf_relocation_iterator_init(&ctx->bin.elfobj, &rel_iter);
	while (elf_relocation_iterator_next(&rel_iter, &rel) == ELF_ITER_OK) {
		if (strcmp(rel.shdrname, ".rela.dyn") != 0)
			continue;
		if (rel.offset != xref->target_vaddr)
			continue;
		switch (rel.type) {
		case R_X86_64_RELATIVE:
			if (elf_read_address(&ctx->bin.elfobj, xref->target_vaddr, &qword,
			    ELF_QWORD) == false) {
				fprintf(stderr, "elf_read_address() failed to read %#lx\n", xref->target_vaddr);
				return false;
			}
			/*
			 * If It's a relative relocation, then it's r_offset will be in the
			 * data section, and never in the .bss. We can safely dereference
			 * target_vaddr to see if an offset lives there that points to another
			 * symbol.
			 */
			res = elf_symbol_by_value_lookup(&ctx->bin.elfobj, qword, &deref_symbol);
			if (res == true) {
				xref->flags |= SHIVA_XREF_F_INDIRECT;
				xref->reloc_type = R_X86_64_RELATIVE;
				xref->got = (uint64_t *)xref->target_vaddr;
				shiva_debug("XREF (Indirect via GOT): Site: %#lx Target: %s (Deref)-> %s(%#lx)\n",
				    xref->rip_rel_site, symbol.name ? symbol.name : "<unknown>",
				    deref_symbol.name, deref_symbol.value);
				memcpy(&xref->deref_symbol, &deref_symbol, sizeof(struct elf_symbol));
				if (set_shiva_strtab_string(ctx, deref_symbol.name,
				    &xref->deref_symbol.name) == false) {
					fprintf(stderr, "Failed to insert '%s' into string table\n",
					    deref_symbol.name);
					return false;
				}
			}
			break;
		case R_X86_64_COPY:
			if (elf_symbol_by_name(&ctx->bin.elfobj, rel.symname, &deref_symbol) == true) {
				xref->flags |= SHIVA_XREF_F_INDIRECT;
				xref->reloc_type = R_X86_64_COPY;
				xref->got = (uint64_t *)xref->target_vaddr;
				shiva_debug("XREF (Indirect via GOT): Site: %#lx Target: %s (Deref)-> %s(%#lx)\n",
				    xref->rip_rel_site, symbol.name ? symbol.name : "<unknown>",
				    deref_symbol.name, deref_symbol.value);
				memcpy(&xref->deref_symbol, &deref_symbol, sizeof(struct elf_symbol));
				if (set_shiva_strtab_string(ctx, deref_symbol.name,
				    &xref->deref_symbol.name) == false) {
					fprintf(stderr, "Failed to insert '%s' into string table\n",
					    deref_symbol.name);
					return false;
				}

			}
			break;
		case R_X86_64_GLOB_DAT:
			if (elf_symbol_by_name(&ctx->bin.elfobj, rel.symname, &deref_symbol) == true) {
				xref->flags |= SHIVA_XREF_F_INDIRECT;
				xref->reloc_type = R_X86_64_GLOB_DAT;
				xref->got = (uint64_t *)xref->target_vaddr;
				shiva_debug("XREF (Indirect via GOT): Site: %#lx Target: %s (Deref)-> %s(%#lx)\n",
				    xref->rip_rel_site, symbol.name ? symbol.name : "<unknown>",
				    deref_symbol.name, deref_symbol.value);
				memcpy(&xref->deref_symbol, &deref_symbol, sizeof(struct elf_symbol));
				if (set_shiva_strtab_string(ctx, deref_symbol.name,
				    &xref->deref_symbol.name) == false) {
					fprintf(stderr, "Failed to insert '%s' into string table\n",
					    deref_symbol.name);
					return false;
				}

			}
			break;
		default:
			break;
		}
	}

	if (elf_symbol_by_range(&ctx->bin.elfobj,
	    current_vaddr, &tmp_sym) == true) {
		xref->flags |= SHIVA_XREF_F_SRC_SYMINFO;
		memcpy(&xref->current_function, &tmp_sym, sizeof(tmp_sym));
		shiva_debug("SETTING XREF SRC SYMBOL INFO: %s\n", tmp_sym.name);
		if (set_shiva_strtab_string(ctx, tmp_sym.name,
		    &xref->current_function.name) == false) {
			fprintf(stderr, "failed to insert '%s' into string table\n", tmp_sym.name);
			return false;
		}
		shiva_debug("current function '%s' set name offset: %zu\n", tmp_sym.name, xref->current_function.name);
		shiva_debug("Source symbol included: %s\n", tmp_sym.name);
	} else {
		xref->flags |= SHIVA_XREF_F_SRC_SYMINFO;
		memcpy(&xref->current_function, &tmp_sym, sizeof(tmp_sym));
		shiva_debug("SETTING XREF SRC SYMBOL INFO: fn_%#lx\n", current_vaddr);
		char *tmp_name = shiva_xfmtstrdup("fn_%#lx\n", current_vaddr);
		if (set_shiva_strtab_string(ctx, tmp_name,
		    &xref->current_function.name) == false) {
			fprintf(stderr, "failed to insert '%s' into string table\n", tmp_sym.name);
			return false;
		}
		shiva_debug("current function '%s' set name offset: %zu\n", tmp_name, xref->current_function.name);
	}
	/*
	 * Insert xref entry
	 */
	shiva_debug("Inserting xref type: %d\n", xref->type);
	shiva_debug("Site: %#lx\n", xref->rip_rel_site);
	shiva_debug("Target: %s\n", symbol.name);

	/*
	 * We store the entire struct except for the pointer at the end
	 * which is a list ptr and we don't need on disk. Let's make sure
	 * we update the total length to make future room for the .shiva.xref section
	 */
	ctx->xref_entry_totlen += sizeof(struct shiva_xref_site) - sizeof(uintptr_t);

	/*
	 * Add the entry to our local list so we can write it out later to disk.
	 */
	TAILQ_INSERT_TAIL(&ctx->tailq.xref_tqlist, xref, _linkage);
	return true;

}

bool
analyze_binary(struct shiva_prelink_ctx *ctx)
{
	struct elf_section section;
	struct elf_symbol symbol;
	const uint8_t *ptr;
	uint64_t call_site, call_addr, retaddr;
	uint64_t current_address = ctx->disas.base;
	int64_t call_offset;
	size_t insn_counter = 0;

	if (elf_section_by_name(&ctx->bin.elfobj, ".text", &section) == false) {
		fprintf(stderr, "elf_section_by_name() failed\n");
		return false;
	}

	struct shiva_branch_site *tmp;
	int xref_type;
	size_t c, i, j;
	size_t code_len = section.size - 1; /* XXX what's up with the -1 ? check this */
	uint64_t code_vaddr = section.address; /* Points to .text */
	uint8_t *code_ptr = ctx->disas.textptr;
	uint8_t *tmp_ptr = code_ptr;
	elf_symtab_iterator_t symtab_iter;
	cs_detail insnack_detail = {{0}};
	cs_insn insnack = {0};
	ctx->disas.insn = &insnack;

#ifdef __aarch64__
	if (cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN,
	    &ctx->disas.handle) != CS_ERR_OK) {
		fprintf(stderr, "cs_open failed\n");
		return false;
	}

	/*
	 * AARCH64
	 * FIND ALL BRANCHES/CALLS
	 */
	shiva_pl_debug("disassembling text(%#lx), %zu bytes\n", section.address, section.size);
	for (c = 0 ;; c += ARM_INSN_LEN) {
		bool res;
		double progress;
		size_t insn_max_count = (code_len / ARM_INSN_LEN);

		insn_counter++;
		progress = insn_counter * 100.0 / insn_max_count;
		if ((int)progress % 10 == 0) {
			fprintf(stdout, ".");
			fflush(stdout);
		}
		shiva_pl_debug("Address: %#lx\n", section.address + c);
		shiva_pl_debug("(uint32_t)textptr: %#x\n", *(uint32_t *)code_ptr);
		if (c >= section.size)
			break;
		shiva_pl_debug("code_ptr: %p\n", code_ptr);
		res = cs_disasm_iter(ctx->disas.handle, (void *)&code_ptr, &code_len,
		    &code_vaddr, ctx->disas.insn);
		if (res == false) {
			shiva_pl_debug("code_ptr after fail: %p\n", code_ptr);
			shiva_pl_debug("code_vaddr after fail: %lx\n", code_vaddr);
			code_vaddr += ARM_INSN_LEN;
			code_ptr += ARM_INSN_LEN;
			continue;
		}
		shiva_pl_debug("0x%"PRIx64":\t%s\t\t%s\n", ctx->disas.insn->address,
		    ctx->disas.insn->mnemonic, ctx->disas.insn->op_str);
		if (strcmp(ctx->disas.insn->mnemonic, "b") == 0) {
			if (build_aarch64_jmp(ctx, section.address + c)
			    == false) {
				fprintf(stderr, "build_aarch64_jmp(%p, %#lx) failed\n",
				    ctx, section.address + c);
				return false;
			}
		}
		if (strncmp(ctx->disas.insn->mnemonic, "b.", 2) == 0) {
			/*
			 * Branch instructions:
			 * b.eq, b.ne, b.gt, b.ge, b.lt, b.le, b.ls, b.hi,
			 * b.cc, b.cs, b.cond
			 */
			if (build_aarch64_jmp(ctx, section.address + c)
			    == false) {
				fprintf(stderr, "build_aarch64_jmp(%p, %#lx) failed\n",
				    ctx, section.address + c);
				return false;
			}
		} else if (strncmp(ctx->disas.insn->mnemonic, "cb", 2) == 0) {
			/*
			 * Compare and branch
			 * cbnz, cbz
			 */
			if (build_aarch64_jmp(ctx, section.address + c)
			    == false) {
				fprintf(stderr, "build_aarch64_jmp(%p, %#lx) failed\n",
				    ctx, section.address + c);
				return false;
			}

		} else if (strncmp(ctx->disas.insn->mnemonic, "tb", 2) == 0) {
			/*
			 * Test bit and branch
			 * tbz, tbnz
			 */
			if (build_aarch64_jmp(ctx, section.address + c)
			    == false) {
				fprintf(stderr, "build_aarch64_jmp(%p, %#lx) failed\n",
				    ctx, section.address + c);
				return false;
			}

		} else if (strcmp(ctx->disas.insn->mnemonic, "bl") == 0) {
			struct shiva_branch_site *tmp;
			uint64_t addr;
			struct elf_symbol tmp_sym;
			char *p = strchr(ctx->disas.insn->op_str, '#');

			if (p == NULL) {
				continue;
				fprintf(stderr, "unexpected error parsing: '%s %s'\n",
				    ctx->disas.insn->mnemonic, ctx->disas.insn->op_str);
				return false;
			}
			call_site = section.address + c;
			call_addr = strtoul((p + 1), NULL, 16);
			retaddr = call_site + ARM_INSN_LEN;
			memset(&symbol, 0, sizeof(symbol));
			tmp = calloc(1, sizeof(*tmp));
			if (tmp == NULL) {
				perror("calloc");
				return false;
			}

			if (elf_symbol_by_value_lookup(&ctx->bin.elfobj, call_addr,
			    &symbol) == false) {
				struct elf_plt plt_entry;
				elf_plt_iterator_t plt_iter;

				symbol.name = NULL;

				elf_plt_iterator_init(&ctx->bin.elfobj, &plt_iter);
				while (elf_plt_iterator_next(&plt_iter, &plt_entry) == ELF_ITER_OK) {
					if (plt_entry.addr == call_addr) {
						symbol.name = shiva_xfmtstrdup("%s@plt", plt_entry.symname);
						symbol.type = STT_FUNC;
						symbol.bind = STB_GLOBAL;
						symbol.size = 0;
						tmp->branch_flags |= SHIVA_BRANCH_F_PLTCALL;
					}
				}
				if (symbol.name == NULL) {
					symbol.name = shiva_xfmtstrdup("fn_%#lx", call_addr);
					if (symbol.name == NULL) {
						perror("strdup");
						return false;
					}
					symbol.value = call_addr;
					symbol.type = STT_FUNC;
					symbol.size = symbol.size;
					symbol.bind = STB_GLOBAL;
				}
			}
			tmp->retaddr = retaddr;
			tmp->target_vaddr = call_addr;
			memcpy(&tmp->o_insn, tmp_ptr + c, ARM_INSN_LEN);
			memcpy(&tmp->symbol, &symbol, sizeof(symbol));
			assert(symbol.name != NULL);
			(void ) set_shiva_strtab_string(ctx, symbol.name, &tmp->symbol.name);
			tmp->branch_type = SHIVA_BRANCH_CALL;
			tmp->branch_site = call_site;
			tmp->branch_flags |= SHIVA_BRANCH_F_DST_SYMINFO;
			tmp->insn_string = get_shiva_strtab_offset(ctx);

			char *tmp_str = shiva_xfmtstrdup("%s %s", ctx->disas.insn->mnemonic,
			    ctx->disas.insn->op_str);

			/*
			 * Add the string to the .shiva.strtab string table.
			 */
			(void) set_shiva_strtab_string(ctx, tmp_str, &tmp->insn_string);
			if (elf_symbol_by_range(&ctx->bin.elfobj, code_vaddr - 4,
			    &tmp_sym) == true) {
				tmp->branch_flags |= SHIVA_BRANCH_F_SRC_SYMINFO;
				tmp->current_function.value = tmp_sym.value;
				tmp->current_function.shndx = tmp_sym.shndx;
				tmp->current_function.bind = tmp_sym.bind;
				tmp->current_function.type = tmp_sym.type;
				tmp->current_function.visibility = tmp_sym.visibility;
				tmp->current_function.__pad2 = 0;
				if (set_shiva_strtab_string(ctx, (char *)tmp_sym.name,
				    &tmp->current_function.name) == false) {
					fprintf(stderr, "Failed to insert string into .shiva.strtab\n");
					exit(EXIT_FAILURE);
				}
				shiva_pl_debug("Source symbol included: %s\n", tmp_sym.name);
			}
			shiva_pl_debug("Inserting branch for symbol %s callsite: %#lx\n", tmp_sym.name, tmp->branch_site);
			TAILQ_INSERT_TAIL(&ctx->tailq.branch_tqlist, tmp, _linkage);
			ctx->branch_entry_totlen += sizeof(struct shiva_branch_site) - sizeof(uintptr_t);
			shiva_pl_debug("Done inserting it\n");
		/*
		 * AARCH64
		 * FIND ALL INSTANCES OF XREF's (LOAD/STORE)
		 */
		} else if (strcmp(ctx->disas.insn->mnemonic, "adrp") == 0) {
			uint64_t adrp_imm, adrp_site;
			uint32_t adrp_o_bytes = *(uint32_t *)ctx->disas.insn->bytes;
			uint32_t next_o_bytes;

			/*
			 * We're looking for several combinations that could be
			 * used to reference/access global data.
			 * scenario: 1
			 * adrp x0, #0x1000 (data segment)
			 * ldr x0, [x0, #0x16 (variable offset)]
			 * 
			 * adrp x0, #0x1000
			 * add x0, x0, #0x16
			 */
			struct shiva_xref_site *xref;
			struct elf_symbol symbol;
			uint64_t xref_site, xref_addr, target_page;
			char *p = strchr(ctx->disas.insn->op_str, '#');

			if (p == NULL) {
				continue;
				fprintf(stderr, "unexpected error parsing: '%s %s'\n",
				    ctx->disas.insn->mnemonic, ctx->disas.insn->op_str);
				return false;
			}
			adrp_site = section.address + c;
			adrp_imm = strtoul((p + 1), NULL, 16);
			target_page = (adrp_site & ~0xfff) + adrp_imm;
			res = cs_disasm_iter(ctx->disas.handle, (void *)&code_ptr, &code_len,
			    &code_vaddr, ctx->disas.insn);
			if (res == false) {
				fprintf(stderr, "cs_disasm_iter() failed\n");
				return false;
			}
			next_o_bytes = *(uint32_t *)ctx->disas.insn->bytes;
			c += ARM_INSN_LEN;
			xref = calloc(1, sizeof(*xref));
			if (xref == NULL) {
				perror("calloc");
				return false;
			}
			/*
			 * Is the next instruction and ldr?
			 */
			if (strcmp(ctx->disas.insn->mnemonic, "ldr") == 0) {
				xref_type = SHIVA_XREF_TYPE_ADRP_LDR;
			} else if (strcmp(ctx->disas.insn->mnemonic, "str") == 0) {
				xref_type = SHIVA_XREF_TYPE_ADRP_STR;
			} else if (strcmp(ctx->disas.insn->mnemonic, "add") == 0) {
				xref_type = SHIVA_XREF_TYPE_ADRP_ADD;
			} else {
				xref_type = SHIVA_XREF_TYPE_UNKNOWN;
			}

			if (xref_type == SHIVA_XREF_TYPE_UNKNOWN) {
				/*
				 * We don't know this combination of instructions for
				 * forming an XREF.
				 */
				continue;
			}
			uint32_t tmp_imm;
			uint64_t qword;
			uint64_t xref_flags = 0;
			bool found_symbol = false;

			p = strchr(ctx->disas.insn->op_str, '#');
			if (p == NULL) {
				continue;
				fprintf(stderr, "unexpected error parsing: '%s %s'\n",
				    ctx->disas.insn->mnemonic, ctx->disas.insn->op_str);
				return false;
			}
			tmp_imm = strtoul((p + 1), NULL, 16);
			shiva_pl_debug("Looking up symbol at address %#lx in"
			    " the target executable\n", target_page + tmp_imm);
			/*
			 * Look up the symbol that this xref points to.
			 */
			if (elf_symbol_by_value_lookup(&ctx->bin.elfobj, target_page + tmp_imm,
			    &symbol) == true) {
				shiva_pl_debug("Target xref symbol '%s'\n", symbol.name);
				found_symbol = true;
			}
			/*
			 * Does target_page + tmp_imm lead to storage of the address
			 * we are looking for? Or does it calculate directly to the
			 * address? First let's try to read 8 bytes from the address
			 * and see if there's an indirect absolute value we are looking
			 * for: (i.e. a .got[entry] pointing to a .bss variable.
			 */
			shiva_pl_debug("Reading from address %#lx\n", target_page + tmp_imm);
			if (elf_read_address(&ctx->bin.elfobj, target_page + tmp_imm,
			    &qword, ELF_QWORD) == false) {
				shiva_pl_debug("Failed to read address %#lx\n", target_page + tmp_imm);
				continue;
			}
			/*
			 * Create a symbol to represent the location represented by adrp.
			 * We have not found one, so we create one because it will be used
			 * to install external re-linking patches for adrp sequences.
			 */
			if (found_symbol == false) {
				struct elf_section shdr;

				res = elf_section_by_address(&ctx->bin.elfobj, target_page + tmp_imm,
				    &shdr);
				if (res == false) {
					fprintf(stderr, "Unable to find section associated with addr: %#lx\n",
					    target_page + tmp_imm);
					return false;
				}
				shiva_pl_debug("%#lx - section.address:%#lx = %#lx\n", target_page + tmp_imm, shdr.address,
				    target_page + tmp_imm - shdr.address);
				symbol.name = shiva_xfmtstrdup("%s+%lx", shdr.name,
				    target_page + tmp_imm - shdr.address);
				symbol.value = target_page + tmp_imm;
				symbol.size = sizeof(uint64_t);
				symbol.bind = STB_GLOBAL;
				symbol.type = STT_OBJECT;
				symbol.visibility = STV_PROTECTED;
				if (elf_section_index_by_name(&ctx->bin.elfobj, shdr.name, (uint64_t *)&symbol.shndx)
				    == false) {
					fprintf(stderr, "Failed to find section index for %s in %s\n",
					    shdr.name, elf_pathname(&ctx->bin.elfobj));
					return true;
				}
			}
			/*
			 * We must get the name of the function that the
			 * xref code is within. This is necessary later on
			 * if transformations happen.
			 */
			struct elf_symbol tmp_sym, deref_symbol;
			struct elf_symbol *src_func = NULL;

			if (elf_symbol_by_range(&ctx->bin.elfobj, code_vaddr - 4,
			    &tmp_sym) == true) {
				xref_flags |= SHIVA_XREF_F_SRC_SYMINFO;
				src_func = shiva_malloc(sizeof(*src_func));
				memcpy(src_func, &tmp_sym, sizeof(*src_func));
				shiva_pl_debug("Source symbol included: %s\n", tmp_sym.name);
			}
			shiva_pl_debug("Looking up value %#lx found at %#lx\n", qword, target_page + tmp_imm);
			res = elf_symbol_by_value_lookup(&ctx->bin.elfobj,
			    qword, &deref_symbol);
			if (res == true) {
				xref_flags |= SHIVA_XREF_F_INDIRECT;
				shiva_pl_debug("XREF (Indirect via GOT) (Type: %d): Site: %#lx target: %s (Deref)-> %s(%#lx)\n",
				    xref_type, adrp_site, symbol.name ? symbol.name : "<unknown>",
				    deref_symbol.name, deref_symbol.value);
			}
			res = gen_aarch64_xref(ctx, &symbol, &deref_symbol, src_func, xref_type, xref_flags, adrp_site,
			    adrp_imm, tmp_imm, adrp_o_bytes, next_o_bytes);
			if (res == false ) {
				fprintf(stderr, "shiva_analyze_install_xref failed\n");
				return false;
			}
			continue;
		}
	}
#endif

#ifdef __x86_64__
	struct elf_symbol tmp_sym, deref_symbol;
	struct elf_symbol *src_func = NULL;
	uint64_t qword;
	bool found_symbol = false;
	bool res, found_insn = false;
	struct shiva_xref_site *xref;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &ctx->disas.handle) != CS_ERR_OK) {
		fprintf(stderr, "cs_open failed\n");
		return false;
	}
	size_t insn_count;
	cs_insn *insn;
	insn_count = cs_disasm(ctx->disas.handle, ctx->disas.textptr,
	    code_len, code_vaddr, 0, &insn);
	if (insn_count == 0) {
		fprintf(stderr, "cs_disasm failed\n");
		return false;
	}
	/*
	 * X86_64
	 * FIND ALL INSTANCES OF BRANCHES/CALLS
	 */
	for (c = 0 ;; c += ctx->disas.insn->size) {
		bool res;
		double progress;
		size_t insn_max_count = insn_count;
		uint64_t current_vaddr = ctx->disas.base + c;

		insn_counter++;
		progress = insn_counter * 100.0 / insn_max_count;
		if ((int)progress % 10 == 0) {
			fprintf(stdout, ".");
			fflush(stdout);
		}

		shiva_pl_debug("insn->size: %d c: %d\n", c, c);
		shiva_pl_debug("Address: %#lx\n", section.address + c);
		shiva_pl_debug("(uint32_t)textptr: %#x\n", *(uint32_t *)code_ptr);
		if (c >= section.size)
			break;
		shiva_pl_debug("code_ptr: %p\n", code_ptr);
		res = cs_disasm_iter(ctx->disas.handle, (void *)&code_ptr, &code_len,
		    &code_vaddr, ctx->disas.insn);
		if (res == false) {
			shiva_pl_debug("code_ptr after fail: %p\n", code_ptr);
			shiva_pl_debug("code_vaddr after fail: %lx\n", code_vaddr);
			code_vaddr += ctx->disas.insn->size;
			code_ptr += ctx->disas.insn->size;
			continue;
		}
		shiva_pl_debug("0x%"PRIx64":\t%s\t\t%s\n", ctx->disas.insn->address,
		    ctx->disas.insn->mnemonic, ctx->disas.insn->op_str);

		/*
		 * Analyze branch instructions
		 */
		if (strncmp(ctx->disas.insn->mnemonic, "j", 1) == 0) {
			if (build_x86_64_jmp(ctx, section.address + c, code_ptr)
			    == false) {
				fprintf(stderr, "analyze_branches failed\n");
				return false;
			}
		} else if (strcmp(ctx->disas.insn->mnemonic, "jmp") == 0) {
			if (build_x86_64_jmp(ctx, section.address + c, code_ptr) == false) {
				fprintf(stderr, "analyze_branches failed\n");
				return false;
			}
		}
		if (strcmp(ctx->disas.insn->mnemonic, "call") == 0) {
			struct shiva_branch_site *tmp;
			uint64_t addr, call_addr, call_site, retaddr;
			struct elf_symbol tmp_sym, symbol;
			shiva_debug("op_str: %s\n", ctx->disas.insn->op_str);

			call_site = section.address + c;
			call_addr = strtoul(ctx->disas.insn->op_str, NULL, 16);
			retaddr = call_site + ctx->disas.insn->size;
			memset(&symbol, 0, sizeof(symbol));
			tmp = calloc(1, sizeof(*tmp));
			if (tmp == NULL) {
				perror("calloc");
				return false;
			}

			if (elf_symbol_by_value_lookup(&ctx->bin.elfobj, call_addr,
			    &symbol) == false) {
				struct elf_plt plt_entry;
				elf_plt_iterator_t plt_iter;

				symbol.name = NULL;

				elf_plt_iterator_init(&ctx->bin.elfobj, &plt_iter);
				while (elf_plt_iterator_next(&plt_iter, &plt_entry) == ELF_ITER_OK) {
					if (plt_entry.addr == call_addr) {
						symbol.name = shiva_xfmtstrdup("%s@plt", plt_entry.symname);
						symbol.type = STT_FUNC;
						symbol.bind = STB_GLOBAL;
						symbol.size = 16;
						symbol.value = call_addr; /* PLTCALL types get their symbol value set to addr of PLT entry */
						tmp->branch_flags |= SHIVA_BRANCH_F_PLTCALL;
					}
				}
				if (symbol.name == NULL) {
					symbol.name = shiva_xfmtstrdup("fn_%#lx", call_addr);
					if (symbol.name == NULL) {
						perror("strdup");
						return false;
					}
					symbol.value = call_addr;
					symbol.type = STT_FUNC;
					symbol.size = symbol.size;
					symbol.bind = STB_GLOBAL;
				}
			}
			tmp->retaddr = retaddr;
			tmp->target_vaddr = call_addr;
			shiva_debug("CODE_PTR(%p): %lx at insn-offset %lx\n",
			    code_ptr, *(uint32_t *)(code_ptr - ctx->disas.insn->size), c);
			memcpy(&tmp->o_insn, code_ptr - ctx->disas.insn->size, ctx->disas.insn->size);
			shiva_debug("o_insn[0]: %02x\n", tmp->o_insn);
			memcpy(&tmp->symbol, &symbol, sizeof(symbol));
			(void) set_shiva_strtab_string(ctx, symbol.name, &tmp->symbol.name);
			assert(symbol.name != NULL);
			tmp->branch_type = SHIVA_BRANCH_CALL;
			tmp->branch_site = call_site;
			tmp->branch_flags |= SHIVA_BRANCH_F_DST_SYMINFO;
			tmp->insn_string = get_shiva_strtab_offset(ctx);
			char *tmp_str = shiva_xfmtstrdup("%s %s", ctx->disas.insn->mnemonic,
			    ctx->disas.insn->op_str);
			/*
			 * Add the string to the .shiva.strtab string table
			 */
			(void) set_shiva_strtab_string(ctx, tmp_str, &tmp->insn_string);
			if (elf_symbol_by_range(&ctx->bin.elfobj, code_vaddr - 4,
			    &tmp_sym) == true) {
				tmp->branch_flags |= SHIVA_BRANCH_F_SRC_SYMINFO;
				tmp->current_function.value = tmp_sym.value;
				tmp->current_function.shndx = tmp_sym.shndx;
				tmp->current_function.bind = tmp_sym.bind;
				tmp->current_function.type = tmp_sym.type;
				tmp->current_function.visibility = tmp_sym.visibility;
				tmp->current_function.__pad2 = 0;
				 if (set_shiva_strtab_string(ctx, (char *)tmp_sym.name,
				     &tmp->current_function.name) == false) {
					fprintf(stderr, "Failed to insert string into .shiva.strtab\n");
					exit(EXIT_FAILURE);
				}
				shiva_debug("Source symbol included: %s\n", tmp_sym.name);
			}
			shiva_debug("Inserting branch for symbol %s callsite: %#lx\n", symbol.name, tmp->branch_site);
			shiva_debug("The symbol string offset is %#lx\n", tmp->symbol.name);
			TAILQ_INSERT_TAIL(&ctx->tailq.branch_tqlist, tmp, _linkage);
			ctx->branch_entry_totlen += sizeof(struct shiva_branch_site) - sizeof(uintptr_t);
		} else {
			if (process_x86_64_xref(ctx, c, current_vaddr) == false)
				return false;
		}
	}

#endif
	return true;
}

int main(int argc, char **argv)
{
	int opt = 0, long_index = 0;
	struct shiva_prelink_ctx ctx;
	elf_error_t error;

	static struct option long_options[] = {
		{"input_exec", required_argument, 0, 'e'},
		{"input_patch", required_argument, 0, 'p'},
		{"output_exec", required_argument, 0, 'o'},
		{"search_path", required_argument, 0, 's'},
		{"interp_path", required_argument, 0, 'i'},
		{"disable-cflow", no_argument,	   0, 'd'},
		{"cfs-binary"	, no_argument,	   0, 'c'},
		{"needed-injection", no_argument,  0, 'N'},
		{0,	0,	0,	0}
	};

	if (argc < 3) {
usage:
		printf("Usage: %s -e test_bin -p patch1.o -i /lib/shiva"
		    " -s /opt/shiva/modules/ -o test_bin_final [-cdN]\n", argv[0]);
		printf("[-e] --input_exec	Input ELF executable\n");
		printf("[-p] --input_patch	Input ELF patch (NOTE: should be a .so patch when the -N flag is used)\n");
		printf("[-i] --interp_path	Interpreter search path, i.e. \"/lib/shiva\"\n");
		printf("[-s] --search_path	Module search path (For patch object)\n");
		printf("[-o] --output_exec	Output executable\n");
		printf("[-d] --disable-cflow	Do not generate CFG data (i.e. .shiva.xref and .shiva.branch)\n");
		printf("[-c] --cfs-binary	Necessary when prelinking cFS (NASA's core flight software)\n");
		printf("[-N] --needed-injection	Injects shared object dependency via DT_NEEDED entry\n");
		exit(0);
	}

	memset(&ctx, 0, sizeof(ctx));

	while ((opt = getopt_long(argc, argv, "Ne:p:i:s:o:dc",
	    long_options, &long_index)) != -1) {
		switch(opt) {
		case 'e':
			ctx.input_exec = strdup(optarg);
			if (ctx.input_exec == NULL) {
				perror("strdup");
				exit(EXIT_FAILURE);
			}
			if (access(ctx.input_exec, F_OK) != 0) {
				perror("access");
				exit(EXIT_FAILURE);
			}
			break;
		case 'p':
			ctx.input_patch = strdup(optarg);
			if (ctx.input_patch == NULL) {
				perror("strdup");
				exit(EXIT_FAILURE);
			}
			break;
		case 'i':
			ctx.interp_path = strdup(optarg);
			if (ctx.interp_path == NULL) {
				perror("strdup");
				exit(EXIT_FAILURE);
			}
			break;
		case 's':
			ctx.search_path = strdup(optarg);
			if (ctx.search_path == NULL) {
				perror("strdup");
				exit(EXIT_FAILURE);
			}
			break;
		case 'o':
			ctx.output_exec = strdup(optarg);
			if (ctx.output_exec == NULL) {
				perror("strdup");
				exit(EXIT_FAILURE);
			}
			break;
		case 'N':
			printf("Injecting DT_NEEDED entry\n");
			ctx.flags |= SHIVA_LD_F_NEEDED_INJECTION;
			ctx.flags |= SHIVA_LD_F_NO_CFG; // no control-flow-graph flag is implicitly set here.
			break;
		case 'd':
			ctx.flags |= SHIVA_LD_F_NO_CFG;
			break;
		case 'c':
			ctx.flags |= SHIVA_LD_F_CFS_BINARY;
			break;
		default:
			break;
		}
	}
	if (ctx.flags & SHIVA_LD_F_NEEDED_INJECTION) {
		if (ctx.search_path == NULL || ctx.input_exec == NULL || ctx.input_patch == NULL || ctx.output_exec == NULL)
			goto usage;
	} else {
		if (ctx.input_exec == NULL || ctx.input_patch == NULL ||
		    ctx.interp_path == NULL || ctx.search_path == NULL || ctx.output_exec == NULL)
			goto usage;
	}
	TAILQ_INIT(&ctx.tailq.xref_tqlist);
	TAILQ_INIT(&ctx.tailq.branch_tqlist);
	/*
	 * Open the target executable, with modification privileges.
	 */
	if (elf_open_object(ctx.input_exec, &ctx.bin.elfobj,
		ELF_LOAD_F_FORENSICS|ELF_LOAD_F_MODIFY|ELF_LOAD_F_PRIV_MAP, &error) == false) {
		fprintf(stderr, "elf_open_object(%s, ...) failed: %s\n",
		    ctx.input_exec, elf_error_msg(&error));
		exit(EXIT_FAILURE);
	}

	struct elf_section section;

	if (elf_section_by_name(&ctx.bin.elfobj, ".text", &section) == false) {
		fprintf(stderr, "elf_section_by_name failed to find section .text\n");
		exit(EXIT_FAILURE);
	}

	ctx.disas.base = section.address;
	ctx.disas.textptr = elf_address_pointer(&ctx.bin.elfobj, section.address);

	if (init_shiva_strtab(&ctx) == false) {
		fprintf(stderr, "Failed to allocate .shiva.strtab: %s\n",
		    strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (((ctx.flags & SHIVA_LD_F_NO_CFG) == 0) && ((ctx.flags & SHIVA_LD_F_NEEDED_INJECTION) == 0)){
		if (analyze_binary(&ctx) == false) {
			fprintf(stderr, "analyze_binary() failed on %s\n",
			    elf_pathname(&ctx.bin.elfobj));
			exit(EXIT_FAILURE);
		}
	}

	printf("\n[+] Input executable: %s\n", ctx.input_exec);
	printf("[+] Input search path for patch: %s\n", ctx.search_path);
	printf("[+] Basename of patch: %s\n", ctx.input_patch);
	printf("[+] Output executable: %s\n", ctx.output_exec);

	if (shiva_prelink(&ctx) == false) {
		fprintf(stderr, "Failed to setup new LOAD segment with new DYNAMIC\n");
		exit(EXIT_FAILURE);
	}
	printf("Finished prelinking.\n");
	exit(EXIT_SUCCESS);
}
