#define _GNU_SOURCE

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

#include "/opt/elfmaster/include/libelfmaster.h"

#define SHIVA_DT_NEEDED	DT_LOOS + 10
#define SHIVA_DT_SEARCH DT_LOOS + 11

#define SHIVA_SIGNATURE 0x31f64

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

/*
 * Shiva prelink context
 */
struct shiva_prelink_ctx {
	char *input_exec;
	char *input_patch;
	char *output_exec;
	char *search_path;
	char *interp_path;
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
} shiva_prelink_ctx;

static bool
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

void test_mark(void)
{
	int i = &test_mark;
}
bool
create_load_segment(struct shiva_prelink_ctx *ctx)
{
	int fd;
	struct elf_segment segment, n_segment;
	elf_segment_iterator_t phdr_iter;
	elf_error_t error;
	uint64_t last_load_vaddr, last_load_offset, last_load_size;
	uint64_t last_load_align;
	bool res;
	bool found_note = false, found_dynamic = false;
	uint8_t *mem;
	char *target_path;
	const char *tmpfile = "/tmp/elf.tmp"; // XXX use mkstemp
	char null = 0;
	struct stat st;
	uint8_t *old_dynamic_segment;
	size_t old_dynamic_size, dynamic_index;

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
			ctx->new_segment.dyn_size += (sizeof(ElfW(Dyn)) * 2);
			//ctx->new_segment.dyn_size = segment.filesz + sizeof(ElfW(Dyn)) * 2;
			ctx->new_segment.dyn_offset = 0;

			old_dynamic_size = elf_dtag_count(&ctx->bin.elfobj) * sizeof(ElfW(Dyn));
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
			/*
			 * Make room for original dynamic segment
			 */
			ctx->new_segment.filesz = segment.filesz;
			/*
			 * Make room for the two new additional dynamic entries
			 */
			ctx->new_segment.filesz += sizeof(ElfW(Dyn)) * 2;
			ctx->new_segment.filesz += strlen(ctx->input_patch) + 1;
			ctx->new_segment.filesz += strlen(ctx->search_path) + 1;
			dynamic_index = phdr_iter.index - 1;
		} else if (segment.type == PT_NOTE) {
			if (found_dynamic == false) {
				fprintf(stderr, "Failed to find PT_DYNAMIC before PT_NOTE\n");
				return false;
			}
			n_segment.type = PT_LOAD;
			n_segment.offset =
			    ELF_PAGEALIGN(ctx->bin.elfobj.size, last_load_align);
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

			printf("s.offset: %#lx\n", n_segment.offset);
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
	struct elf_section shdr;

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
			break;
		}
	}
			/*
	 * Write out
	 * 1. New dynamic segment (With additional SHIVA_DT_ entries)
	 * 2. Strings for search path and module.
	 */

	if (stat(elf_pathname(&ctx->bin.elfobj), &st) < 0) {
		perror("stat");
		return false;
	}
	fd = open(tmpfile, O_RDWR|O_TRUNC|O_CREAT, st.st_mode);
	if (fd < 0) {
		perror("open");
		return false;
	}

	shiva_pl_debug("Writing first %zu bytes of %s into tmpfile\n",
	    ctx->bin.elfobj.size, ctx->bin.elfobj.path);

	if (write(fd, ctx->bin.elfobj.mem, ctx->bin.elfobj.size) < 0) {
		perror("write 1.");
		return false;
	}

	shiva_pl_debug("s.offset: %#lx ctx->bin.elfobj.size: %#lx\n", n_segment.offset, ctx->bin.elfobj.size);
	shiva_pl_debug("Writing extended sement of %zu bytes\n",
	    n_segment.offset - ctx->bin.elfobj.size);

	if (write(fd, &null, n_segment.offset - ctx->bin.elfobj.size) < 0) {
		perror("write 2.");
		return false;
	}

	/*
	 * Write out entire old dynamic segment, except for the last entry
	 * which will be DT_NULL
	 */
	printf("Writing %d bytes of old dynamic segment into place\n", old_dynamic_size - sizeof(ElfW(Dyn)));
	if (write(fd, old_dynamic_segment,
	    old_dynamic_size - sizeof(ElfW(Dyn))) < 0) {
		perror("write 3.");
		return false;
	}

	ElfW(Dyn) dyn[3];

	/*
	 * Write out new dynamic entry for SHIVA_DT_SEARCH and
	 * SHIVA_DT_NEEDED
	 */
	dyn[0].d_tag = SHIVA_DT_SEARCH;
	dyn[0].d_un.d_ptr = ctx->new_segment.vaddr + ctx->new_segment.dyn_size;

	dyn[1].d_tag = SHIVA_DT_NEEDED;
	dyn[1].d_un.d_ptr = ctx->new_segment.vaddr + ctx->new_segment.dyn_size + strlen(ctx->search_path) + 1;

	dyn[2].d_tag = DT_NULL;

	printf("Writing custom DT_ entries, three of them totally %d bytes\n", sizeof(dyn));
	if (write(fd, &dyn[0], sizeof(dyn)) < 0) {
		perror("write 4.");
		return false;
	}
	if (write(fd, ctx->search_path, strlen(ctx->search_path) + 1) < 0) {
		perror("write 5.");
		return false;
	}

	if (write(fd, ctx->input_patch, strlen(ctx->input_patch) + 1) < 0) {
		perror("write 6.");
		return false;
	}

	if (fchown(fd, st.st_uid, st.st_gid) < 0) {
		perror("fchown");
		return false;
	}
	close(fd);

	target_path = strdup(elf_pathname(&ctx->bin.elfobj));
	if (target_path == NULL) {
		perror("strdup");
		return false;
	}

	elf_close_object(&ctx->bin.elfobj);
	rename(tmpfile, ctx->output_exec);

	printf("Opening: %s\n", ctx->output_exec);
	if (elf_open_object(ctx->output_exec, &ctx->bin.elfobj,
	    ELF_LOAD_F_MODIFY|ELF_LOAD_F_STRICT, &error) == false) {
		fprintf(stderr, "elf_open_object(%s, ...) failed: %s\n",
		    ctx->output_exec, elf_error_msg(&error));
		free(target_path);
		return false;
	}
	free(target_path);
	*(uint32_t *)&ctx->bin.elfobj.mem[EI_PAD] = SHIVA_SIGNATURE;
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
		{0,	0,	0,	0}
	};

	if (argc < 3) {
usage:
		printf("Usage: %s -e test_bin -p patch1.o -i /lib/shiva"
		    "-s /opt/shiva/modules/ -o test_bin_final\n", argv[0]);
		printf("[-e] --input_exec	Input ELF executable\n");
		printf("[-p] --input_patch	Input ELF patch\n");
		printf("[-i] --interp_path	Interpreter search path, i.e. \"/lib/shiva\"\n");
		printf("[-s] --search_path	Module search path (For patch object)\n");
		printf("[-o] --output_exec	Output executable\n");
		exit(0);
	}

	memset(&ctx, 0, sizeof(ctx));

	while ((opt = getopt_long(argc, argv, "e:p:i:s:o:",
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
			if (access(ctx.input_exec, F_OK) != 0) {
				perror("access");
				exit(EXIT_FAILURE);
			}
			break;
		case 'i':
			ctx.interp_path = strdup(optarg);
			if (ctx.interp_path == NULL) {
				perror("strdup");
				exit(EXIT_FAILURE);
			}
			if (access(ctx.interp_path, F_OK) != 0) {
				perror("access");
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
		default:
			break;
		}
	}
	if (ctx.input_exec == NULL || ctx.input_patch == NULL ||
	    ctx.interp_path == NULL || ctx.search_path == NULL || ctx.output_exec == NULL)
		goto usage;

	/*
	 * Open the target executable, with modification privileges.
	 */
	printf("Opening: %s\n", ctx.input_exec);
	if (elf_open_object(ctx.input_exec, &ctx.bin.elfobj,
		ELF_LOAD_F_STRICT|ELF_LOAD_F_MODIFY, &error) == false) {
		fprintf(stderr, "elf_open_object(%s, ...) failed: %s\n",
		    ctx.input_exec, elf_error_msg(&error));
		exit(EXIT_FAILURE);
	}

	/*
	 * Open the patch object
	 */
	if (elf_open_object(ctx.input_patch, &ctx.patch.elfobj,
		ELF_LOAD_F_STRICT, &error) == false) {
		fprintf(stderr, "elf_open_object(%s, ...) failed: %s\n",
		    ctx.input_patch, elf_error_msg(&error));
		exit(EXIT_FAILURE);
	}

	if (create_load_segment(&ctx) == false) {
		fprintf(stderr, "Failed to setup new LOAD segment with new DYNAMIC\n");
		exit(EXIT_FAILURE);
	}
}
