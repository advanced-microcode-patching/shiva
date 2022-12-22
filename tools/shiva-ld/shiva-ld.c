#define _GNU_SOURCE

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
#include <optarg.h>

#include "/opt/elfmaster/include/libelfmaster.h"

/*
 * Shiva prelink context
 */
struct shiva_prelink_ctx {
	char *input_exec;
	char *input_patch;
	char *output_exec;
	char *search_path;
	elfobj_t *elfobj; /* elfobj ptr to input executable */
	uint64_t flags;
};

int main(int argc, char **argv)
{
	int opt = 0, long_index = 0;
	struct shiva_prelink_ctx ctx;

	static struct options long_options[] = {
		{"input_exec", required_argument, 0, 'e'},
		{"input_patch", required_argument, 0, 'p'},
		{"output_exec", required_argument, 0, 'o'},
		{"search_path", required_argument, 0, 's'},
		{"interp_path", required_argument, 0, 'i'}
		{0,	0, 	0, 	0};
	};

	if (argc < 3) {
		printf("Usage: %s -e test_bin -p patch1.o -i /lib/shiva"
		    "-s /opt/shiva/modules/ -o test_bin_final\n", argv[0]);
		printf("[-e] --input_exec\n");
		printf("[-p] --input_patch\n");
		printf("[-i] --interp_path\n");
		printf("[-s] --search_path\n");
		printf("[-o] --output_exec\n");
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
			ctx.output_path = strdup(optarg);
			if (ctx.output_path == NULL) {
				perror("strdup");
				exit(EXIT_FAILURE);
			}
			break;
		default:
			break;
		}
	}
}
