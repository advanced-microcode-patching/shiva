#include "shiva.h"

bool
shiva_so_resolve_symbol(struct shiva_module *linker, char *symname, struct elf_symbol *out,
    char **so_path)
{
	elf_shared_object_iterator_t so_iter;
	struct elf_shared_object so;
	elf_iterator_res_t res;
	elf_error_t error;
	elfobj_t so_obj;

	*so_path = NULL;

	if (elf_shared_object_iterator_init(linker->target_elfobj, &so_iter,
	    NULL, ELF_SO_RESOLVE_ALL_F| /*ELF_SO_LDSO_FAST_F|*/ELF_SO_IGNORE_VDSO_F, &error) == false) {
		fprintf(stderr, "elf_shared_object_iterator_init failed: %s\n",
		    elf_error_msg(&error));
		return false;
	}
	for (;;) {
		res = elf_shared_object_iterator_next(&so_iter, &so, &error);
		if (res == ELF_ITER_DONE)
			break;
		if (res == ELF_ITER_ERROR) {
			fprintf(stderr, "elf_shared_object_iterator_next failed: %s\n",
			    elf_error_msg(&error));
			return false;
		}
		shiva_debug("[+] Processing: %s\n", so.path);
		if (elf_open_object(so.path, &so_obj, ELF_LOAD_F_STRICT, &error) == false) {
			fprintf(stderr, "elf_open_object failed: %s\n", elf_error_msg(&error));
			return false;
		}
		shiva_debug("[+] Searching for symbol '%s' in shared object '%s'\n",
		    symname, so.basename);

		if (elf_symbol_by_name(&so_obj, symname, out) == false)
			continue;
		if (out->bind != STB_GLOBAL && out->bind != STB_WEAK)
			continue;
		/*
		 * Fill in the pathname to the shared object that this symbol
		 * lives within.
		 */
		*so_path = strdup(so.path);
		if (*so_path == NULL) {
			perror("strdup");
			exit(EXIT_FAILURE);
		}
		shiva_debug("Found symbol '%s' (symval: %#lx) in shared object '%s'\n",
		    symname, out->value, so.basename);
		return true;
	}
	if (*so_path == NULL)
		return false;

	return true;
}
