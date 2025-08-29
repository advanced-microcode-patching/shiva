#include "shiva.h"

/*
 * returns true if function succeeds
 * the last two args: addr and size are where the outputs are stored for the address and size
 */
bool
shiva_dwarf_line_attributes(const char *binpath, const char *funcname,
    unsigned int lineno, uint64_t *addr, size_t *size)
{
	int fd;
	Dwarf_Debug dbg = 0;
	Dwarf_Error err = 0;
	size_t line_count = 0;
	size_t line_capacity = 0;
	Dwarf_Unsigned cu_header_length = 0;
	Dwarf_Half version = 0, header_length = 0;
	Dwarf_Half address_size, length_size, extension_size;
	Dwarf_Off abbrev_offset;
	Dwarf_Sig8 type_sig;
	bool found_func;
	Dwarf_Die func_die;

	printf("Opening %s\n", binpath);
	fd = open(binpath, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "failed to open: %s. %s\n", binpath, strerror(errno));
		return false;
	}


	int ret = dwarf_init_b(fd, DW_DLC_READ, 0, NULL, NULL, &dbg, &err);
	if (ret != DW_DLV_OK) {
		fprintf(stderr, "dwarf_init_b() failed: %s\n", dwarf_errmsg(err));
		dwarf_dealloc_error(dbg, err);
		close(fd);
		return false;
	}

	/*
	 * Iterate over each compilation unit (i.e. source files) until we find
	 * the function specified by funcname
	 */
	printf("iterating over compilation units\n");
	while ((ret = dwarf_next_cu_header_d(dbg, true, &cu_header_length, &version,
	    &abbrev_offset, &address_size, &length_size, &extension_size, &type_sig,
	    NULL, NULL, NULL, &err)) == DW_DLV_OK) {

		Dwarf_Die cu_die = 0;
		ret = dwarf_siblingof_b(dbg, NULL, 1, &cu_die, &err);
		if (ret != DW_DLV_OK) {
			fprintf(stderr, "dwarf_siblingof_b failed: %s\n", dwarf_errmsg(err));
			continue;
		}

		bool found_func = false;
		Dwarf_Die child_die;
		/*
		 * Get the first child DIE
		 */
		ret = dwarf_child(cu_die, &child_die, &err);
		do {
			if (ret != DW_DLV_OK)
				break;
			Dwarf_Half tag;
			/*
			 * Is this a function?
			 */
			if (dwarf_tag(child_die, &tag, &err) == DW_DLV_OK &&
			    tag == DW_TAG_subprogram) {
				char *name = NULL;
				
				/*
				 * If it is a function, does it compare to char *funcname?
				 */
				if (dwarf_diename(child_die, &name, &err) == DW_DLV_OK) {
					if (strcmp(name, funcname) == 0) {
						func_die = child_die;
						found_func = true;
						dwarf_dealloc(dbg, name, DW_DLA_STRING);
						break;
					}
					dwarf_dealloc(dbg, name, DW_DLA_STRING);
				}
			}
			Dwarf_Die next_die = 0;
			ret = dwarf_siblingof_b(dbg, child_die, true, &child_die, &err);
			dwarf_dealloc(dbg, child_die, DW_DLA_DIE);
		} while(child_die && ret == DW_DLV_OK);
	}

	/*
	 * The function 'funcname' has been found. Let us now
	 * determine line attributes: address and size
	 */
	if (func_die) {
		printf("Function name found: %s\n", funcname);
		Dwarf_Line *linebuf;
	}
}
