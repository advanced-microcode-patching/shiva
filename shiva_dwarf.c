#include "shiva.h"

static bool
shiva_dwarf_find_function(Dwarf_Debug, const char *, Dwarf_Die *);

static bool
shiva_dwarf_resolve_die_location(Dwarf_Debug dbg, Dwarf_Die var_die, Dwarf_Addr pc, shiva_dwarf_loc_t *location)
{


}
/*
 * A local variable or argument can be resolved
 * at given PC to a specific register or stack offset
 * -- This gives us the ability to function splice at a more
 *  high-level with original local variable names, etc.
 */
bool
shiva_dwarf_resolve_variable(struct shiva_ctx *ctx, const char *funcname, const char *varname,
    Dwarf_Addr pc, shiva_dwarf_loc_t *location)
{
	int fd;
	Dwarf_Attribute attr;
	Dwarf_Debug dbg = ctx->dwarf.debug;
	Dwarf_Error err;
	Dwarf_Die func_die = NULL;
	Dwarf_Die child = NULL;
	Dwarf_Die sibling = NULL;
	char *name = NULL;

	fd = ctx->elfobj.fd;

	int ret = dwarf_init_b(fd, 0, NULL, NULL, &dbg, &err);
	if (ret != DW_DLV_OK) {
		fprintf(stderr, "dwarf_init_b() failed: %s\n", dwarf_errmsg(err));
		dwarf_dealloc_error(dbg, err);
		close(fd);
		return false;
	}
	if (shiva_dwarf_find_function(dbg, funcname, &func_die) == false) {
		fprintf(stderr, "failed to find dwarf die for function %s\n", funcname);
		return false;
	}

	ret = dwarf_child(func_die, &child, &err);
	if (ret != DW_DLV_OK) {
		shiva_debug("dwarf_child() failed\n");
		return false;
	}
	while (child != NULL) {
		Dwarf_Half tag;

		ret = dwarf_tag(child, &tag, &err);
		if (ret != DW_DLV_OK)
			break;

		switch(tag) { /* may add more types in future */
		case DW_TAG_formal_parameter:
		case DW_TAG_variable:
			ret = dwarf_formstring(attr, &name, &err);
			if (ret == DW_DLV_OK && name != NULL && strcmp(name, varname) == 0) {
				dwarf_dealloc(dbg, name, DW_DLA_STRING);
				return shiva_dwarf_resolve_die_location(dbg, child, pc, location);
			}
			if (name != NULL) {
				dwarf_dealloc(dbg, name, DW_DLA_STRING);
			}
			return false;
			break;
		default:
			break;
		}
		ret = dwarf_siblingof_b(dbg, child, true, &sibling, &err);
		if (ret != DW_DLV_OK)
			break;
		dwarf_dealloc(dbg, child, DW_DLA_DIE);
		child = sibling;
	}
	return false;
}

static bool
shiva_dwarf_find_function(Dwarf_Debug dbg, const char *funcname, Dwarf_Die *out)
{
	Dwarf_Unsigned cu_header_length;
	Dwarf_Unsigned next_cu_header, typeoffset;
	Dwarf_Half version, header_length;
	Dwarf_Half address_size, length_size, extension_size, header_cu_type;
	Dwarf_Off abbrev_offset;
	Dwarf_Sig8 type_sig;
	Dwarf_Die func_die;
	Dwarf_Die cu_die;
	Dwarf_Error err;
	int ret;

	while ((ret = dwarf_next_cu_header_e(dbg, true, &cu_die, &cu_header_length, &version,
	    &abbrev_offset, &address_size, &length_size, &extension_size, &type_sig,
	    &typeoffset, &next_cu_header, &header_cu_type, &err)) == DW_DLV_OK) {

		shiva_debug("Iterating again\n");
		if (ret != DW_DLV_OK) {
			fprintf(stderr, "dwarf_siblingof_b failed: %s\n", dwarf_errmsg(err));
			continue;
		}
		bool found_func = false;
		Dwarf_Die child_die, sibling;
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
						*out = func_die;
						found_func = true;
						dwarf_dealloc(dbg, name, DW_DLA_STRING);
						goto done;
					}
					dwarf_dealloc(dbg, name, DW_DLA_STRING);
				}
			}
			Dwarf_Die next_die = 0;
			ret = dwarf_siblingof_b(dbg, child_die, true, &sibling, &err);
			dwarf_dealloc(dbg, child_die, DW_DLA_DIE);
			child_die = sibling;
		} while(child_die && ret == DW_DLV_OK);
	}
done:
	if (func_die) {
		/*
		 * The caller must dwarf_dealloc_die of Dwarf_Die *out
		 */
		return true;
	}
	return false;
}


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
	Dwarf_Unsigned cu_header_length;
	Dwarf_Unsigned next_cu_header, typeoffset;
	Dwarf_Half version, header_length;
	Dwarf_Half address_size, length_size, extension_size, header_cu_type;
	Dwarf_Off abbrev_offset;
	Dwarf_Sig8 type_sig;
	bool found_func = false, found_line = false;
	Dwarf_Die func_die;
	Dwarf_Die cu_die;

	fd = open(binpath, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "failed to open: %s. %s\n", binpath, strerror(errno));
		return false;
	}

	int ret = dwarf_init_b(fd, 0, NULL, NULL, &dbg, &err);
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
	while ((ret = dwarf_next_cu_header_e(dbg, true, &cu_die, &cu_header_length, &version,
	    &abbrev_offset, &address_size, &length_size, &extension_size, &type_sig,
	    &typeoffset, &next_cu_header, &header_cu_type, &err)) == DW_DLV_OK) {

		shiva_debug("Iterating again\n");
		if (ret != DW_DLV_OK) {
			fprintf(stderr, "dwarf_siblingof_b failed: %s\n", dwarf_errmsg(err));
			continue;
		}

		bool found_func = false;
		Dwarf_Die child_die, sibling;
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
						shiva_debug("Found function breaking\n");
						func_die = child_die;
						found_func = true;
						dwarf_dealloc(dbg, name, DW_DLA_STRING);
						goto getlineinfo;
					}
					dwarf_dealloc(dbg, name, DW_DLA_STRING);
				}
			}
			Dwarf_Die next_die = 0;
			ret = dwarf_siblingof_b(dbg, child_die, true, &sibling, &err);
			dwarf_dealloc(dbg, child_die, DW_DLA_DIE);
			child_die = sibling;
		} while(child_die && ret == DW_DLV_OK);
	}
getlineinfo:
	/*
	 * The function 'funcname' has been found. Let us now
	 * determine line attributes: address and size
	 * w_pc
	 */
	if (func_die) {
		shiva_debug("Function name found: %s\n", funcname);
		Dwarf_Line *linebuf;
		Dwarf_Unsigned line_no, version;
		Dwarf_Signed linecount;
		Dwarf_Addr line_addr;
		Dwarf_Line_Context line_context = 0;
		Dwarf_Small table_count;
		int i;
		enum Dwarf_Form_Class class;
		Dwarf_Addr low_pc, high_pc;
		Dwarf_Half form;
#if 0
		ret = dwarf_lowpc(func_die, &low_pc, &err);
		if (ret != DW_DLV_OK) {
			fprintf(stderr, "dwarf_lowpc() failed\n");
			return false;
		}
		ret = dwarf_highpc_b(func_die, &high_pc, &form, &class, &err);
		if (ret == DW_DLV_OK) {
			fprintf(stderr, "dwarf_highpc_b() failed\n");
			return false;
		}
#endif
		shiva_debug("calling dwarf_srclines_b\n");

		ret = dwarf_srclines_b(cu_die, &version, &table_count, &line_context, &err);
		if (ret != DW_DLV_OK) {
			fprintf(stderr, "dwarf_srclines() failed\n");
			return false;
		}

		ret = dwarf_srclines_from_linecontext(line_context, &linebuf, &linecount, &err);
		if (ret != DW_DLV_OK) {
			fprintf(stderr, "Error in dwarf_srclines_from_linecontext: %s\n", dwarf_errmsg(err));
			dwarf_dealloc_error(dbg, err);
			dwarf_srclines_dealloc_b(line_context);
			return false;
		}

		for (i = 0; i < linecount; i++) {
			char *filename;
#if 0
			if (dwarf_linesrc(linebuf[i], &filename, &err) != DW_DLV_OK) {
				fprintf(stderr, "dwarf_linesrc() failed\n");
				return false;
			}
			if (strstr(filename, srcfile) == NULL) {
				shiva_debug("Skipping line in wrong file %s (expected %s)\n",
				    filename, srcfile);
				dwarf_dealloc(dbg, filename, DW_DLA_STRING);
				continue;
			}
#endif
			if (dwarf_lineno(linebuf[i], &line_no, &err) != DW_DLV_OK) {
				fprintf(stderr, "dwarf_lineno() failed\n");
				return false;
			}

			if (line_no != lineno)
				continue;

			if (dwarf_lineaddr(linebuf[i], &line_addr, &err) != DW_DLV_OK) {
				fprintf(stderr, "dwarf_lineaddr() failed\n");
				return false;
			}
			*addr = line_addr;
			*size = 0;
			if (i + 1 < linecount) {
				Dwarf_Addr next_addr;

				if (dwarf_lineaddr(linebuf[i + 1], &next_addr, &err) == DW_DLV_OK &&
				    next_addr > line_addr) {
					*size = next_addr - line_addr;
				}
			}
			found_line = true;
			break;
		}
	}
	dwarf_dealloc_die(func_die);
	return found_line;
}
