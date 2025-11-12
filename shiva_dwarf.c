#include "shiva.h"

static bool
shiva_dwarf_find_function(Dwarf_Debug, const char *, Dwarf_Die *);

static bool
shiva_dwarf_resolve_die_location(Dwarf_Debug dbg, Dwarf_Die var_die, Dwarf_Addr pc, shiva_dwarf_loc_t *location)
{
	Dwarf_Error err = NULL;
	Dwarf_Attribute loc_attr;
	Dwarf_Off loc_offset;
	int ret, i, j;
        Dwarf_Unsigned entry_cnt = 0;
	Dwarf_Loc_Head_c loclist = NULL;
	bool res = false;

	/*
	 * Reference to location list in .debug_loc section
	 */
	ret = dwarf_attr(var_die, DW_AT_location, &loc_attr, &err);
	if (ret != DW_DLV_OK) {
		shiva_debug("dwarf_attr failed. no location info\n");
		return false;
	}

#if 0
	/*
	 * Get the offset of the location table
	 */
	ret = dwarf_global_formref(loc_attr, &loc_offset, &err);
	if (ret != DW_DLV_OK) {
		dwarf_dealloc(dbg, loc_attr, DW_DLA_ATTR);
		shiva_debug("dwarf_global_formref() failed\n");
		return false;
	}
#endif
	/*
	 * Read list into an array of Dwarf_Locdesc's
	 */
	shiva_debug("Calling dwarf_get_loclist_c\n");
	ret = dwarf_get_loclist_c(loc_attr, &loclist, &entry_cnt, &err);
	if (ret != DW_DLV_OK) {
		shiva_debug("dwarf_loclist_n() failed\n");
		return false;
	}
	shiva_debug("Iterating over %d entries\n", entry_cnt);
	for (i = 0; i < entry_cnt; i++) {
		Dwarf_Locdesc_c ld;
		Dwarf_Unsigned lopc, hipc, cents, lle_bytecount, expression_offset, locdesc_offset;
		Dwarf_Small lle_value, loclist_source;
		Dwarf_Bool dbg_addr_unavailable;
		Dwarf_Addr lowpc_cooked, hipc_cooked;

		shiva_debug("dwarf_get_locdesc_entry_e calling\n");
		ret = dwarf_get_locdesc_entry_e(loclist, i, &lle_value, &lopc, &hipc, &dbg_addr_unavailable,
		    &lowpc_cooked, &hipc_cooked, &cents, &lle_bytecount, &ld, &loclist_source, &expression_offset,
		    &locdesc_offset, &err);
		if (ret != DW_DLV_OK) {
			shiva_debug("dwarf_get_locdesc_entry_e failed\n");
			goto out;
		}
		printf("dbg_addr_unavailable: %d\n", dbg_addr_unavailable);
		if (dbg_addr_unavailable == true) {
			shiva_debug("Location entry %d has unavailable addresses\n", i);
			continue;
		}
		shiva_debug("pc: %#lx lopc: %#lx hipc: %#lx\n", pc, lowpc_cooked, hipc_cooked);
		if (entry_cnt == 1 && lowpc_cooked == 0 && hipc_cooked == 0) {
			shiva_debug("Single location expression for entire scope\n");
		} else if (pc < lowpc_cooked || pc >= hipc_cooked) {
			shiva_debug("PC %#lx outside of range %#lx-%#lx\n", pc, lowpc_cooked, hipc_cooked);
			continue;
		}

		if (cents == 0) {
			shiva_debug("No location entries for PC %#lx\n", pc);
			continue;
		}
		for (j = 0; j < cents; j++) {
			Dwarf_Small atom;
			Dwarf_Unsigned val, op1, op2, branch_offset;

			shiva_debug("Calling dwarf_get_location_op_value_c\n");
			ret = dwarf_get_location_op_value_c(ld, j, &atom, &val, &op1, &op2, &branch_offset, &err);
			if (ret != DW_DLV_OK) {
				shiva_debug("dwarf_get_location_op_value_c failed\n");
				goto out;
			}
			if (atom >= DW_OP_reg0 && atom <= DW_OP_reg31) {
				shiva_debug("Register location: reg=%u\n", atom - DW_OP_reg0);
				location->type = SHIVA_DWARF_LOC_REG;
				location->reg = atom - DW_OP_reg0;
				res = true;
				goto out;
			}

			if (atom == DW_OP_fbreg) {
				shiva_debug("Stack location: [rbp + (%04x)]\n", val);
				location->type = SHIVA_DWARF_LOC_STACK;
				location->stack_offset = val;
				res = true;
				goto out;
			}
			/*
			 * TODO: evaluate complex location.
			 */
			shiva_debug("unable to evaluate location\n");
			goto out;
		}
	}
out:
	dwarf_dealloc(dbg, loc_attr, DW_DLA_ATTR);
	dwarf_dealloc(dbg, loclist, DW_DLA_BLOCK);
	return res;
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
	int fd, ret;
	Dwarf_Attribute attr = NULL;
	Dwarf_Debug dbg = ctx->dwarf.debug;
	Dwarf_Error err;
	Dwarf_Die func_die = NULL;
	Dwarf_Die child = NULL;
	Dwarf_Die sibling = NULL;
	char *name = NULL;
	bool res = false;
	fd = ctx->elfobj.fd;

	if (shiva_dwarf_find_function(dbg, funcname, &func_die) == false) {
		fprintf(stderr, "failed to find dwarf die for function %s\n", funcname);
		return false;
	}

	ret = dwarf_child(func_die, &child, &err);
	if (ret != DW_DLV_OK) {
		shiva_debug("dwarf_child() failed\n");
		dwarf_dealloc(dbg, func_die, DW_DLA_DIE);
		return false;
	}
	while (child != NULL) {
		Dwarf_Half tag;
		ret = dwarf_tag(child, &tag, &err);
		if (ret != DW_DLV_OK) {
			dwarf_dealloc(dbg, child, DW_DLA_DIE);
			break;
		}
		shiva_debug("Checking tag\n");
		switch(tag) { /* may add more types in future */
		case DW_TAG_formal_parameter:
		case DW_TAG_variable:
			shiva_debug("Getting attribute\n");
			ret = dwarf_attr(child, DW_AT_name, &attr, &err);
			if (ret == DW_DLV_ERROR) {
				fprintf(stderr, "dwarf_attr() failed\n");
				dwarf_dealloc(dbg, child, DW_DLA_DIE);
				return false;
			}
			shiva_debug("Calling dwarf_formstring\n");
			ret = dwarf_formstring(attr, &name, &err);
			if (ret == DW_DLV_OK && name != NULL && strcmp(name, varname) == 0) {
				shiva_debug("name: %s, varname: %s\n", name, varname);
				dwarf_dealloc(dbg, name, DW_DLA_STRING);
				dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
				res = shiva_dwarf_resolve_die_location(dbg, child, pc, location);
				dwarf_dealloc(dbg, child, DW_DLA_DIE);
				dwarf_dealloc(dbg, func_die, DW_DLA_DIE);
				return res;
			}
			if (name != NULL) {
				dwarf_dealloc(dbg, name, DW_DLA_STRING);
			}
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

bool
shiva_dwarf_init(struct shiva_ctx *ctx)
{
	int fd;
	fd = ctx->elfobj.fd; /* already open file desriptor on ELF target */
	Dwarf_Error err;

        int ret = dwarf_init_b(fd, 0, NULL, NULL, &ctx->dwarf.debug, &err);
        if (ret != DW_DLV_OK) {
                fprintf(stderr, "dwarf_init_b() failed: %s\n", dwarf_errmsg(err));
                dwarf_dealloc_error(ctx->dwarf.debug, err);
                return false;
        }
	return true;
}

bool
shiva_dwarf_fini(struct shiva_ctx *ctx)
{
	Dwarf_Error err;

	if (dwarf_finish(ctx->dwarf.debug) != DW_DLV_OK) {
		fprintf(stderr, "shiva_dwarf_fini() failed: %s\n", dwarf_errmsg(err));
		return false;
	}
	return true;
}

/*
 * returns true if function succeeds
 * the last two args: addr and size are where the outputs are stored for the address and size
 */
bool
shiva_dwarf_line_attributes(struct shiva_ctx *ctx, const char *binpath, const char *funcname,
    unsigned int lineno, uint64_t *addr, size_t *size)
{
	int fd, ret;
	Dwarf_Debug dbg = ctx->dwarf.debug;
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
