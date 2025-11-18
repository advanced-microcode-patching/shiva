/*
#include "shiva.h"

#include <gcc-plugin.h>
#include <plugin-api.h>
#include <tree.h>
#include <tree-iterator.h>
#include <cgraph.h>
#include <gimple.h>
#include <gimple-iterator.h>
#include <tree-pass.h>
#include <rtl.h>
#include <emit-rtl.h>
#include <basic-block.h>
#include <function.h>
#include <insn-codes.h>
#include <libelf.h>
*/

#include "shiva.h"

#include <gcc-plugin.h>
#include <plugin-api.h>
#include <tree.h>
#include <tree-iterator.h>
#include <cgraph.h>
#include <gimple.h>
#include <gimple-iterator.h>
#include <tree-pass.h>
#include <basic-block.h>
#include <function.h>
#include <memmodel.h>	     /* ← CRITICAL: Defines enum memmodel fully */
#include <rtl.h>
#include <emit-rtl.h>	     /* ← Now safe: memmodel is included */
#include <insn-codes.h>
#include <libelf.h>
#include <context.h>

#if 0
#include <string.h>
#include <stdio.h>
#endif


static const pass_data splice_pass_data_constructor = {
	GIMPLE_PASS,	      /* type */
	"splice_pass",	      /* name */
	OPTGROUP_NONE,	      /* optinfo_flags */
	TV_NONE,	      /* tv_id */
	PROP_cfg,	      /* properties_required (minimal for GIMPLE passes) */
	0,		      /* properties_provided */
	0,		      /* properties_destroyed */
	0,		      /* todo_flags_start */
	0		      /* todo_flags_finish */
};

// Plugin info required by GCC we are using visibility so that it
// doesn't be marked hidden by our flag in the Makefile
__attribute__((visibility("default"))) int plugin_is_GPL_compatible;

typedef struct shiva_reloc {
	unsigned long r_offset;   // Instruction address
	const char *symbol_name;  // DWARF symbol name
	int patch_field;	  // SOURCE_REGISTER, SOURCE_OFFSET, DEST_REGISTER, DEST_OFFSET
	int displacement_size;	  // 8, 32 (stack), or 0 (register)
	int access_size;	  // 64, 32, etc.
	int access_type;	  // READ or WRITE
	int src_register;	  // Source reg for writes (e.g., 0 for %rax)
	int dest_register;	  // Dest reg for reads (e.g., 0 for %rax)
} shiva_reloc_t;

static struct plugin_info splice_plugin_info = {
  .version = "1.10",
  .help = "Shiva splice plugin with DWARF support for local  variable resolution\n"
	  "Usage: -fplugin-arg-shiva_splice-elf=<path_to_elf>",
};

/* Register names for inline assembly */
static const char *shiva_reg_names[] = {
	"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
	"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
};

static struct shiva_ctx shiva_ctx;
static Dwarf_Addr insert_addr = 0, extend_addr = 0;
char *elf_path;

static bool
shiva_dwarf_find_function(Dwarf_Debug, const char *, Dwarf_Die *);

/*
 * Retrieve the size of a variable from its DWARF DIE.
 * Returns the size in bytes as a uint32_t, defaulting to 4 (int size) if
 * the size cannot be determined.
 */
static uint32_t
shiva_dwarf_get_variable_size(Dwarf_Debug dbg, Dwarf_Die var_die)
{
	Dwarf_Attribute type_attr;
	Dwarf_Off type_offset;
	Dwarf_Die type_die;
	Dwarf_Error err;
	Dwarf_Attribute size_attr;
	Dwarf_Unsigned byte_size;
	uint32_t size = 4;	/* Default to 4 bytes (int). */
	int ret;
	Dwarf_Bool res, is_info;

	ret = dwarf_attr(var_die, DW_AT_type, &type_attr, &err);
	if (ret != DW_DLV_OK)
		return size;

	ret = dwarf_formref(type_attr, &type_offset, &res, &err);
	if (ret != DW_DLV_OK) {
		dwarf_dealloc(dbg, type_attr, DW_DLA_ATTR);
		return size;
	}

	ret = dwarf_offdie_b(dbg, type_offset, is_info, &type_die, &err);
	if (ret != DW_DLV_OK) {
		dwarf_dealloc(dbg, type_attr, DW_DLA_ATTR);
		return size;
	}

	ret = dwarf_attr(type_die, DW_AT_byte_size, &size_attr, &err);
	if (ret == DW_DLV_OK) {
		ret = dwarf_formudata(size_attr, &byte_size, &err);
		if (ret == DW_DLV_OK)
			size = (uint32_t)byte_size;
		dwarf_dealloc(dbg, size_attr, DW_DLA_ATTR);
	}

	dwarf_dealloc(dbg, type_attr, DW_DLA_ATTR);
	dwarf_dealloc(dbg, type_die, DW_DLA_DIE);
	return size;
}

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
	bool res;
	elf_error_t elf_error;

	ctx->path = elf_path;

	res = elf_open_object(elf_path, &ctx->elfobj, ELF_LOAD_F_STRICT, &elf_error);
	if (res == false) {
		fprintf(stderr, "elf_open_object(%s, ...) failed: %s\n",
		    elf_path, elf_error_msg(&elf_error));
		return false;
	}
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

static struct plugin_name_args *global_plugin_info;

/*
 * parse_arguments - Parse plugin command-line arguments
 *
 * Extracts ELF path, insert address, and extend address from plugin args.
 */
static void
parse_arguments(void)
{
	struct plugin_argument *arg;

	for (arg = global_plugin_info->argv; arg->key != NULL; arg++) {
		if (strcmp(arg->key, "elf") == 0)
			elf_path = arg->value;
		else if (strcmp(arg->key, "insert") == 0)
			insert_addr = strtoull(arg->value, NULL, 0);
		else if (strcmp(arg->key, "extend") == 0)
			extend_addr = strtoull(arg->value, NULL, 0);
	}
}

#if 0
/*
 * splice_gimple_pass - GIMPLE pass to modify splice function variable accesses
 *
 * Iterates through GIMPLE statements in splice functions, rewriting
 * variable accesses to use DWARF-derived locations (stack or register)
 * and adding register preservation and a jump to the extend address.
 *
 * Returns: 0 on success
 */
static unsigned int
splice_gimple_pass(void)
{
	/* Iterate over all functions in the program’s call graph to find splice functions */
	struct cgraph_node *node;
	basic_block bb;

	FOR_EACH_DEFINED_FUNCTION(node) {
		/* Skip functions without a body (e.g., declarations or external functions) */
		if (!gimple_has_body_p(node->decl))
			continue;

		/* Retrieve the function’s name from its declaration for identification */
		const char *funcname = IDENTIFIER_POINTER(DECL_NAME(node->decl));

		/* Check if this is a splice function by verifying the prefix "__shiva_splice_fn_name_" */
		if (strncmp(funcname, "__shiva_splice_fn_name_", 23) != 0)
			continue;

		/* Extract the target function name (e.g., "foo" from "__shiva_splice_fn_name_foo") */
		const char *target_func = funcname + 23;

		/* Initialize a dynamic array to store DWARF-derived variable locations */
		shiva_dwarf_loc_t *vars = NULL;
		int var_count = 0;
		Dwarf_Die func_die = NULL;

		/* Use DWARF to find the DIE (Debugging Information Entry) for the target function */
		if (shiva_dwarf_find_function(shiva_ctx.dwarf.debug, target_func, &func_die)) {
			/* Retrieve the first child DIE under the function (e.g., variables or parameters) */
			Dwarf_Die child = NULL, sibling = NULL;
			Dwarf_Error err;
			int ret = dwarf_child(func_die, &child, &err);

			/* If children exist, iterate to collect variable locations */
			if (ret == DW_DLV_OK) {
				while (child != NULL) {
					/* Get the DIE’s tag to identify variables or formal parameters */
					Dwarf_Half tag;

					if (dwarf_tag(child, &tag, &err) == DW_DLV_OK &&
					    (tag == DW_TAG_variable ||
					    tag == DW_TAG_formal_parameter)) {
						/* Extract the variable’s name from the DWARF attributes */
						Dwarf_Attribute attr;
						char *var_name = NULL;

						if (dwarf_attr(child, DW_AT_name, &attr,
						    &err) == DW_DLV_OK) {
							if (dwarf_formstring(attr, &var_name,
							    &err) == DW_DLV_OK) {
								/* Create a location structure for the variable */
								shiva_dwarf_loc_t loc = {0};

								loc.symname = xstrdup(var_name);

								/* Resolve the variable’s location (stack offset or register) at the splice point */
								if (shiva_dwarf_resolve_variable(
								    &shiva_ctx, target_func,
								    var_name, insert_addr, &loc)) {
									/* Store valid locations in the array for later GIMPLE processing */
									vars = (shiva_dwarf_loc_t *)xrealloc(vars,
									    (var_count + 1) *
									    sizeof(shiva_dwarf_loc_t));
									vars[var_count] = loc;
									var_count++;
								} else {
									/* Free memory if DWARF resolution fails (e.g., variable not found) */
									free(loc.symname);
								}
								/* Clean up DWARF string resources */
								dwarf_dealloc(shiva_ctx.dwarf.debug,
								    var_name, DW_DLA_STRING);
							}
							/* Clean up DWARF attribute resources */
							dwarf_dealloc(shiva_ctx.dwarf.debug, attr,
							    DW_DLA_ATTR);
						}
					}
					/* Move to the next sibling DIE (e.g., next variable or parameter) */
					ret = dwarf_siblingof_b(shiva_ctx.dwarf.debug, child,
					    true, &sibling, &err);
					dwarf_dealloc(shiva_ctx.dwarf.debug, child, DW_DLA_DIE);
					child = sibling;
				}
			}
			/* Clean up the function DIE after processing all children */
			dwarf_dealloc(shiva_ctx.dwarf.debug, func_die, DW_DLA_DIE);
		}

		/* Set the current function context to enable GIMPLE manipulation */
		push_cfun(DECL_STRUCT_FUNCTION(node->decl));

		/* Access the GIMPLE body of the splice function (e.g., __shiva_splice_fn_name_foo) */
		gimple_seq body = gimple_body(node->decl);
		gimple_stmt_iterator gsi;

		/* Iterate through each GIMPLE statement in the function body */
		FOR_EACH_BB_FN(bb, cfun) {
			for (gsi = gsi_start(body); !gsi_end_p(gsi); gsi_next(&gsi)) {
				/* Get the current GIMPLE statement (e.g., assignment, conditional) */
				gimple *stmt = gsi_stmt(gsi);

				/* Process only assignments (GIMPLE_ASSIGN) or conditionals (GIMPLE_COND) */
				if (gimple_code(stmt) == GIMPLE_ASSIGN ||
				    gimple_code(stmt) == GIMPLE_COND) {
					/* Extract the left-hand side (LHS) and right-hand side (RHS) operands */
					tree lhs = gimple_num_ops(stmt) > 1 ?
					    gimple_op(stmt, 0) : NULL;
					tree rhs = gimple_num_ops(stmt) > 1 ?
					    gimple_op(stmt, 1) : NULL;

					/* Check each DWARF-resolved variable to see if it appears in the statement */
					for (int i = 0; i < var_count; i++) {
						/* Handle LHS variable references (e.g., local_var = ...) */
						if (lhs && TREE_CODE(lhs) == VAR_DECL &&
						    strcmp(IDENTIFIER_POINTER(DECL_NAME(lhs)),
						    vars[i].symname) == 0) {
							if (vars[i].type == SHIVA_DWARF_LOC_STACK) {
								/* Replace the variable reference with a memory reference to the DWARF-derived stack location (e.g., [rbp-8]) */
								tree mem_ref = build2(MEM_REF,
								    TREE_TYPE(lhs),
								    build_int_cst(ptr_type_node,
								    vars[i].stack_offset),
								    build_int_cst(ptr_type_node, 0));
								    gimple_set_op(stmt, 0, mem_ref);
							} else if (vars[i].type == SHIVA_DWARF_LOC_REG) {
								/* For register variables, use inline assembly to load the value (e.g., movl %edi, %eax) */
								char asm_str[64];
								const char *reg_name = shiva_reg_names[vars[i].reg];

								snprintf(asm_str, sizeof(asm_str),
								    "movl %%%s, %%eax", reg_name);
								gimple *asm_stmt = gimple_build_asm_vec(
								    asm_str, NULL, NULL, NULL, NULL);
								gsi_insert_after(&gsi, asm_stmt, GSI_SAME_STMT);
								//gimple_seq_add_stmt(&gimple_body(
								//   gsi.bb), asm_stmt);
								/* Create a temporary variable to bridge inline assembly to GIMPLE */
								tree temp = create_tmp_var(
								    TREE_TYPE(lhs), "temp");
								    gimple_set_op(stmt, 0, temp);
							}
						}
					/* Handle RHS variable references (e.g., ... = local_var) */
						if (rhs && TREE_CODE(rhs) == VAR_DECL &&
						    strcmp(IDENTIFIER_POINTER(DECL_NAME(rhs)),
						    vars[i].symname) == 0) {
							if (vars[i].type == SHIVA_DWARF_LOC_STACK) {
							/* Replace the variable reference with a memory reference to the DWARF-derived stack location */
								tree mem_ref = build2(MEM_REF,
								    TREE_TYPE(rhs),
								    build_int_cst(ptr_type_node,
								    vars[i].stack_offset),
								    build_int_cst(ptr_type_node, 0));
								gimple_set_op(stmt, 1, mem_ref);
							} else if (vars[i].type == SHIVA_DWARF_LOC_REG) {
								/* Load register value via inline assembly */
								char asm_str[64];
								const char *reg_name = shiva_reg_names[
									vars[i].reg];

								snprintf(asm_str, sizeof(asm_str),
								    "movl %%%s, %%eax", reg_name);
								gimple *asm_stmt = gimple_build_asm_vec(
								    asm_str, NULL, NULL, NULL, NULL);
								//gimple_seq_add_stmt(&gimple_body(
								//   gsi.bb), asm_stmt);
								gsi_insert_after(&gsi, asm_stmt, GSI_SAME_STMT);
								tree temp = create_tmp_var(
								    TREE_TYPE(rhs), "temp");
								gimple_set_op(stmt, 1, temp);
							}
						}
						/* Handle address-of expressions (e.g., &local_var) */
						if (rhs && TREE_CODE(rhs) == ADDR_EXPR &&
						    TREE_OPERAND(rhs, 0) &&
						    TREE_CODE(TREE_OPERAND(rhs, 0)) == VAR_DECL &&
						    strcmp(IDENTIFIER_POINTER(DECL_NAME(
							TREE_OPERAND(rhs, 0))), vars[i].symname) == 0) {
							if (vars[i].type == SHIVA_DWARF_LOC_STACK) {
								/* Generate address of stack variable (e.g., leaq -8(%rbp), %rax) */
								char asm_str[64];

								snprintf(asm_str, sizeof(asm_str),
								    "leaq %ld(%%rbp), %%rax",
								     vars[i].stack_offset);
								gimple *asm_stmt = gimple_build_asm_vec(
								    asm_str, NULL, NULL, NULL, NULL);
								//gimple_seq_add_stmt(&gimple_body(
								//   gsi.bb), asm_stmt);
								gsi_insert_after(&gsi, asm_stmt, GSI_SAME_STMT);
								tree temp = create_tmp_var(
								    ptr_type_node, "temp_addr");
								gimple_set_op(stmt, 1, temp);
							} else if (vars[i].type == SHIVA_DWARF_LOC_REG) {
								/* Use register value as the address (e.g., movq %rdi, %rax) */
								char asm_str[64];
								const char *reg_name = shiva_reg_names[
									vars[i].reg];

								snprintf(asm_str, sizeof(asm_str),
								    "movq %%%s, %%rax", reg_name);
								gimple *asm_stmt = gimple_build_asm_vec(
								    asm_str, NULL, NULL, NULL, NULL);
								//gimple_seq_add_stmt(&gimple_body(
								  //  gsi.bb), asm_stmt);
								gsi_insert_after(&gsi, asm_stmt, GSI_SAME_STMT);
								tree temp = create_tmp_var(
								    ptr_type_node, "temp_addr");
								gimple_set_op(stmt, 1, temp);
							}
						}
					}
				}
			}
		}
		/* Add register preservation at the function’s entry to protect foo’s state */
		basic_block entry_bb = ENTRY_BLOCK_PTR_FOR_FN(cfun);
		gimple_seq prelude = NULL;

		/* Save %rax, used for register loads and addresses */
		gimple *push_rax = gimple_build_asm_vec("push %rax", NULL, NULL,
		    NULL, NULL);
		/* Save %rbx, used for splice variables (e.g., some_new_variable) */
		gimple *push_rbx = gimple_build_asm_vec("push %rbx", NULL, NULL,
		    NULL, NULL);
		gimple_seq_add_stmt(&prelude, push_rax);
		gimple_seq_add_stmt(&prelude, push_rbx);
		
		//gimple_seq_set_body(entry_bb->head, prelude);

		/* replace previous commented line with: */

		entry_bb = ENTRY_BLOCK_PTR_FOR_FN(cfun);
#if 0
		gimple_seq seq = NULL;
		gimple_seq_add_seq(&seq, prelude);
		gimple_set_bb_seq(entry_bb, seq);
#endif


		gimple_seq_add_seq(&entry_bb->il.gimple.seq, prelude);

		/* Add register restoration and jump at the function’s exit */
		basic_block exit_bb = EXIT_BLOCK_PTR_FOR_FN(cfun);
		basic_block last_bb = exit_bb->prev_bb;
		gimple_seq postlude = NULL;

		/* Restore %rbx */
		gimple *pop_rbx = gimple_build_asm_vec("pop %rbx", NULL, NULL,
		    NULL, NULL);
		/* Restore %rax */
		gimple *pop_rax = gimple_build_asm_vec("pop %rax", NULL, NULL,
		    NULL, NULL);
		/* Jump to the extend address (e.g., 0x11d6) specified by the plugin argument */
		char jmp_str[64];

		snprintf(jmp_str, sizeof(jmp_str), "jmp 0x%llx",
		    (unsigned long long)extend_addr);
		gimple *jmp = gimple_build_asm_vec(jmp_str, NULL, NULL, NULL, NULL);
		gimple_seq_add_stmt(&postlude, pop_rbx);
		gimple_seq_add_stmt(&postlude, pop_rax);
		gimple_seq_add_stmt(&postlude, jmp);
		gimple_seq_add_seq(&last_bb->il.gimple.seq, postlude);
		/* Restore the previous function context */
		pop_cfun();

		/* Clean up allocated memory for DWARF variable locations */
		for (int i = 0; i < var_count; i++)
			free(vars[i].symname);
		free(vars);
	}

	/* Return 0 to indicate successful pass execution */
	return 0;
}

#endif

namespace {
    class splice_pass : public gimple_opt_pass {
    public:
        splice_pass(gcc::context *ctxt)
            : gimple_opt_pass(splice_pass_data_constructor, ctxt) {}

        virtual unsigned int execute(function *) override {
            // Your original splice_gimple_pass logic goes here (the entire body)
            // Iterate over cgraph nodes, DWARF resolution, GIMPLE rewriting, etc.
            // Return 0 on success
            struct cgraph_node *node;
            basic_block bb;

            FOR_EACH_DEFINED_FUNCTION(node) {
                if (!gimple_has_body_p(node->decl))
                    continue;

                const char *funcname = IDENTIFIER_POINTER(DECL_NAME(node->decl));

                if (strncmp(funcname, "__shiva_splice_fn_name_", 23) != 0)
                    continue;

                const char *target_func = funcname + 23;

                shiva_dwarf_loc_t *vars = NULL;
                int var_count = 0;
                Dwarf_Die func_die = NULL;

                if (shiva_dwarf_find_function(shiva_ctx.dwarf.debug, target_func, &func_die)) {
                    Dwarf_Die child = NULL, sibling = NULL;
                    Dwarf_Error err;
                    int ret = dwarf_child(func_die, &child, &err);

                    if (ret == DW_DLV_OK) {
                        while (child != NULL) {
                            Dwarf_Half tag;

                            if (dwarf_tag(child, &tag, &err) == DW_DLV_OK &&
                                (tag == DW_TAG_variable || tag == DW_TAG_formal_parameter)) {
                                Dwarf_Attribute attr;
                                char *var_name = NULL;

                                if (dwarf_attr(child, DW_AT_name, &attr, &err) == DW_DLV_OK) {
                                    if (dwarf_formstring(attr, &var_name, &err) == DW_DLV_OK) {
                                        shiva_dwarf_loc_t loc = {0};

                                        loc.symname = xstrdup(var_name);

                                        if (shiva_dwarf_resolve_variable(&shiva_ctx, target_func, var_name, insert_addr, &loc)) {
                                            vars = (shiva_dwarf_loc_t *)xrealloc(vars, (var_count + 1) * sizeof(shiva_dwarf_loc_t));
                                            vars[var_count] = loc;
                                            var_count++;
                                        } else {
                                            free(loc.symname);
                                        }
                                        dwarf_dealloc(shiva_ctx.dwarf.debug, var_name, DW_DLA_STRING);
                                    }
                                    dwarf_dealloc(shiva_ctx.dwarf.debug, attr, DW_DLA_ATTR);
                                }
                            }
                            ret = dwarf_siblingof_b(shiva_ctx.dwarf.debug, child, true, &sibling, &err);
                            dwarf_dealloc(shiva_ctx.dwarf.debug, child, DW_DLA_DIE);
                            child = sibling;
                        }
                    }
                    dwarf_dealloc(shiva_ctx.dwarf.debug, func_die, DW_DLA_DIE);
                }

                push_cfun(DECL_STRUCT_FUNCTION(node->decl));

                gimple_seq body = gimple_body(node->decl);
                gimple_stmt_iterator gsi;

                FOR_EACH_BB_FN(bb, cfun) {
                    for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
                        gimple *stmt = gsi_stmt(gsi);

                        if (gimple_code(stmt) == GIMPLE_ASSIGN || gimple_code(stmt) == GIMPLE_COND) {
                            tree lhs = gimple_num_ops(stmt) > 1 ? gimple_op(stmt, 0) : NULL;
                            tree rhs = gimple_num_ops(stmt) > 1 ? gimple_op(stmt, 1) : NULL;

                            for (int i = 0; i < var_count; i++) {
                                // Handle LHS
                                if (lhs && TREE_CODE(lhs) == VAR_DECL && strcmp(IDENTIFIER_POINTER(DECL_NAME(lhs)), vars[i].symname) == 0) {
                                    if (vars[i].type == SHIVA_DWARF_LOC_STACK) {
                                        tree mem_ref = build2(MEM_REF, TREE_TYPE(lhs), build_int_cst(ptr_type_node, vars[i].stack_offset), build_int_cst(ptr_type_node, 0));
                                        gimple_set_op(stmt, 0, mem_ref);
                                    } else if (vars[i].type == SHIVA_DWARF_LOC_REG) {
                                        char asm_str[64];
                                        const char *reg_name = shiva_reg_names[vars[i].reg];
                                        snprintf(asm_str, sizeof(asm_str), "movl %%%s, %%eax", reg_name);
                                        gimple *asm_stmt = gimple_build_asm_vec(asm_str, NULL, NULL, NULL, NULL);
                                        gsi_insert_after(&gsi, asm_stmt, GSI_SAME_STMT);
                                        tree temp = create_tmp_var(TREE_TYPE(lhs), "temp");
                                        gimple_set_op(stmt, 0, temp);
                                    }
                                }
                                // Handle RHS (similar for rhs, ADDR_EXPR)
                                if (rhs && TREE_CODE(rhs) == VAR_DECL && strcmp(IDENTIFIER_POINTER(DECL_NAME(rhs)), vars[i].symname) == 0) {
                                    if (vars[i].type == SHIVA_DWARF_LOC_STACK) {
                                        tree mem_ref = build2(MEM_REF, TREE_TYPE(rhs), build_int_cst(ptr_type_node, vars[i].stack_offset), build_int_cst(ptr_type_node, 0));
                                        gimple_set_op(stmt, 1, mem_ref);
                                    } else if (vars[i].type == SHIVA_DWARF_LOC_REG) {
                                        char asm_str[64];
                                        const char *reg_name = shiva_reg_names[vars[i].reg];
                                        snprintf(asm_str, sizeof(asm_str), "movl %%%s, %%eax", reg_name);
                                        gimple *asm_stmt = gimple_build_asm_vec(asm_str, NULL, NULL, NULL, NULL);
                                        gsi_insert_after(&gsi, asm_stmt, GSI_SAME_STMT);
                                        tree temp = create_tmp_var(TREE_TYPE(rhs), "temp");
                                        gimple_set_op(stmt, 1, temp);
                                    }
                                }
                                // Handle ADDR_EXPR (similar, add your code)
                            }
                        }
                    }
                }

                // Register preservation at entry
                basic_block entry_bb = ENTRY_BLOCK_PTR_FOR_FN(cfun);
                gimple_seq prelude = NULL;
                gimple *push_rax = gimple_build_asm_vec("push %rax", NULL, NULL, NULL, NULL);
                gimple *push_rbx = gimple_build_asm_vec("push %rbx", NULL, NULL, NULL, NULL);
                gimple_seq_add_stmt(&prelude, push_rax);
                gimple_seq_add_stmt(&prelude, push_rbx);
                gimple_seq_add_seq(&entry_bb->il.gimple.seq, prelude);

                // Register restoration and jump at exit
                basic_block exit_bb = EXIT_BLOCK_PTR_FOR_FN(cfun);
                basic_block last_bb = exit_bb->prev_bb;
                gimple_seq postlude = NULL;
                gimple *pop_rbx = gimple_build_asm_vec("pop %rbx", NULL, NULL, NULL, NULL);
                gimple *pop_rax = gimple_build_asm_vec("pop %rax", NULL, NULL, NULL, NULL);
                char jmp_str[64];
                snprintf(jmp_str, sizeof(jmp_str), "jmp 0x%llx", (unsigned long long)extend_addr);
                gimple *jmp = gimple_build_asm_vec(jmp_str, NULL, NULL, NULL, NULL);
                gimple_seq_add_stmt(&postlude, pop_rbx);
                gimple_seq_add_stmt(&postlude, pop_rax);
                gimple_seq_add_stmt(&postlude, jmp);
                gimple_seq_add_seq(&last_bb->il.gimple.seq, postlude);

                pop_cfun();

                for (int i = 0; i < var_count; i++)
                    free(vars[i].symname);
                free(vars);
            }

            return 0;
        }

        virtual splice_pass *clone() override {
            return this;  /* No cloning needed for simple passes */
        }
    };
}  /* Anonymous namespace to avoid name clashes */
#if 0
/* Pass data for GIMPLE pass registration */
static struct gimple_opt_pass splice_pass_data = {
	.pass = {
		.type = GIMPLE_PASS,
		.name = "splice_pass",
		.gate = NULL,
		.execute = splice_gimple_pass,
		.sub = NULL,
		.next = NULL,
		.static_pass_number = 0
	}
};
#endif

#if 0

/* plugin_init - Initialize the GCC plugin
 *
 * Parameters:
 *	plugin_info: Plugin name and arguments
 *	version: GCC version information
 *
 * Returns: 0 on success
 */
int
plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
	global_plugin_info = plugin_info;
	parse_arguments();
	shiva_dwarf_init(&shiva_ctx); 

	struct register_pass_info pass_info = {
		.pass = &splice_pass_data,
		.reference_pass_name = "ssa",
		.ref_pass_instance_number = 1,
		.pos_op = PASS_POS_INSERT_AFTER
	};

	register_callback(plugin_info->base_name, PLUGIN_PASS_MANAGER_SETUP,
	    NULL, &pass_info);
	return 0;
}

#endif

__attribute__((visibility("default")))
int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version) {
    global_plugin_info = plugin_info;
    parse_arguments();
    shiva_dwarf_init(&shiva_ctx);

    /* Create the pass instance with new (required for C++ class) */
    struct register_pass_info pass_info;
    pass_info.pass = new splice_pass(g);

    pass_info.reference_pass_name = "ssa";
    pass_info.ref_pass_instance_number = 1;
    pass_info.pos_op = PASS_POS_INSERT_AFTER;

    register_callback(plugin_info->base_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &pass_info);

    return 0;
}
