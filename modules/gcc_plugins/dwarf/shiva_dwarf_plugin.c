#if 0
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Werror=implicit-function-declaration"
#pragma GCC diagnostic ignored "-Werror=undeclared-identifier"	 // may not exist, try without
#include "shiva.h"

#include <gcc-plugin.h>
#include <plugin-api.h>
#include <tree.h>
#include <tree-iterator.h>
#include <cgraph.h>
#include <gimple.h>
#include <gimple-iterator.h>
#include <tree-ssa.h>      /* provides add_referenced_var, update_stmt, etc. */
#include <tree-ssa-operands.h>
//#include <tree-into-ssa.h> /* sometimes needed for SSA name handling */
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
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Werror=implicit-function-declaration"

#define IN_GCC 1
#define IN_GCC_PLUGIN 1

#include "shiva.h"
#include "gcc-common.h"

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
#include <memmodel.h>
#include <rtl.h>
#include <emit-rtl.h>
#include <insn-codes.h>
#include <context.h>

/* Critical SSA headers in this order */
#include <tree-ssa.h>
#include <tree-ssa-operands.h>
#include <tree-ssa-alias.h>
#include <gimple-ssa.h>          /* often needed for full visibility */

#pragma GCC diagnostic pop

/* These two lines fix the "undefined symbol" at plugin load time on GCC 11 */
extern void add_referenced_var(tree var);
extern void update_stmt(gimple *stmt);

static const pass_data splice_pass_data_constructor = {
        GIMPLE_PASS,          /* type */
        "splice_pass",        /* name */
        OPTGROUP_NONE,        /* optinfo_flags */
        TV_NONE,              /* tv_id */
        PROP_cfg,             /* properties_required (minimal for GIMPLE passes) */
        0,                    /* properties_provided */
        0,                    /* properties_destroyed */
        0,                    /* todo_flags_start */
        0                     /* todo_flags_finish */
};

#if 0
namespace {
    class splice_pass : public gimple_opt_pass {
    public:
        splice_pass(gcc::context *ctxt)
            : gimple_opt_pass(splice_pass_data_constructor, ctxt) {}

        virtual unsigned int execute(function *fun) override;
    };
}
#endif
/* Nuclear option for GCC 11 - force the symbols */

//extern void add_referenced_var(tree);
//extern void update_stmt(gimple *);

#ifndef as_a_gasm
static inline gasm *
as_a_gasm(gimple *stmt)
{
    return (gasm *)stmt;  /* unchecked but safe for GIMPLE_ASM */
}
#endif


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

#include <string.h>   /* for strlen */

#include <string.h>   /* for strlen */

static vec<tree, va_gc> *
build_clobbers_vec (const char **clobber_names)
{
	vec<tree, va_gc> *clobbers = NULL;
	unsigned i;

	for (i = 0; clobber_names[i] != NULL; i++) {
		const char *name = clobber_names[i];
      
      		tree clobber = build_string_literal (strlen (name) + 1, name);
      		vec_safe_push (clobbers, clobber);
    	}
	return clobbers;
}

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
	shiva_debug("returning true!\n");
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
				shiva_debug("shiva_dwarf_resolve_die_location() sucessful!\n");
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
	fd = ctx->elfobj.fd;
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
	shiva_debug("elf_path: %s\n", elf_path);
}

namespace {
    class splice_pass : public gimple_opt_pass {
    public:
	splice_pass(gcc::context *ctxt)
	    : gimple_opt_pass(splice_pass_data_constructor, ctxt) {}

virtual unsigned int execute(function *fun) override
{
    struct cgraph_node *node;
    static char *processed_target = NULL;

    FOR_EACH_DEFINED_FUNCTION(node) {
        if (!gimple_has_body_p(node->decl))
            continue;

        const char *funcname = IDENTIFIER_POINTER(DECL_NAME(node->decl));

        if (strncmp(funcname, "__shiva_splice_fn_name_", 23) != 0)
            continue;

        const char *target_func = funcname + 23;

        if (processed_target && strcmp(target_func, processed_target) == 0) {
            shiva_debug("Target %s already processed, skipping\n", target_func);
            continue;
        }

        free(processed_target);
        processed_target = xstrdup(target_func);

        shiva_debug("Processing splice for target function: %s (at insert PC %#llx)\n",
                    target_func, (unsigned long long)insert_addr);

        /* Resolve variables via DWARF */
        shiva_dwarf_loc_t *vars = NULL;
        int var_count = 0;

        Dwarf_Die func_die = NULL;
        if (shiva_dwarf_find_function(shiva_ctx.dwarf.debug, target_func, &func_die)) {
            Dwarf_Die child = NULL, sibling = NULL;
            Dwarf_Error err;
            int ret = dwarf_child(func_die, &child, &err);

            while (ret == DW_DLV_OK && child != NULL) {
                Dwarf_Half tag;
                if (dwarf_tag(child, &tag, &err) == DW_DLV_OK &&
                    (tag == DW_TAG_variable || tag == DW_TAG_formal_parameter)) {

                    Dwarf_Attribute attr = NULL;
                    char *var_name = NULL;

                    if (dwarf_attr(child, DW_AT_name, &attr, &err) == DW_DLV_OK &&
                        dwarf_formstring(attr, &var_name, &err) == DW_DLV_OK) {

                        shiva_dwarf_loc_t loc = {0};
                        loc.symname = xstrdup(var_name);

                        if (shiva_dwarf_resolve_variable(&shiva_ctx, target_func,
                                                         var_name, insert_addr, &loc)) {
                            vars = (shiva_dwarf_loc_t *)xrealloc(vars,
                                        (var_count + 1) * sizeof(shiva_dwarf_loc_t));
                            vars[var_count++] = loc;
                            shiva_debug("Resolved '%s' -> type=%d reg=%d stack=%ld\n",
                                        var_name, loc.type, loc.reg, loc.stack_offset);
                        } else {
                            free(loc.symname);
                        }
                        dwarf_dealloc(shiva_ctx.dwarf.debug, var_name, DW_DLA_STRING);
                    }
                    if (attr)
                        dwarf_dealloc(shiva_ctx.dwarf.debug, attr, DW_DLA_ATTR);
                }

                ret = dwarf_siblingof_b(shiva_ctx.dwarf.debug, child, true, &sibling, &err);
                dwarf_dealloc(shiva_ctx.dwarf.debug, child, DW_DLA_DIE);
                child = sibling;
            }
            dwarf_dealloc(shiva_ctx.dwarf.debug, func_die, DW_DLA_DIE);
        }

        if (var_count == 0) {
            shiva_debug("No variables resolved for %s\n", target_func);
            free(vars);
            continue;
        }

        /* Rewrite the splice function */
        push_cfun(DECL_STRUCT_FUNCTION(node->decl));

        basic_block bb;
        FOR_EACH_BB_FN(bb, cfun) {
            gimple_stmt_iterator gsi;
            for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
                gimple *stmt = gsi_stmt(gsi);
                bool stmt_modified = false;

                tree lhs = NULL, rhs = NULL;
                if (gimple_code(stmt) == GIMPLE_ASSIGN) {
                    lhs = gimple_assign_lhs(stmt);
                    rhs = gimple_assign_rhs1(stmt);
                }

                for (int i = 0; i < var_count; i++) {
                    const char *vname = vars[i].symname;
                    tree *targets[2] = { &lhs, &rhs };

                    for (int t = 0; t < 2; t++) {
                        tree *tp = targets[t];
                        if (!*tp || TREE_CODE(*tp) != VAR_DECL)
                            continue;

                        if (strcmp(IDENTIFIER_POINTER(DECL_NAME(*tp)), vname) != 0)
                            continue;

                        shiva_debug("Rewriting reference to '%s'\n", vname);

                        if (vars[i].type == SHIVA_DWARF_LOC_STACK) {
                            /* MEM_REF using approximate frame base */
                            tree offset = build_int_cst(sizetype, vars[i].stack_offset);
                            tree frame = build_fold_addr_expr(cfun->decl);  // better than before
                            tree mem_ref = build2(MEM_REF, TREE_TYPE(*tp), frame, offset);
                            TREE_TYPE(mem_ref) = TREE_TYPE(*tp);
                            *tp = mem_ref;
                            stmt_modified = true;

                        } else if (vars[i].type == SHIVA_DWARF_LOC_REG) {
                            tree temp = create_tmp_var(TREE_TYPE(*tp), "shiva_reg");
                            add_referenced_var(temp);

                            char asm_str[64];
                            snprintf(asm_str, sizeof(asm_str), "mov %%%s, %%%s",
                                     shiva_reg_names[vars[i].reg],
                                     shiva_reg_names[0]);   // rax for now

                            const char *clobbers[] = {shiva_reg_names[0], "memory", NULL};
                            vec<tree, va_gc> *clobber_vec = build_clobbers_vec(clobbers);

                            gimple *asm_stmt = gimple_build_asm_vec(asm_str, NULL, NULL,
                                                                    clobber_vec, NULL);
                            gimple_asm_set_volatile(as_a_gasm(asm_stmt), true);

                            gsi_insert_before(&gsi, asm_stmt, GSI_SAME_STMT);

                            *tp = temp;
                            stmt_modified = true;
                        }
                    }
                }

                if (stmt_modified)
                    update_stmt(stmt);
            }
        }

        pop_cfun();

        /* Cleanup */
        for (int i = 0; i < var_count; i++)
            free(vars[i].symname);
        free(vars);
    }

    return 0;
}
};
}
#if 0
	virtual unsigned int execute(function *) override {
	    // original splice_gimple_pass logic goes here (the entire body)
	    // Iterate over cgraph nodes, DWARF resolution, GIMPLE rewriting, etc.
	    // Return 0 on success
		struct cgraph_node *node;
		basic_block bb;
		static char *processed_target = NULL;

		FOR_EACH_DEFINED_FUNCTION(node) {
			shiva_debug("Iterating over function\n");
			if (!gimple_has_body_p(node->decl))
				continue;

			const char *funcname = IDENTIFIER_POINTER(DECL_NAME(node->decl));

			if (strncmp(funcname, "__shiva_splice_fn_name_", 23) != 0)
				continue;

			const char *target_func = funcname + 23;
			if (processed_target && strcmp(target_func, processed_target) == 0) {
				shiva_debug("Target %s already processed\n", target_func);
				continue;
			}
			
			free(processed_target);
			processed_target = xstrdup(target_func);

			shiva_dwarf_loc_t *vars = NULL;
			int var_count = 0;
			Dwarf_Die func_die = NULL;
			char *var_name = NULL;

			if (shiva_dwarf_find_function(shiva_ctx.dwarf.debug, target_func, &func_die)) {
				Dwarf_Die child = NULL, sibling = NULL;
				Dwarf_Error err;
		    
				int ret = dwarf_child(func_die, &child, &err);
				shiva_dwarf_loc_t loc = {0};
				if (ret == DW_DLV_OK) {
					while (child != NULL) {
						Dwarf_Half tag;

						if (dwarf_tag(child, &tag, &err) == DW_DLV_OK &&
						    (tag == DW_TAG_variable || tag == DW_TAG_formal_parameter)) {
							Dwarf_Attribute attr;

							if (dwarf_attr(child, DW_AT_name, &attr, &err) == DW_DLV_OK) {
								if (dwarf_formstring(attr, &var_name, &err) == DW_DLV_OK) {

									loc.symname = xstrdup(var_name);

									if (shiva_dwarf_resolve_variable(&shiva_ctx, target_func, var_name, insert_addr, &loc)) {
										vars = (shiva_dwarf_loc_t *)xrealloc(vars, (var_count + 1) * sizeof(shiva_dwarf_loc_t));
										vars[var_count] = loc;
										var_count++;
										shiva_debug("Sucessfully located %s at %#lx\n", var_name, insert_addr);
									} else {
										free(loc.symname);
									}
									dwarf_dealloc(shiva_ctx.dwarf.debug, var_name, DW_DLA_STRING);
								}
								dwarf_dealloc(shiva_ctx.dwarf.debug, attr, DW_DLA_ATTR);
							}
						}
						shiva_debug("calling dwarf_siblinfof, var_name: %s\n", loc.symname);
						ret = dwarf_siblingof_b(shiva_ctx.dwarf.debug, child, false, &sibling, &err);
						shiva_debug("siblingof_b returned ret=%d (DW_DLV_OK=0, NO_ENTRY=-1, ERROR=1), "
						    "old child DIE ptr=%p, new sibling DIE ptr=%p, var_name=%s\n",
						    ret, (void*)child, (void*)sibling,
						    var_name ? var_name : "<no name>");

						if (ret != DW_DLV_OK) {
							shiva_debug("Breaking loop - no more siblings or error\n");
							break;	// add this if not already present
						}
						dwarf_dealloc(shiva_ctx.dwarf.debug, child, DW_DLA_DIE);
						child = sibling;
					}
				}
				dwarf_dealloc(shiva_ctx.dwarf.debug, func_die, DW_DLA_DIE);
				shiva_debug("Did we get here?\n");
			}

			push_cfun(DECL_STRUCT_FUNCTION(node->decl));

			gimple_seq body = gimple_body(node->decl);
			gimple_stmt_iterator gsi;
			vec<tree, va_gc> *clobbers;
			FOR_EACH_BB_FN(bb, cfun) {
				for (gsi = gsi_start_bb(bb); !gsi_end_p(gsi); gsi_next(&gsi)) {
					gimple *stmt = gsi_stmt(gsi);
					if (gimple_code(stmt) == GIMPLE_ASSIGN || gimple_code(stmt) == GIMPLE_COND) {
					tree lhs = gimple_num_ops(stmt) > 1 ? gimple_op(stmt, 0) : NULL;
					tree rhs = gimple_num_ops(stmt) > 1 ? gimple_op(stmt, 1) : NULL;

					for (int i = 0; i < var_count; i++) {
						if (lhs && TREE_CODE(lhs) == VAR_DECL && strcmp(IDENTIFIER_POINTER(DECL_NAME(lhs)), vars[i].symname) == 0) {
							if (vars[i].type == SHIVA_DWARF_LOC_STACK) {
								tree mem_ref = build2(MEM_REF, TREE_TYPE(lhs), build_int_cst(ptr_type_node, vars[i].stack_offset), build_int_cst(ptr_type_node, 0));
								gimple_set_op(stmt, 0, mem_ref);
							} else if (vars[i].type == SHIVA_DWARF_LOC_REG) {
								char asm_str[64];
								const char *reg_name = shiva_reg_names[vars[i].reg];
								snprintf(asm_str, sizeof(asm_str), "movl %%%s, %%eax", reg_name);
								const char *clobbers_mov_eax[] = {"eax", "memory", NULL};
								clobbers = build_clobbers_vec(clobbers_mov_eax);
								gimple *asm_stmt = gimple_build_asm_vec(asm_str, NULL, NULL, clobbers, NULL);
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
								const char *clobbers_mov_eax2[] = {"eax", "memory", NULL};
								clobbers = build_clobbers_vec(clobbers_mov_eax2);
								gimple *asm_stmt = gimple_build_asm_vec(asm_str, NULL, NULL, clobbers, NULL);
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
#if 0
		gimple_seq prelude = NULL;
		
		const char *clobbers_push_rax[] = { "rax", "memory", NULL };
		
		clobbers = build_clobbers_vec(clobbers_push_rax);
		gimple *push_rax = gimple_build_asm_vec("push %rax", NULL, NULL, clobbers, NULL);
		gasm *push_rax_g = as_a_gasm(push_rax);
		gimple_asm_set_volatile(push_rax_g, true);

		const char *clobbers_push_rbx[] = {"rbx", "memory", NULL};
		
		clobbers = build_clobbers_vec(clobbers_push_rbx);
		gimple *push_rbx = gimple_build_asm_vec("push %rbx", NULL, NULL, clobbers, NULL);
		gasm *push_rbx_g = as_a_gasm(push_rbx);
		gimple_asm_set_volatile(push_rbx_g, true);

		gimple_seq_add_stmt(&prelude, push_rax);
		gimple_seq_add_stmt(&prelude, push_rbx);
		gimple_seq_add_seq(&entry_bb->il.gimple.seq, prelude);

		// Register restoration and jump at exit
		basic_block exit_bb = EXIT_BLOCK_PTR_FOR_FN(cfun);
		basic_block last_bb = exit_bb->prev_bb;
		gimple_seq postlude = NULL;
		const char *clobbers_pop_rbx[] = {"rbx", "memory", NULL};

		clobbers = build_clobbers_vec(clobbers_pop_rbx);
		gimple *pop_rbx = gimple_build_asm_vec("pop %rbx", NULL, NULL, clobbers, NULL);
		gasm *pop_rbx_g = as_a_gasm(pop_rbx);
		gimple_asm_set_volatile(pop_rbx_g, true);

		const char *clobbers_pop_rax[] = {"rax", "memory", NULL};
		clobbers = build_clobbers_vec(clobbers_pop_rax);
		gimple *pop_rax = gimple_build_asm_vec("pop %rax", NULL, NULL, clobbers, NULL);
		gimple_seq_add_stmt(&postlude, pop_rbx);
		gimple_seq_add_stmt(&postlude, pop_rax);
		gimple_seq_add_seq(&last_bb->il.gimple.seq, postlude);

		pop_cfun();
#endif
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
#endif
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

	shiva_debug("Callback registered\n");
	register_callback(plugin_info->base_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &pass_info);

    return 0;
}
/* Force export of the symbols that cc1 needs */
__attribute__((visibility("default")))
void __shiva_force_symbols(void) {
    (void)add_referenced_var;
    (void)update_stmt;
}
#pragma CC diagnostic pop

