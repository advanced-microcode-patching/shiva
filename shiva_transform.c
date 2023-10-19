#include "shiva.h"
#if __aarch64__
#include "shiva_aarch64.h"
#endif

#define COPY_FIRST_HALF		0
#define COPY_SECOND_HALF	2
#define COPY_TF_SOURCE		3

#define ARM_INSN_LEN 4
#define AARCH64_NOP 0xd503201f

/*
 * Example of function transformation on foo() in some target executable.
 *
 * Tranformed version of foo():
 * 
 * 1. First we copy the new function into place with it's spliced
 * code.
 * 2. Next we relink the first half and second half of the code (Avoiding the spliced in code)
 * 3. Down the road aways when relocations are handled, the spliced code will be properly fixed up
 * by the module relocator.
 *
 * .text
 * int foo(void) {
 * [original code] <- shiva_transform.c:shiva_tf_relink_new_func()
 * [spliced code ] <- shiva_module.c:apply_relocation()
 * [original code] <- shiva_transform.c:shiva_tf_relink_new_func()
 * }
 */
/*
 * shiva_tf_splice_function_extend
 * Copy the function that is being transformed into a new location
 * while splicing the transform source (The patch) into place.
 * If the original byte-code is smaller than the patch, then we overwrite
 * the original code and then extend from that offset to make room for the
 * rest of the patch.
 *
 * The patch code is relocatable, and will be properly relocated by apply_relocation().
 * The code before and after the patch insertion may also need to be relinked due to
 * offsets changing.
 */
static bool
shiva_tf_splice_function_extend(struct shiva_module *linker, struct shiva_transform *transform,
    uint8_t *dst)
{
	/*
	 * Destination function
	 */
	uint8_t *dest = dst;
	/*
	 * Source function
	 */
	uint8_t *source = (uint8_t *)transform->target_symbol.value + linker->target_base;
	size_t copy_len;
	uint64_t src_tf_offset = transform->offset;

	/*
	 * Step 1 Inject first half
	 * Copy first half of function into module image.
	 */
	copy_len = transform->offset;

	shiva_debug("COPY_FIRST_HALF: dest:%p, source:%p, len:%zu\n",
	    dest, source, copy_len);
	memcpy(dest, source, copy_len);
	transform->splice.copy_len1 = copy_len;

	test_mark();
	/* Step 2. Inject patch code. If the patch code is larger
	 * than the original code, then extend.
	 * Copy the patch code (Transform source) into the correct
	 * offset (transform->offset to be exact) of the new function.
	 */
	copy_len = transform->new_len;
	source = transform->ptr;
	shiva_debug("note: transform_offset: %#zu\n", transform->offset);
	shiva_debug("COPY_TF_SOURCE: dest:%#lx, source:%#lx, len:%zu\n",
	    dest + transform->offset, source, copy_len);
	/*
	 * attribute((naked)) does not work with gcc aarch64.
	 * Our patch functions are compiled with a 4 byte prologue
	 * that we must NOP out. As well as an 8 byte epilogue.
	 */
#ifdef __aarch64__
	*(uint32_t *)&transform->ptr[0] = AARCH64_NOP;
	*(uint32_t *)&transform->ptr[transform->new_len - 4] = AARCH64_NOP;
	*(uint32_t *)&transform->ptr[transform->new_len - 8] = AARCH64_NOP;
#endif
	memcpy(dest + transform->offset, transform->ptr, copy_len);
	transform->splice.copy_len2 = copy_len;

	test_mark();

	/*
	 * Step 3. Inject last half of function
	 * Copy the second half of the original function
	 * into place after the patch code.
	 */
	source = (uint8_t *)transform->target_symbol.value + linker->target_base;
	copy_len = transform->target_symbol.value + transform->target_symbol.size;
	copy_len = copy_len - (transform->target_symbol.value + transform->offset + transform->old_len);
	shiva_debug("COPY_SECOND_HALF: dest:%#lx, source:%#lx, len:%zu\n",
	    dest + transform->offset + transform->new_len,
	    source + transform->offset + transform->old_len, copy_len);
	if (transform->flags & SHIVA_TRANSFORM_F_INJECT) {
		/*
		 * A caveat when dealing with the INJECT flag.
		 * XXX don't commit until we can garantee this
		 * is the best solution.
		 */
		//src_tf_offset = transform->offset - ARM_INSN_LEN;
	}
	memcpy(dest + transform->offset + transform->new_len,
	    source + transform->offset + transform->old_len, copy_len);
	transform->splice.copy_len3 = copy_len;

	test_mark();
	/*
	 * Step 4. Create an extended area at the end of the function
	 * containing .text read-only data. The data stored here
	 * are typically read-only addresses that are referenced
	 * indirectly. Shiva fixes up these areas at runtime via
	 * ELF relocations, such as ADR_PREL_PG_HI21/ADD_ABS_LO12_NC
	 * To be more specific this area is for read-only data that
	 * normally exists within the .text right after a function
	 * in a relocatable object. This extended read-only data
	 * area that lives at the end of a function.
	 * In our specific case, the function is a transform source;
	 * that is code that is to be spliced into the program.
	 * At the end of our transform source function, i.e.
	 * __shiva_tf_splice_fn_foo(), there will exist some data
	 * encoded into the .text used by various instructions like
	 * adrp, and add. When we splice the source function (The patch) in with
	 * the target function, we will have to move this read-only .text
	 * to the end of the final spliced function. The relocations
	 * r_addend fields will have to be increased by:
	 * transform->splice.copy_len3 bytes
	 *
	 * foo() function layout after step 4
	 * 1. [first_half ]
	 * 2. [patch_code ]
	 * 3. [second_half]
	 * 4. [.text encoded values]
	 */
	shiva_debug("COPY_IN_TEXT_ENCDODINGS: dest:%#lx, source: %#lx, len: %zu\n",
	    dest + transform->offset + transform->new_len + transform->splice.copy_len3,
	    &transform->ptr[transform->source_symbol.size],
	    transform->ext_len);
	memcpy(dest + transform->offset + transform->new_len + transform->splice.copy_len3,
	    &transform->ptr[transform->source_symbol.size],
	    transform->ext_len);
	test_mark();
	return true;
}

/*
 * Thank you Humbly to the software engineers of GDB (particularly aarch64
 * remotely simulated relocations in the GDB server for aarch64).
 * Their code helped to shed some light on re-encoding the branches.
 */
#define BRANCH_IS_LOCAL(addr) \
	(addr >= branch->current_function.value && \
	 addr < branch->current_function.value + branch->current_function.size)

#define BRANCH_LINK (1UL << 0)
#define RELOC_MASK(n)	((1U << n) - 1)

#define submask(x) ((1L << ((x) + 1)) - 1)
#define bits(obj,st,fn) (((obj) >> (st)) & submask ((fn) - (st)))
#define bit(obj,st) (((obj) >> (st)) & 1)
#define sbits(obj,st,fn) \
  ((long) (bits(obj,st,fn) | ((long) bit(obj,fn) * ~ submask (fn - st))))

/*
 * XXX SECURITY ISSUES XXX
 * Due to earlier design decisions, it's not clean to have 'shiva_ctx *ctx' passed
 * to this function, therefore we are using 'struct shiva_ctx *ctx_global' which is
 * a data segment variable that always points to the shiva ctx towards the top of
 * the stack.
 *
 * We should probably remove ctx_global all together, atleast in this version of
 * Shiva. It has some uses in the x86 version, but its dangerous and gives attackers
 * a pointer to damn near the top of the stack. If /lib/shiva was PIE on aarch64
 * it wouldn't matter so much, but its an ET_EXEC, so this ctx_global variable
 * is predictable, and therefore makes the stack predictable.
 *
 */
static bool
shiva_tf_relink_xref(struct shiva_module *linker, struct shiva_transform *transform,
    struct shiva_xref_site *xref)
{
	bool res;
	shiva_error_t error;
	uint32_t n_adrp_insn;
	uint32_t n_add_insn;
	uint32_t n_ldr_insn;
	uint32_t n_str_insn;
	int32_t rel_val, xoffset;
	uint64_t rel_addr, adrp_off;
	uint8_t *rel_unit;

	shiva_debug("ctx_global: %p\n", ctx_global);

	assert(xref->adrp_site >= transform->target_symbol.value &&
	    xref->adrp_site < transform->target_symbol.value + transform->target_symbol.size);

	/*
	 * we get the offset of an adrp instruction from beginning of the
	 * transformed function. This offset can change if the transform
	 * new_len is > than old_len.
	 */
	adrp_off = xref->adrp_site - transform->target_symbol.value;
	shiva_debug("Adrp offset: %#lx\n", adrp_off);
	if (adrp_off > transform->offset + transform->old_len)
		adrp_off += transform->new_len - transform->old_len;
	rel_addr = linker->text_vaddr + transform->segment_offset + adrp_off;

	shiva_debug("Symbol name: %s\n", xref->symbol.name);
	shiva_debug("Source sym: %s\n", xref->current_function.name);
	shiva_debug("Target symbol addr: %#lx\n", linker->target_base + xref->symbol.value);
	xoffset = rel_val = (int32_t)
	    (ELF_PAGESTART(linker->target_base + xref->symbol.value) - ELF_PAGESTART(rel_addr));
	shiva_debug("rel_val = %#lx - %#lx = %#lx\n", ELF_PAGESTART(linker->target_base + xref->symbol.value),
	    ELF_PAGESTART(rel_addr), rel_val);
	rel_val >>= 12;

	shiva_debug("rel_addr: %#lx\n", rel_addr);
	shiva_debug("rel_val: %#lx\n", rel_val);

	n_adrp_insn = xref->adrp_o_insn & 0xffffffff;
	n_adrp_insn = (n_adrp_insn & ~((RELOC_MASK (2) << 29) | (RELOC_MASK(19) << 5)))
	    | ((rel_val & RELOC_MASK(2)) << 29) | ((rel_val & (RELOC_MASK(19) << 2)) << 3);
	rel_unit = (uint8_t *)rel_addr;
	memcpy(rel_unit, &n_adrp_insn, 4);

	/*
	 * We are relinking a transformed function's adrp
	 * It is not necessarily to update the offset in the
	 * subsequent add/ldr/str instruction, because the
	 * target address lives in the executable, and the
	 * add/ldr/str offset will be fixed from there.
	 *
	 * In other scenarios, where we are relinking an
	 * adrp to a completely new variable, we do have
	 * to update the offset for the subsequent add/ldr/str.
	 */
#if 0
	switch(xref->type) {
	case SHIVA_XREF_TYPE_UNKNOWN:
		return false;
	case SHIVA_XREF_TYPE_ADRP_ADD:
		rel_unit = (uint8_t *)rel_addr;
		shiva_debug("Installing SHIVA_XREF_TYPE_ADRP_ADD patch at %#lx to link symbol %s\n",
		    rel_addr, xref->symbol.name);
		memcpy(rel_unit, &n_adrp_insn, 4);
#if 0
		shiva_trace_write() cannot work here because it relies on shiva_maps_prot_by_addr()
		which cannot find the memory mapping entry for the address we need to write
		at: (void *)rel_unit. In the future I will fix this so that shiva_trace_write()
		can work. Meanwhile, we will do this manually.

		res = shiva_trace_write(ctx_global, 0, (void *)rel_unit,
		    (void *)&n_adrp_insn, 4, &error);
		if (res == false) {
			fprintf(stderr, "shiva_trace_write failed: %s\n", shiva_error_msg(&error));
			return false;
		}
#endif
		rel_val = xref->symbol.value;
		shiva_debug("Add offset: %#lx\n", rel_val);
		n_add_insn = xref->next_o_insn;
		n_add_insn = (n_add_insn & ~(RELOC_MASK(12) << 10)) | ((rel_val & RELOC_MASK(12)) << 10);

		rel_unit += sizeof(uint32_t);
#if 0
XXX TODO
		This function cannot work here because it relies on shiva_maps_prot_by_addr()
		which cannot find the memory mapping entry for the address we need to write
		at: (void *)rel_unit. In the future I will fix this so that shiva_trace_write()
		can work. Meanwhile, we will do this manually.

		res = shiva_trace_write(ctx_global, 0, (void *)rel_unit,
		    (void *)&n_add_insn, 4, &error);
		if (res == false) {
			fprintf(stderr, "shiva_trace_write failed: %s\n", shiva_error_msg(&error));
			return false;
		}
#endif
		memcpy(rel_unit, &n_add_insn, sizeof(uint32_t));
		break;
	case SHIVA_XREF_TYPE_ADRP_LDR:
		//rel_unit = (uint8_t *)rel_addr;
		//rel_val = transform->target_symbol.value;
		shiva_debug("Installing SHIVA_XREF_TYPE_ADRP_LDR patch at %#lx\n",
		    xref->adrp_site + linker->target_base);
		shiva_debug("SHIVA_XREF_TYPE_ADRP_LDR not yet supported\n");
		assert(true);
		break;
	}
#endif
	return true;

}

static bool
shiva_tf_relink_global_branch(struct shiva_module *linker, struct shiva_transform *transform,
    struct shiva_branch_site *branch)
{
	/*
	 * Offset to branch instruction (Within our new transformed version of the function)
	 */
	size_t br_off = branch->branch_site - transform->target_symbol.value;
	shiva_debug("br_off = %lx - %lx = %#lx\n", branch->branch_site, transform->target_symbol.value,
	    br_off);
	/*
	 * mem points to the branch instruction within the new location of the
	 * spliced/transformed function.
	 */
	if (br_off > transform->offset + transform->old_len)
		br_off += transform->new_len - transform->old_len;
	uint8_t *mem = &linker->text_mem[transform->segment_offset + br_off];

	/*
	 * 32bit width instruction
	 */
	uint32_t raw_insn = *(uint32_t *)mem;
	uint64_t br_flag = 0;

	uint64_t decoded_offset, target_vaddr;
	uint64_t new_offset;

	shiva_debug("insn_string: %s\n", branch->insn_string);
	shiva_debug("insn: %#lx\n", raw_insn);
	if (strncmp(branch->insn_string, "bl ", 3) == 0) {

		if (branch->branch_flags & SHIVA_BRANCH_F_PLTCALL) {
			shiva_debug("plt call to %s\n", branch->symbol.name);
		} else {
			shiva_debug("local call to %s\n", branch->symbol.name);
		}
		decoded_offset = sbits(raw_insn, 0, 25) << 2;
		target_vaddr = linker->target_base + branch->branch_site + decoded_offset;
		shiva_debug("Target vaddr: %#lx\n", target_vaddr);
		new_offset = (target_vaddr - (linker->text_vaddr + transform->segment_offset + br_off)) >> 2;
		raw_insn = (raw_insn & ~RELOC_MASK(26)) | (new_offset & RELOC_MASK(26));
		*(uint32_t *)mem = raw_insn;

		shiva_debug("Relinking branch %s to %#lx. Old offset: %#lx New offset: %#lx\n",
		    branch->insn_string, target_vaddr, decoded_offset, new_offset);
		return true;
	}
	shiva_debug("No bl instruction found\n");
	return false;
}

static bool
shiva_tf_relink_local_branch(struct shiva_module *linker, struct shiva_transform *transform,
    struct shiva_branch_site *branch, ssize_t delta)
{
	/*
	 * Offset to branch instruction
	 */
	size_t br_off = branch->branch_site - transform->target_symbol.value;
	shiva_debug("br_off = %lx - %lx = %#lx\n", branch->branch_site, transform->target_symbol.value,
	    br_off);
	/*
	 * mem points to the branch instruction within the new location of the
	 * spliced/transformed function.
	 */
	if (br_off > transform->offset + transform->old_len)
		br_off += transform->new_len - transform->old_len;
	uint8_t *mem = &linker->text_mem[transform->segment_offset + br_off];

	/*
	 * 32bit ARM instruction
	 */
	uint32_t raw_insn = *(uint32_t *)mem;
	uint64_t br_flag = 0;
	uint64_t decoded_offset;
	uint64_t o_target_vaddr, n_target_vaddr;
	uint32_t br_cond, is64, rn, rt, bit;
	uint32_t is_cbnz = 0, is_tbnz = 0;

	shiva_debug("Decoding raw insn: %#x (%s)\n", raw_insn, branch->insn_string);
	/*
	 * DECODE/RELINK INSTRUCTION: b / bl
	 *
	 * b  0001 01ii iiii iiii iiii iiii iiii iiii
	 * bl 1001 01ii iiii iiii iiii iiii iiii iiii
	 */
	if (((raw_insn & 0x7e000000) == 0x94000000) ||
	    ((raw_insn & 0x7e000000) == 0x14000000)) {
		shiva_debug("decoding b/bl\n");
		br_flag |= (raw_insn >> 31) & 0x1 ? BRANCH_LINK : 0;
		decoded_offset = sbits(raw_insn, 0, 25) << 2;
		o_target_vaddr = branch->branch_site + decoded_offset - 4;
		n_target_vaddr = linker->text_vaddr + transform->segment_offset 
		    + br_off + decoded_offset - 4;
		shiva_debug("Relinking branch %s. Old offset: %#lx New offset: %#lx\n",
		    branch->insn_string, decoded_offset, decoded_offset + delta);
		shiva_aarch64_emit_b(mem, br_flag & BRANCH_LINK, decoded_offset + delta);
	/*
	 * DECODE/RELINK INSRUCTION b
	 * Not sure why the imm branch instructions are not encoded
	 * as in the specs... The above code only seems to work for
	 * bl instructions, but according to the spec it should work
	 * wit b instructions also. However they seem to be encoded
	 * differently.
	 */
	} else if ((raw_insn & 0x7e000000) == 0x16000000) {
		shiva_debug("decoding b\n");
		decoded_offset = sbits(raw_insn, 0, 25) << 2;
		o_target_vaddr = branch->branch_site + decoded_offset - 4;
		n_target_vaddr = linker->text_vaddr + transform->segment_offset
		    + br_off + decoded_offset - 4;
		shiva_debug("Relinking branch %s. Old offset: %#lx New offset: %#lx\n",
		    branch->insn_string, decoded_offset, decoded_offset + delta);
		shiva_aarch64_emit_b2(mem, decoded_offset + delta);
	/*
	 * DECODE/RELINK INSTRUCTION: b.cond
	 */
	 /* b.cond  0101 0100 iiii iiii iiii iiii iii0 cccc */
	} else if ((raw_insn & 0xff000010) == 0x54000000) {
		shiva_debug("decoding b.cond\n");
		br_cond = raw_insn & 0xf;
		decoded_offset = sbits(raw_insn, 5, 23) << 2;
		o_target_vaddr = branch->branch_site + decoded_offset - 4;
		n_target_vaddr = linker->text_vaddr + transform->segment_offset
		    + br_off + decoded_offset - 4;
		shiva_debug("Relinking branch %s (br_cond: %d). Old offset: %#lx New offset: %#lx\n",
		    branch->insn_string, br_cond, decoded_offset, decoded_offset + delta);
		shiva_aarch64_emit_bcond(mem, br_cond, decoded_offset + delta);
	/*
	 * DECODE/RELINK INSTRUCTION: cbz/cbnz
	 *  cbz  T011 010o iiii iiii iiii iiii iiir rrrr
	 *  cbnz T011 010o iiii iiii iiii iiii iiir rrrr
	 */
	} else if ((raw_insn & 0x7e000000) == 0x34000000) {
		shiva_debug("decoding cbz/cbnz\n");
		decoded_offset = sbits(raw_insn, 5, 23) << 2;
		rn = (raw_insn >> 0) & 0x1f;
		is64 = (raw_insn >> 31) & 0x1;
		is_cbnz = (raw_insn >> 24) & 0x1;
		o_target_vaddr = branch->branch_site + decoded_offset - 4;
		n_target_vaddr = linker->text_vaddr + transform->segment_offset
		    + br_off + decoded_offset - 4;
		shiva_debug("Relinking branch %s. Old offset: %#lx New offset: %#lx\n",
		    branch->insn_string, decoded_offset, decoded_offset + delta);
		shiva_aarch64_emit_cb(mem, is_cbnz, rn, is64, decoded_offset + delta);
	/*
	 * DECODE/RELINK INSTRUCTION: tbz/tbnz
	 * tbz	b011 0110 bbbb biii iiii iiii iiir rrrr
	 * tbnz B011 0111 bbbb biii iiii iiii iiir rrrr
	 */
	} else if ((raw_insn & 0x7e000000) == 0x36000000) {
		shiva_debug("decoding tbz/tbnz\n");
		decoded_offset = sbits(raw_insn, 5, 18) << 2;
		rt = (raw_insn >> 0) & 0x1f;
		is_tbnz = (raw_insn >> 24) & 0x1;
		bit = ((raw_insn >> (31 - 4)) & 0x20) | ((raw_insn >> 19) & 0x1f);
		o_target_vaddr = branch->branch_site + decoded_offset - 4;
		n_target_vaddr = linker->text_vaddr + transform->segment_offset
		    + br_off + decoded_offset - 4;
		shiva_debug("Relinking branch %s. Old offset: %#lx New offset: %#lx\n",
		    branch->insn_string, decoded_offset, decoded_offset + delta);
		shiva_aarch64_emit_tb(mem, is_tbnz, bit, rt, decoded_offset + delta);
	} else {
		fprintf(stderr, "Failed to decode branch instruction for %s\n",
		    branch->insn_string);
		return false;
	}
	shiva_debug("Returning true\n");
	return true;
}

static bool
shiva_tf_relink_new_func(struct shiva_module *linker,
    struct shiva_transform *transform)
{
	uint8_t *code_ptr;
	struct shiva_branch_site *branch;
	struct shiva_xref_site *xref;
	ssize_t delta;
	bool res;

	/*
	 * Local branches (i.e. jmp's) and global branches (i.e. calls)
	 * must be re-linked.
	 */
	TAILQ_FOREACH(branch, &transform->branch_list, _linkage) {
		if ((transform->flags & SHIVA_TRANSFORM_F_EXTEND) == 0)
			continue;
		/*
		 * Relink positive offsets that link to code
		 * after the splice insertion, from code before
		 * the splice insertion.
		 */
		shiva_debug("Processing transform branch: %#lx:%s\n", branch->branch_site,
		    branch->insn_string);

		if (BRANCH_IS_LOCAL(branch->target_vaddr)) {
			shiva_debug("Processing local branch: %#lx:%s\n", branch->branch_site,
			    branch->insn_string);
			shiva_debug("Is branch_site %#lx < %#lx\n", branch->branch_site, transform->target_symbol.value +
			    transform->offset);
			 if ((branch->branch_site < transform->target_symbol.value + transform->offset) &&
			    branch->target_vaddr > transform->target_symbol.value + transform->offset) {
				delta = transform->new_len - transform->old_len;
				shiva_debug("Calling shiva_tf_relink_local_branch with delta %zd\n", delta);
				res = shiva_tf_relink_local_branch(linker,
				    transform, branch, delta);
				if (res == false) {
					fprintf(stderr,
					    "shiva_tf_relink_local_branch() failed\n");
					return false;
				}
			} else if ((branch->branch_site > transform->target_symbol.value +
				transform->offset + transform->old_len) &&
				branch->target_vaddr < transform->target_symbol.value + transform->offset) {
				delta = transform->new_len - transform->old_len;
				shiva_debug("Calling shiva_tf_relink_local_branch (Backwards) with delta: %d\n", -delta);
				res = shiva_tf_relink_local_branch(linker,
				    transform, branch, -delta);
				if (res == false) {
					fprintf(stderr,
					    "shiva_tf_relink_local_branch() failed\n");
					return false;
				}
			}
		} else if ((branch->branch_site < transform->target_symbol.value + transform->offset) ||
			    (branch->branch_site > transform->target_symbol.value  + transform->offset + transform->old_len)) {
			shiva_debug("Calling shiva_tf_relink_global_branch\n");
			res = shiva_tf_relink_global_branch(linker,
			    transform, branch);
			if (res == false) {
				fprintf(stderr,
				    "shiva_tf_relink_global_branch() failed\n");
				return false;
			}
		}
	}

	/*
	 * Relink xrefs: instruction pairs such as 'adrp/add'
	 * are used to reference data. Now that our function has
	 * been transformed in a totally new memory location we
	 * must re-link any references to variables with the
	 * correct offsets, etc.
	 */
	TAILQ_FOREACH(xref, &transform->xref_list, _linkage) {
		if ((xref->adrp_site < transform->target_symbol.value + transform->offset) ||
		    (xref->adrp_site >= transform->target_symbol.value + transform->offset + transform->old_len)) {
			res = shiva_tf_relink_xref(linker, transform, xref);
			if (res == false) {
				fprintf(stderr,
				    "shiva_tf_relink_xrefs() failed\n");
				return false;
			}
		}
	}
	return true;
}
/*
 * NOTE to self! Don't forget to update the modules relocation entries
 * for code and data that has been shifted forward due to splicing.
 * In other words r_offset is updated and r_addend must be updated
 * accordingly.
 */
#define ARM_INSN_LEN 4

bool
shiva_tf_process_transforms(struct shiva_module *linker, uint8_t *dst,
    struct elf_section section, uint64_t *segment_offset)
{
	uint8_t *ptr;
	bool res = false;
	struct shiva_transform *transform;
	elf_symtab_iterator_t symtab;
	struct elf_symbol symbol;

	TAILQ_FOREACH(transform, &linker->tailq.transform_list, _linkage) {
		switch(transform->type) {
		case SHIVA_TRANSFORM_SPLICE_FUNCTION:
			shiva_debug("Calling shiva_tf_splice_function\n");
			shiva_debug("Transform offset: %#lx (%zu)\n", transform->offset,
			    transform->offset);
			if (transform->flags & SHIVA_TRANSFORM_F_EXTEND) {
				res = shiva_tf_splice_function_extend(linker, transform, dst);
				if (res == true ) {
					transform->segment_offset = *segment_offset;
					*segment_offset += transform->target_symbol.size;
					*segment_offset += transform->source_symbol.size;
					*segment_offset += transform->ext_len;
					shiva_debug("setting segment_offset to %#lx\n", *segment_offset);
					if (*segment_offset % ARM_INSN_LEN != 0) {
						shiva_debug("Aligning *segment_offset to 4\n");
						*segment_offset = *segment_offset + 4 & ~3;
					}
					shiva_debug("Calling shiva_tf_relink_new_func\n");
					res = shiva_tf_relink_new_func(linker, transform);
				}
				break;
			}
			break;
		case SHIVA_TRANSFORM_EMIT_BYTECODE:
		default:
			break;
		}
	}
	linker->tf_text_offset = *segment_offset;
	test_mark();
	return res;
}
