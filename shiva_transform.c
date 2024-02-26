#include "shiva.h"
#if __aarch64__
#include "shiva_aarch64.h"
#endif

#define COPY_FIRST_HALF		0
#define COPY_SECOND_HALF	2
#define COPY_TF_SOURCE		3

#define ARM_INSN_LEN 4
#define AARCH64_NOP 0xd503201f

#define X86_64_ENDBR64 0xfa1e0ff3
#define X86_64_UD2 0x00000b0f
#define X86_64_NOP 0x90
#define X86_64_IMM_CALL 0xe8

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
 * shiva_tf_splice_function
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
shiva_tf_splice_function(struct shiva_module *linker, struct shiva_transform *transform,
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
	 * If the patch code is the same size, then simply replace
	 * the code in question.
	 * If the patch code is smaller than the target area, then
	 * this implicitly instructs us to patch the remaining target
	 * code with NOPS.
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
#elif __x86_64__
	if (*(uint32_t *)&transform->ptr[0] == X86_64_ENDBR64) {
		transform->ptr[0] = X86_64_NOP;
		transform->ptr[1] = X86_64_NOP;
		transform->ptr[2] = X86_64_NOP;
		transform->ptr[3] = X86_64_NOP;
	}
	if (*(uint16_t *)&transform->ptr[transform->new_len - 2] == X86_64_UD2) {
		transform->ptr[transform->new_len - 2] = X86_64_NOP;
		transform->ptr[transform->new_len - 1] = X86_64_NOP;
	}
#endif
	memcpy(dest + transform->offset, transform->ptr, copy_len);

	/*
	 * If the end address is further away than the amount of code
	 * we are copying, then overwrite the remaining target code
	 * with NOPS. This technique allows a splicer to overwrite
	 * multiple lines of code with just a single line of code in
	 * their place, overwriting the remaining area with nops.
	 * TODO: Add x86_64 support for this capability.
	 */
	if (transform->flags & SHIVA_TRANSFORM_F_NOP_PAD) {
#ifdef __aarch64__
		uint32_t nop_bytes = AARCH64_NOP;
		size_t nop_len = transform->old_len - transform->new_len;
		size_t i;

		assert((nop_len % ARM_INSN_LEN) == 0);

		shiva_debug("Copying in %d NOP instructions at %p\n",
		    (nop_len / 4) * ARM_INSN_LEN, dest);

		for (i = 0; i < nop_len / 4; i++) {
			memcpy(dest + transform->offset + copy_len + (i * ARM_INSN_LEN),
			    &nop_bytes, ARM_INSN_LEN );
		}
		copy_len += (nop_len / 4) * ARM_INSN_LEN;
#elif __x86_64__
		size_t nop_len = transform->old_len - transform->new_len;
		size_t i;

		shiva_debug("Copying in %d NOP instructions at %p\n", nop_len,
		    dest);
		for (i = 0; i < nop_len; i++) {
			dest[transform->offset + copy_len + i] = 0x90;
		}
		copy_len += nop_len;
#endif
	}
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


#ifdef __x86_64__
static bool
shiva_tf_relink_xref_x86_64(struct shiva_module *linker, struct shiva_transform *transform,
    struct shiva_xref_site *xref)
{
	bool res;
	uint8_t *rel_unit;
	uint64_t rel_addr, insn_offset;
	uint32_t rel_val;

	assert(xref->rip_rel_site >= transform->target_symbol.value &&
	    xref->rip_rel_site < transform->target_symbol.value + transform->target_symbol.size);
	insn_offset = xref->rip_rel_site - transform->target_symbol.value;
	if (insn_offset > transform->offset + transform->old_len)
		insn_offset += transform->new_len - transform->old_len;
	rel_addr = linker->text_vaddr + transform->segment_offset + insn_offset;
	rel_val = xref->target_vaddr + linker->target_base - rel_addr - xref->insn_len;
	rel_unit = (uint8_t *)rel_addr;

	/*
	 * NOTE: All IP relative LEA's are 7 bytes.
	 * Some IP relative mov's can be 7 bytes or 6
	 * bytes depending on the modrm.
	 */
	switch(xref->type) {
	case SHIVA_XREF_TYPE_IP_RELATIVE_LEA:
		shiva_debug("Patching LEA with offset: %#lx\n", rel_val);
		*(uint32_t *)&rel_unit[3] = rel_val;
		break;
	case SHIVA_XREF_TYPE_IP_RELATIVE_MOV_LDR:
	case SHIVA_XREF_TYPE_IP_RELATIVE_MOV_STR:
		if (xref->insn_len == 6) {
			*(uint32_t *)&rel_unit[2] = rel_val;
		} else if (xref->insn_len == 7) {
			*(uint32_t *)&rel_unit[3] = rel_val;
		} else {
			fprintf(stderr, "invalid insn len for ip relative mov. len val: %u\n",
			    xref->insn_len);
			return false;
		}
		shiva_debug("Patching MOV with offset: %#lx\n", rel_val);
		break;
	default:
		break;
	}
	return true;

}
#elif __aarch64__
static bool
shiva_tf_relink_xref_aarch64(struct shiva_module *linker, struct shiva_transform *transform,
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

	return true;

}
#endif

#ifdef __x86_64__

static bool
shiva_tf_relink_global_branch_x86_64(struct shiva_module *linker, struct shiva_transform *transform,
    struct shiva_branch_site *branch)
{

	/*
	 * Offset to branch instruction (Within our new transformed version of the function)
	*/
        size_t br_site_off = branch->branch_site - transform->target_symbol.value;

	shiva_debug("br_site_off = %lx - %lx = %#lx\n", branch->branch_site, transform->target_symbol.value,
            br_site_off);
        /*
         * mem points to the branch instruction within the new location of the
         * spliced/transformed function.
         */
        if (br_site_off > transform->offset + transform->old_len)
                br_site_off += transform->new_len - transform->old_len;

	uint8_t *mem = &linker->text_mem[transform->segment_offset + br_site_off];
	size_t br_site_addr = linker->text_vaddr + transform->segment_offset + br_site_off;

	if (branch->branch_type == SHIVA_BRANCH_CALL &&
	    branch->o_insn[0] == X86_64_IMM_CALL) {
		uint64_t new_offset;

		new_offset = (branch->target_vaddr + linker->target_base) - br_site_addr - 5;
		*(uint32_t *)&mem[1] = new_offset;
		return true;
	}
	return false;
}
#elif __aarch64__
static bool
shiva_tf_relink_global_branch_aarch64(struct shiva_module *linker, struct shiva_transform *transform,
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
#endif

#ifdef __x86_64__

/*
 * Taken from ftrace.c https://github.com/elfmaster/ftrace
 */
struct branch_instr {
	char *mnemonic;
	uint8_t opcode;
};

const struct branch_instr branch_table[64] = {
			{"jo",	0x70},
			{"jno", 0x71},	{"jb", 0x72},  {"jnae", 0x72},	{"jc", 0x72},  {"jnb", 0x73},
			{"jae", 0x73},	{"jnc", 0x73}, {"jz", 0x74},	{"je", 0x74},  {"jnz", 0x75},
			{"jne", 0x75},	{"jbe", 0x76}, {"jna", 0x76},	{"jnbe", 0x77}, {"ja", 0x77},
			{"js",	0x78},	{"jns", 0x79}, {"jp", 0x7a},	{"jpe", 0x7a}, {"jnp", 0x7b},
			{"jpo", 0x7b},	{"jl", 0x7c},  {"jnge", 0x7c},	{"jnl", 0x7d}, {"jge", 0x7d},
			{"jle", 0x7e},	{"jng", 0x7e}, {"jnle", 0x7f},	{"jg", 0x7f},  {"jmp", 0xeb},
			{"jmp", 0xe9},	{"jmpf", 0xea}, {"je", 0x0f},    {NULL, 0}
		};


static struct branch_instr *
shiva_tf_search_local_branch_opcode(uint8_t byte)
{
	const struct branch_instr *p;

	for (p = branch_table; p->mnemonic != NULL; p++) {
		if (p->opcode == byte)
			return (struct branch_instr *)p;
	}
	return NULL;
}

static bool
shiva_tf_relink_local_branch_x86_64(struct shiva_module *linker, struct shiva_transform *transform,
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

	struct branch_instr *bptr = shiva_tf_search_local_branch_opcode(branch->o_insn[0]);
	if (bptr == NULL) {
		fprintf(stderr, "failed to find branch opcode: %02x\n", branch->o_insn[0]);
		return false;
	}
	/*
	 * Near jump opcodes
	 */

	if (mem[0] == 0x0f) {
		uint32_t orig_offset = *(uint32_t *)&mem[2];
		shiva_debug("relinking near jump branch: %s to (%lx + %lx) = %#lx\n", bptr->mnemonic, orig_offset, delta, orig_offset + delta);
		*(uint32_t *)&mem[2] = orig_offset + delta;
	} else {
		uint32_t orig_offset = *(uint8_t *)&mem[1];
		shiva_debug("relinking short jump branch: %s to (%lx + %lx) = %#lx\n", bptr->mnemonic, orig_offset, delta, orig_offset + delta);
		*(uint8_t *)&mem[1] = orig_offset + delta;
	}
done:
	return true;
}

#elif __aarch64__
static bool
shiva_tf_relink_local_branch_aarch64(struct shiva_module *linker, struct shiva_transform *transform,
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
#endif

bool
shiva_tf_relink_global_branch(struct shiva_module *linker, struct shiva_transform *transform,
    struct shiva_branch_site *branch)
{
#ifdef __x86_64__
	return shiva_tf_relink_global_branch_x86_64(linker, transform, branch);
#elif __aarch64__
	return shiva_tf_relink_global_branch_aarch64(linker, transform, branch);
#endif

}

bool
shiva_tf_relink_xref(struct shiva_module *linker, struct shiva_transform *transform,
    struct shiva_xref_site *xref)
{
#ifdef __x86_64__
	return shiva_tf_relink_xref_x86_64(linker, transform, xref);
#elif __aarch64__
	return shiva_tf_relink_xref_aarch64(linker, transform, xref);
#endif
}

bool
shiva_tf_relink_local_branch(struct shiva_module *linker, struct shiva_transform *transform,
    struct shiva_branch_site *branch, ssize_t delta)
{
#ifdef __x86_64__
	return shiva_tf_relink_local_branch_x86_64(linker, transform, branch, delta);
#elif __aarch64__
	return shiva_tf_relink_local_branch_aarch64(linker, transform, branch, delta);
#endif
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
		/*
		 * Relink positive offsets that link to code
		 * after the splice insertion, from code before
		 * the splice insertion.
		 */
		shiva_debug("Processing transform branch: %#lx:%s\n", branch->branch_site,
		    branch->insn_string);

		if (BRANCH_IS_LOCAL(branch->target_vaddr)) {
			/*
			 * If the patch is the same size as the destination area
			 * that's being patched, then the replace flag is set.
			 * In this event, the local branches surrounding the
			 * splicd in patch won't change, so we simply continue.
			 */
			if (transform->flags & SHIVA_TRANSFORM_F_REPLACE)
				continue;

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
#ifdef __aarch64__
		if ((xref->adrp_site < transform->target_symbol.value + transform->offset) ||
		    (xref->adrp_site >= transform->target_symbol.value + transform->offset + transform->old_len)) {
#elif __x86_64__
		if ((xref->rip_rel_site < transform->target_symbol.value + transform->offset) ||
		    (xref->rip_rel_site >= transform->target_symbol.value + transform->offset + transform->old_len)) {
#endif
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
				res = shiva_tf_splice_function(linker, transform, dst);
				if (res == true ) {
					shiva_debug("SHIVA_TRANSFORM_F_EXTEND");
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
			} else if (transform->flags & SHIVA_TRANSFORM_F_REPLACE) {
				res = shiva_tf_splice_function(linker, transform, dst);
				if (res == true) {
					shiva_debug("SHIVA_TRANSFORM_F_REPLACE\n");
					transform->segment_offset = *segment_offset;
					*segment_offset += transform->target_symbol.size;
					*segment_offset += transform->source_symbol.size;
					*segment_offset += transform->ext_len;
					shiva_debug("setting segment_offset to %#lx\n", *segment_offset);
					if (*segment_offset % ARM_INSN_LEN != 0) {
						shiva_debug("Aligning *segment_offset to 4\n");
						*segment_offset = *segment_offset + 4 & ~3;
					}
					res = shiva_tf_relink_new_func(linker, transform);
				}
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
