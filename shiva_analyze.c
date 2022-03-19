/*
 * shiva_analyze.c - Functions for performing control flow analysis, and gathering other
 */

bool
shiva_analyze_find_calls(struct shiva_ctx *ctx, struct shiva branch_site)
{
	uint8_t *ptr;
	uint64_t call_offset;
	uint64_t call_site;
	uint64_t current_address = ctx->disas.base;

	ud_init(&ctx->disas.ud_obj);
	ud_set_input_buffer(&ctx->disas.ud_obj, ctx->disas.textptr, section.size);
	ud_set_mode(&ctx->disas.ud_obj, bits);
	ud_set_syntax(&ctx->disas.ud_obj, UD_SYN_INTEL);
	while (ud_disassemble(&ctx->disas.ud_obj) != 0) {
		if (ud_insn_mnemonic(&ctx->disas.ud_obj) != UD_Icall)
			continue;
		ptr = ud_insn_ptr(&ctx->disas.ud_obj);
		assert(ptr != NULL);
		if (ptr[0] != 0xe8)
			continue;
		call_offset = *(uint32_t *)&ptr[1];
		call_site = current_address;
		call_addr = call_site - offset - 5;
	}
}
