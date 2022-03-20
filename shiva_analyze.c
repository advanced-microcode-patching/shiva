/*
 * shiva_analyze.c - Functions for performing control flow analysis, and gathering other
 */
#include "shiva.h"

bool
shiva_analyze_find_calls(struct shiva_ctx *ctx, struct shiva_branch_site *site)
{
	struct elf_section section;
	struct elf_symbol symbol;
	const uint8_t *ptr;
	uint64_t call_offset, call_site, call_addr, addr;
	uint64_t current_address = ctx->disas.base;
	size_t offset;
	int bits;

	bits = elf_class(&ctx->elfobj) == elfclass64 ? 64 : 32;
	ud_init(&ctx->disas.ud_obj);
	ud_set_input_buffer(&ctx->disas.ud_obj, ctx->disas.textptr, section.size);
	ud_set_mode(&ctx->disas.ud_obj, bits);
	ud_set_syntax(&ctx->disas.ud_obj, UD_SYN_INTEL);
	while (ud_disassemble(&ctx->disas.ud_obj) != 0) {
		struct shiva_branch_site *tmp;

		if (ud_insn_mnemonic(&ctx->disas.ud_obj) != UD_Icall)
			continue;
		ptr = ud_insn_ptr(&ctx->disas.ud_obj);
		assert(ptr != NULL);
		if (ptr[0] != 0xe8)
			continue;
		tmp = calloc(1, sizeof(*tmp));
		if (tmp == NULL) {
			perror("calloc");
			return false;
		}
		call_offset = *(uint32_t *)&ptr[1];
		call_site = current_address;
		call_addr = call_site - offset - 5;
		if (elf_type(&ctx->elfobj) == ET_DYN) {
			addr = ctx->ulexec.base_vaddr + call_addr;
		} else {
			addr = call_addr;
		}
		if (elf_symbol_by_value(&ctx->elfobj, addr,
		    &symbol) == false) {
			symbol.name = shiva_xfmtstrdup("fn_%#lx", addr);
			if (symbol.name == NULL) {
				perror("strdup");
				return false;
			}
			symbol.value = addr;
			symbol.type = STT_FUNC;
		}
		memcpy(&tmp->symbol, &symbol, sizeof(symbol));
		tmp->branch_type = SHIVA_BRANCH_CALL;
		tmp->target_vaddr = addr;
		tmp->branch_site = call_site;
		TAILQ_INSERT_TAIL(&ctx->tailq.branch_tqlist, tmp, _linkage);
	}
	return true;
}
