/*
 * shiva_jumptable.c:
 * iterator interface to access the llvm_jump_table_sizes section
 */
#include "shiva.h"
#include "shiva_debug.h"

void
shiva_jumptable_iterator_init(struct shiva_ctx *ctx, struct shiva_jumptable_iterator *iter)
{
	int i = 0;

	iter->index = 0;
	iter->ctx = ctx;
	iter->jmptab = ctx->jmptab;
	iter->entry_count = ctx->jmptab_size / 16;
	return;
}

shiva_iterator_res_t
shiva_jumptable_iterator_next(struct shiva_jumptable_iterator *iter,
    struct shiva_jumptable_entry *entry)
{
	struct jmptab_struct {
		uint64_t base;
		uint64_t entries;
	};

	struct jmptab_struct *jptr = (struct jmptab_struct *)iter->jmptab;

	if (iter->index >= iter->entry_count)
		return SHIVA_ITER_DONE;
	
	entry->base = jptr[iter->index].base;
	entry->entries = jptr[iter->index].entries;

	iter->index++;
	return SHIVA_ITER_OK;
}
