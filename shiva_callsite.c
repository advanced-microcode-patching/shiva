#include "shiva.h"

void
shiva_callsite_iterator_init(struct shiva_ctx *ctx, struct shiva_callsite_iterator *iter)
{

	iter->current = TAILQ_FIRST(&ctx->tailq.branch_tqlist);
	return;
}

shiva_iterator_res_t
shiva_callsite_iterator_next(struct shiva_callsite_iterator *iter, struct shiva_branch_site *e)
{
	if (iter->current == NULL)
		return SHIVA_ITER_DONE;
check_branch:
	if (iter->current->branch_type == SHIVA_BRANCH_CALL) {
		memcpy(e, iter->current, sizeof(*e));
		iter->current = TAILQ_NEXT(iter->current, _linkage);
		return ELF_ITER_OK;
	} else {
		iter->current = TAILQ_NEXT(iter->current, _linkage);
		if (iter->current == NULL)
			return SHIVA_ITER_DONE;
		goto check_branch;
	}
	return ELF_ITER_DONE;
}
