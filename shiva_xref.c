#include "shiva.h"

void
shiva_xref_iterator_init(struct shiva_ctx *ctx, struct shiva_xref_iterator *iter)
{
	
	assert(TAILQ_EMPTY(&ctx->tailq.xref_tqlist) == false);
	iter->current = TAILQ_FIRST(&ctx->tailq.xref_tqlist);
	iter->ctx = ctx;
	return;
}

shiva_iterator_res_t
shiva_xref_iterator_next(struct shiva_xref_iterator *iter, struct shiva_xref_site *e)
{
	if (iter->current == NULL)
		return SHIVA_ITER_DONE;
	memcpy(e, iter->current, sizeof(*e));
	iter->current = TAILQ_NEXT(iter->current, _linkage);
	return ELF_ITER_OK;
}
