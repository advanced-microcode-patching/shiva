#include "shiva.h"
#include "shiva_debug.h"

#define ERRONEOUS_AUXV_COUNT 4096

bool
shiva_auxv_iterator_init(struct shiva_ctx *ctx, struct shiva_auxv_iterator *iter,
    void *auxv)
{
	int i = 0;

	iter->index = 0;
	iter->ctx = ctx;

	/*
	 * If the caller supplies an auxv pointer then use it.
	 * (This is typically for reading secondary auxv's such
	 * as those built for a userland exec. :)
	 */
	if (auxv != NULL) {
		iter->auxv = (Elf64_auxv_t *)auxv;
		shiva_debug("Setting iter->auxv to %p\n", iter->auxv);
		return true;
	}

	if (ctx->envp == NULL)
		return false;

	for (i = 0; ctx->envp[i] != NULL; i++)
		;
	shiva_debug("Setting iter->auxv to envp[%d]\n", i + 1);
	iter->auxv = (Elf64_auxv_t *)&ctx->envp[i + 1];
	return true;
}


shiva_iterator_res_t
shiva_auxv_iterator_next(struct shiva_auxv_iterator *iter, struct shiva_auxv_entry *entry)
{

	if (iter->auxv[iter->index].a_type == AT_NULL)
		return SHIVA_ITER_DONE;

	entry->type = iter->auxv[iter->index].a_type;
	entry->value = iter->auxv[iter->index].a_un.a_val;
	if (iter->auxv[iter->index].a_type == AT_EXECFN)
		entry->string = (char *)entry->value;
	if (iter->index++ >= ERRONEOUS_AUXV_COUNT)
		return SHIVA_ITER_ERROR;
	return SHIVA_ITER_OK;
}

/*
 * Set the auxv value of where the iterator is currently
 * at within the auxv array.
 */
bool
shiva_auxv_set_value(struct shiva_auxv_iterator *iter, long value)
{
	
	if (((ssize_t)iter->index - 1) < 0)
		return false;
	/*
	 * iter->index is always incremented after each iteration
	 * so we must use index - 1 to get the index of what the
	 * programmer sees as the current auxv iteration.
	 */
	iter->auxv[iter->index - 1].a_un.a_val = (uint64_t)value;
	return true;
}
