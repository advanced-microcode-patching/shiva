#ifndef _SHIVA_MISC_H_
#define _SHIVA_MISC_H_

/*
 * We use a temporary variable, tvar, so that we can
 * free the entry while iterating.
 */
#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar)                                 \
        for ((var) = ((head)->tqh_first);                               \
        	(var) && ((tvar) = (var)->field.tqe_next);	        \
		(var) = (tvar))
#endif
#endif

