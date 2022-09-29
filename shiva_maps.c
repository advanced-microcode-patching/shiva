#include "shiva.h"

/*
 * Get the base address of the target executable.
 * The base address is set in the out argument.
 */
bool
shiva_maps_get_base(struct shiva_ctx *ctx, uint64_t *out)
{
	FILE *fp;
	char buf[PATH_MAX];
	char *p;

	fp = fopen("/proc/self/maps", "r");
	if (fp == NULL) {
		perror("fopen");
		return false;
	}
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if (strstr(buf, ctx->path) == NULL)
			continue;
		p = strchr(buf, '-');
		*p = '\0';
		*out = strtoul(buf, NULL, 16);
		return true;
	}
	return false;
}

/*
 * Checking if 'addr' is a valid address mapping.
 * It's valid if it exists in /proc/pid/maps, as long as it
 * doesn't belong to the debuggers text/data segment.
 * In the future we may create more restrictions, but currently
 * the debugee must be able to access the debuggers heap for
 * shared arena's with malloc.
 */
bool
shiva_maps_validate_addr(struct shiva_ctx *ctx, uint64_t addr)
{
	struct shiva_mmap_entry *current;

	TAILQ_FOREACH(current, &ctx->tailq.mmap_tqlist, _linkage) {
		if (current->debugger_mapping == true)
			continue;
		if (addr >= current->base && addr < current->base + current->len)
			return true;
	}
	return false;
}

/*
 * Load /proc/pid/maps into the ctx->tailq.mmap_tqlist
 * XXX: Update this function to deal with Shiva when
 * it's in interpreter mode... the address space layout
 * is different than it would be in standalone mode. 
 */
bool
shiva_maps_build_list(struct shiva_ctx *ctx)
{
	FILE *fp;
	char buf[PATH_MAX];
	int i;

	if (!TAILQ_EMPTY(&ctx->tailq.mmap_tqlist)) {
		fprintf(stderr, "mmap_tqlist is already initialized\n");
		return false;
	}

	TAILQ_INIT(&ctx->tailq.mmap_tqlist);

	fp = fopen("/proc/self/maps", "r");
	if (fp == NULL) {
		perror("fopen");
		return false;
	}
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		struct shiva_mmap_entry *entry;
		unsigned long end;
		char *appname = NULL;
		char *p, *q;
		char tmp[PATH_MAX];

		strcpy(tmp, buf);

		p = strrchr(buf, '/');
		if (p != NULL)
			appname = &p[1];
		entry = shiva_malloc(sizeof(*entry));
		memset(entry, 0, sizeof(*entry));

		p = strrchr(buf, '/');
		if (p != NULL) {
			if (strncmp(&p[1], "shiva", 5) == 0) {
				if (strstr(buf, "r----") != NULL) {
					if (ctx->shiva_path == NULL) {
						p = strchr(tmp, '/');
                                		ctx->shiva_path = shiva_malloc(PATH_MAX + 1);
                                		for (i = 0; *p != '\n' && *p != '\0'; p++, i++)
                                        		ctx->shiva_path[i] = *p;
                                		ctx->shiva_path[i] = '\0';
					}
				}
				entry->mmap_type = SHIVA_MMAP_TYPE_SHIVA;
			}
		} else if (strstr(buf, "[heap]") != NULL) {
			entry->mmap_type = SHIVA_MMAP_TYPE_HEAP;
		} else if (strstr(buf, "[stack]") != NULL) {
			entry->mmap_type = SHIVA_MMAP_TYPE_STACK;
		} else if (strstr(buf, "[vdso]") != NULL) {
			entry->mmap_type = SHIVA_MMAP_TYPE_VDSO;
		} else {
			entry->mmap_type = SHIVA_MMAP_TYPE_MISC;
		}

		p = strchr(buf, '-');
		assert(p != NULL);
		*p = '\0';
		entry->base = strtoul(buf, NULL, 16);
		end = strtoul(p + 1, NULL, 16);
		assert(end > entry->base);
		entry->len = end - entry->base;
		shiva_debug("base: %#lx\n", entry->base);
		if (appname != NULL) {
			if (!strncmp(appname, "shiva", 5)) {
				shiva_debug("Debug mapping found: %#lx\n", entry->base);
				entry->debugger_mapping = true;
			}
		}
		q = strchr(p + 1, ' ');
		assert(q != NULL);
		p = q + 1;
		while (*p != ' ') {
			switch(*p) {
			case 'r':
				entry->prot |= PROT_READ;
				break;
			case 'w':
				entry->prot |= PROT_WRITE;
				break;
			case 'x':
				entry->prot |= PROT_EXEC;
			case 'p':
				entry->mapping = MAP_PRIVATE;
				break;
			case 's':
				entry->mapping = MAP_SHARED;
			case '-':
			default:
				break;
			}
			p++;
		}
		shiva_debug("Inserted mapping for %#lx - %#lx\n", entry->base,
		    entry->base + entry->len);
		TAILQ_INSERT_TAIL(&ctx->tailq.mmap_tqlist, entry, _linkage);
	}
	return true;
}

void
shiva_maps_iterator_init(struct shiva_ctx *ctx, struct shiva_maps_iterator *iter)
{

	iter->current = TAILQ_FIRST(&ctx->tailq.mmap_tqlist);
	iter->ctx = ctx;
	return;
}

shiva_iterator_res_t
shiva_maps_iterator_next(struct shiva_maps_iterator *iter, struct shiva_mmap_entry *e)
{
	if (iter->current == NULL)
		return SHIVA_ITER_DONE;
	memcpy(e, iter->current, sizeof(*e));
	iter->current = TAILQ_NEXT(iter->current, _linkage);
	return ELF_ITER_OK;
}

bool
shiva_maps_prot_by_addr(struct shiva_ctx *ctx, uint64_t addr, int *prot)
{
	shiva_maps_iterator_t mmap_iter;
	struct shiva_mmap_entry mmap_entry;

	shiva_maps_iterator_init(ctx, &mmap_iter);
	while (shiva_maps_iterator_next(&mmap_iter, &mmap_entry) == SHIVA_ITER_OK) {
		if (addr >= mmap_entry.base && addr < mmap_entry.base + mmap_entry.len) {
			*prot = mmap_entry.prot;
			return true;
		}
	}
	return false;
}
