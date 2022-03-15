#include "shiva.h"

bool
shiva_maps_build_list(struct shiva_ctx *ctx)
{
	FILE *fp;
	char buf[PATH_MAX];

	assert(TAILQ_EMPTY(&ctx->tailq.mmap_tqlist));

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
	
		p = strrchr(buf, '/');
		if (p != NULL)
			appname = &p[1];
		entry = shiva_malloc(sizeof(*entry));
		memset(entry, 0, sizeof(*entry));
		
		p = strchr(buf, '-');
		assert(p != NULL);
		*p = '\0';
		q = p + 1;
		entry->base = strtoul(buf, NULL, 16);
		end = strtoul(p + 1, NULL, 16);
		assert(end > entry->base);
		entry->len = end - entry->base;
		shiva_debug("base: %#lx\n", entry->base);
		if (!strncmp(appname, "shiva", 5)) {
			shiva_debug("Debug mapping found: %#lx\n", entry->base);
			entry->debugger_mapping = true;
		}
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
