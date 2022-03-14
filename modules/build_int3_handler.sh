#!/bin/sh
rm -f trap_handler.c
echo '#include "../shiva.h"' > trap_handler.c
echo 'extern shiva_ctx_t *ctx;' >> trap_handler.c
cat shakti_runtime.c >> trap_handler.c
