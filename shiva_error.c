#include "shiva.h"

bool
shiva_error_set(shiva_error_t *error, const char *fmt, ...)
{
        va_list va;

        if (error == NULL)
                return false;

        va_start(va, fmt);
        vsnprintf(error->string, sizeof(error->string), fmt, va);
        va_end(va);
        error->_errno = errno;
        return true;
}

