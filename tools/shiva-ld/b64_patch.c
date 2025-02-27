#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <dlfcn.h>

char *b64_encode_unsafe(const unsigned char *in, size_t len)
{
	char * (*o_b64_encode_unsafe)(const unsigned char *, size_t);
	o_b64_encode_unsafe = (char * (*)(const unsigned char *, size_t))dlsym(RTLD_NEXT, "b64_encode_unsafe");

	if (in != NULL && len >= 0) {
		char *retptr = o_b64_encode_unsafe(in, len);
		return retptr;
	}
	return NULL;
}

