#include "shiva_module.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <byteswap.h>

#define HEADER_LEN 6
#define PDU_LEN 6

/*
 * This hooks the original processSciencePacket() function and processes each
 * part of the input buffer, using the 6 byte header as a delimiter. Passing
 * each header-delimited part of the buffer to the original function. Thus
 * not confusing the original function with extra headers.
 *
 * NOTE: This is an optimized verison of the patch which doesn't perform
 * any of the unnecessary memcpy's in the original patch.
 */
int processSciencePacket(char *buf, int len)
{
	int ret, new_len;
	char *p;

	/*    6      6    6    6     6      6    6
	 * [header][pdu][pdu][pdu][header][pdu][pdu]
	 *///\------------------\  \---------------- etc. \

	/*
	 * Process initial header
	 */
	for (p = buf; (p - buf) < len; ) {
		uint16_t packet_len = *(uint16_t *)&p[4];
		packet_len =  __builtin_bswap16(packet_len);
		packet_len += 1;
		new_len = packet_len + HEADER_LEN;
		ret = SHIVA_HELPER_CALL_EXTERNAL_ARGS2(processSciencePacket,
		    p, new_len);
		p += new_len;
	}
	return ret;
}
