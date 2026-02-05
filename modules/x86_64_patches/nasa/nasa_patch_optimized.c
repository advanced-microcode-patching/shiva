#include "shiva_module.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <byteswap.h>

#define HEADER_LEN 6
#define PDU_LEN 6

/*
 * science_dp_integrated ELF executable is ground-control software example
 * from NASA that improperly parses a stream that contains more than one
 * header. The bug in essence is that after the program reads the first header
 * it parses all subsequent headers as if they are PDU science data.
 *
 * This patch interposes the original processSciencePacket() function and processes each
 * part of the input buffer, using the 6 byte header as a delimiter. Passing
 * each header-delimited part of the buffer to the original function. Thus
 * not confusing the original function with extra headers.
 *
 * NOTE: This is an optimized verison of the patch which doesn't perform
 * any of the unnecessary memcpy's from the original patch.
 */
int processSciencePacket(char *buf, int len)
{
	int ret, new_len;
	char *p;

	/*    6      6    6    6     6      6    6
	 * [header][pdu][pdu][pdu][header][pdu][pdu]
	 *///\------------------\  \---------------- etc. \

	/*
	 * Process initial 6-byte header. Packetlen is in bytes 4 and 5.
	 * PDU are 6 bytes also
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
