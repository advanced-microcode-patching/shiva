#include "shiva_module.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <byteswap.h>

int print_packet(char *buf, int len)
{
	int i;
#if DEBUG
	printf("DEBUG_PRINT_PACKET\n");
	for (i = 0; i < len; i++) {
		printf("%02x", buf[i] & 0xff);
		if (i % 24 == 0)
			printf("\n");
	}
	printf("\n");
#endif
}

#define HEADER_LEN 6
#define PDU_LEN 6

/*
 * This hooks the original processSciencePacket() function and processes each
 * part of the input buffer, using the 6 byte header as a delimiter. Passing
 * each header-delimited part of the buffer to the original function. Thus
 * not confusing the original function with extra headers.
 */
int processSciencePacket(char *buf, int len)
{
	int ret, new_len;
	char *p, *sp;
	char new_buf[1024];

	/*    6      6    6    6     6      6    6
	 * [header][pdu][pdu][pdu][header][pdu][pdu]
	 *///\------------------\  \---------------- etc. \

	p = (uint8_t *)buf;
	/*
	 * Process initial header
	 */
	for (sp = new_buf, p = buf; ;) {
		uint16_t packet_len = *(uint16_t *)&p[4];
		packet_len =  __builtin_bswap16(packet_len);
		packet_len += 1;
		print_packet(buf, packet_len);
		memcpy(sp, p, HEADER_LEN);
		memcpy(&sp[HEADER_LEN], &p[HEADER_LEN], packet_len);
		new_len = packet_len + HEADER_LEN;
		ret = SHIVA_HELPER_CALL_EXTERNAL_ARGS2(processSciencePacket,
		    sp, new_len);
		sp += new_len;
		p += new_len;
		if ((p - buf) >= len)
			break;
	}
	return ret;
}
