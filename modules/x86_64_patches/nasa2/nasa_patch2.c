#include "shiva_module.h"
#include <stdio.h>
#include <stdint.h>
#include <byteswap.h>

int print_packet(char *buf, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		printf("%02x", buf[i] & 0xff);
		if (i % 24 == 0)
			printf("\n");
	}

}

int processSciencePacket(char *buf, int len)
{
	int ret, i;
	char *p, *sp;
	char new_buf[1024];

	/*    6      6    6    6     6      6    6
	 * [header][pdu][pdu][pdu][header][pdu][pdu]
	 */

	p = (uint8_t *)buf;
	/*
	 * Process initial header
	 */

	uint16_t packet_len = *(uint16_t *)&p[4];
	packet_len =  __builtin_bswap16(packet_len);
	for (i = 0, sp = new_buf, p = buf; ; i++) {
		print_packet(buf, packet_len);
		memcpy(sp, p, packet_len);
		ret = SHIVA_HELPER_CALL_EXTERNAL_ARGS2(processSciencePacket,
		    sp, packet_len);
		i += packet_len;
		sp += packet_len;
		if (i >= len)
			break;
	}

	return ret;
}
