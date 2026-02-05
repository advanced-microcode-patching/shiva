/*
 * This patch, although not the most efficient way to patch the problem,
 * uses a function splice to replace line 11 (Using DWARF line info)
 * with the code below that re-packages the packet stream so that it
 * has only a single header followed only by PDU's.
 */
#include "shiva_module.h"
#include <stdio.h>
#include <string.h>

#define HEADER_LEN 6
#define PDU_LEN 6

SHIVA_T_SPLICE_FUNCTION_REPLACE_SRCLINE(processSciencePacket, 11)
{
	static int ret, i, len;
	static char *p, *sp, *newp;
	static char new[1024];
	static size_t new_len, header_len;
	static size_t delta_len = 0;
	static size_t dst_buf_len = 0;
	static size_t iter = 0, total_header_len = 0;

	/*    6      6    6    6     6      6    6
	 * [header][pdu][pdu][pdu][header][pdu][pdu]
	 */
	SHIVA_T_PAIR_RSI(lenarg);
	SHIVA_T_PAIR_RDI(realbuf);

	char *buf = (char *)realbuf;
	len = lenarg;

	/*
	 * Process initial header
	 */

	for (newp = new, p = buf; (p - buf) < len; ) {
		uint16_t packet_len = *(uint16_t *)&p[4];
		packet_len =  __builtin_bswap16(packet_len);
		packet_len += 1;
		new_len = packet_len + HEADER_LEN;
		header_len = (iter++ == 0) ? 0 : HEADER_LEN;
		memcpy(newp, p + header_len, new_len - header_len);
		newp += new_len - header_len;
		p += new_len;
		dst_buf_len += new_len - header_len;
		total_header_len += header_len;
	}
	if (dst_buf_len >= len)
		return -1;
	ret = SHIVA_HELPER_CALL_EXTERNAL_ARGS2(processSciencePacket,
	    new, len - total_header_len);
	exit(0);
}

