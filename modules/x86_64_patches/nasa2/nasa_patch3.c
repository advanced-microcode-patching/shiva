#include "shiva_module.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <byteswap.h>

#define HEADER_LEN 6
#define PDU_LEN 6

/*
 * This patch (nasa_patch3.c) is another example of how to patch
 * the Ground Control challenge. In the previous two patches we
 * break the data stream up into individual chunks consisting of
 * each header followed by its PDU's and pass them individually
 * to the original processSciencePacket() function, since it is
 * able to process one header at a time, but not multiple of them.
 *
 * In this patch we re-package the data stream into a new buffer
 * that only contains the initial header, and all subsequent headers
 * are removed so that they don't get read in as random data. This
 * version of the patch only has to call the original function once
 * with the new buffer and new input len.
 */
int processSciencePacket(char *buf, int len)
{
	int ret;
	size_t new_len, header_len;
	size_t delta_len = 0;
	size_t dst_buf_len = 0;
	size_t iter = 0, total_header_len = 0;
	char *p, *newp;
	char new[len];
	int i;

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
	return ret;
}
