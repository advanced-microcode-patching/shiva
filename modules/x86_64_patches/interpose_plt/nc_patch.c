#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>

#include "../../include/shiva_module.h"

int
connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{

	unsigned short port = ntohs(((struct sockaddr_in *)addr)->sin_port);
	if (port == 31337) {
		printf("Suspicious activity... connect to port 31337?\n");
	}
	/*
	 * Now call the original pow() :)
	 */
	int ret = SHIVA_HELPER_CALL_EXTERNAL_ARGS3(connect, sockfd, addr, addrlen);
	return ret;
}
