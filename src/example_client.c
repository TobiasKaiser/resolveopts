#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <resolveopts/resolveopts.h>

int main(int argc, char *argv[]) {
	if(argc!=3) {
		printf("Usage...\n");
		exit(1);
	}
	struct resolveopts_addrinfo *res, hints;
	int ret;
	memset(&hints, 0, sizeof(struct resolveopts_addrinfo));
	hints.ai_family=AF_INET;
	hints.ai_socktype=SOCK_STREAM;
	

	ret=resolveopts_getaddrinfo(argv[1], argv[2], &hints, &res);

	if(ret) {
		//...
		printf("error=%i\n", ret);
		return 1;
	} else {
		char hostname[NI_MAXHOST];
		ret=getnameinfo(res->ai_addr, res->ai_addrlen, hostname, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
		if(ret) {
			printf("getnameinfo failed\n");
			return 1;
		}
		printf("res->ai_addr=%s\n", hostname);
	}

	return 0;
}