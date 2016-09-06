#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <resolveopts/resolveopts.h>

int main(int argc, char *argv[]) {
	if(argc!=3) {
		printf("Usage: ./example_client NODE SERVICE\n");
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
		printf("error=%i (\"%s\")\n", ret, resolveopts_gai_strerror(ret));
		return 1;
	} else {
		char hostname[NI_MAXHOST];
		ret=getnameinfo(res->ai_addr, res->ai_addrlen, hostname, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
		if(ret) {
			printf("getnameinfo failed\n");
			return 1;
		}
		printf("res->ai_flags=%i\n", res->ai_flags);
		printf("res->ai_family=%i\n", res->ai_family);
		printf("res->ai_socktype=%i\n", res->ai_socktype);
		printf("res->ai_protocol=%i\n", res->ai_protocol);

		printf("res->ai_addrlen=%i\n", res->ai_addrlen);
		printf("res->ai_addr=%s\n", hostname);

		printf("res->ai_canonname=%s\n", res->ai_canonname?res->ai_canonname:"NULL");
		printf("res->ai_next=%p\n", res->ai_next);
	}

	return 0;
}