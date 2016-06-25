#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <resolveopts/resolveopts.h>

int main(int argc, char *argv[]) {
	if(argc!=3) {
		printf("Usage...\n");
		exit(1);
	}
	struct resolveopts_addrinfo *res, hints;
	memset(&hints, 0, sizeof(struct resolveopts_addrinfo));
	hints.ai_family=AF_INET;
	hints.ai_socktype=SOCK_STREAM;
	resolveopts_getaddrinfo(argv[1], argv[2], &hints, &res);

	return 0;
}