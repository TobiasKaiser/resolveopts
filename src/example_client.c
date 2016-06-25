#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <resolveopts/resolveopts.h>

int main(int argc, char *argv[]) {
	struct resolveopts_addrinfo *res, hints;
	memset(&hints, 0, sizeof(struct resolveopts_addrinfo));
	hints.ai_family=AF_INET;
	hints.ai_socktype=SOCK_STREAM;
	resolveopts_getaddrinfo("google.com", "80", &hints, &res);

	return 0;
}