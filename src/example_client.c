#include <stdio.h>
#include <resolveopts/resolveopts.h>

int main(int argc, char *argv[]) {
	struct resolveopts_addrinfo *res;

	resolveopts_getaddrinfo("google.com", "80", NULL, &res);
}