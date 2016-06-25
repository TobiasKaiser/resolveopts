struct resolveopts_addrinfo {
	int test;
};

int resolveopts_getaddrinfo(const char *node, const char *service, const struct resolveopts_addrinfo *hints, struct resolveopts_addrinfo **res);