struct resolveopts_addrinfo {
	int              ai_flags;
	int              ai_family;
	int              ai_socktype;
	int              ai_protocol;
	socklen_t        ai_addrlen;
	struct sockaddr *ai_addr;
	char            *ai_canonname;
	struct addrinfo *ai_next;
};

int resolveopts_getaddrinfo(const char *node, const char *service, const struct resolveopts_addrinfo *hints, struct resolveopts_addrinfo **res);

#define RESOLVEOPTS_EAI_AGAIN		1
#define RESOLVEOPTS_EAI_BADFLAGS	2
#define RESOLVEOPTS_EAI_FAMILY		3
#define RESOLVEOPTS_EAI_MEMORY		4
#define RESOLVEOPTS_EAI_NONAME		5
#define RESOLVEOPTS_EAI_SERVICE		6
#define RESOLVEOPTS_EAI_SOCKTYPE	7
#define RESOLVEOPTS_EAI_SYSTEM		8
#define RESOLVEOPTS_EAI_OVERFLOW	9
#define RESOLVEOPTS_EAI_COMM		10