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

void resolveopts_freeaddrinfo(struct resolveopts_addrinfo *res);

char *resolveopts_gai_strerror(int error);

#define RESOLVEOPTS_EAI_ADDRFAMILY	1
#define RESOLVEOPTS_EAI_AGAIN		2
#define RESOLVEOPTS_EAI_BADFLAGS	3
#define RESOLVEOPTS_EAI_FAIL		4
#define RESOLVEOPTS_EAI_FAMILY		5
#define RESOLVEOPTS_EAI_MEMORY		6
#define RESOLVEOPTS_EAI_NODATA		7
#define RESOLVEOPTS_EAI_NONAME		8
#define RESOLVEOPTS_EAI_SERVICE		9
#define RESOLVEOPTS_EAI_SOCKTYPE	10
#define RESOLVEOPTS_EAI_SYSTEM		11
#define RESOLVEOPTS_EAI_OVERFLOW	12
#define RESOLVEOPTS_EAI_COMM		13