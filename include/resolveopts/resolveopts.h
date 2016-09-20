struct ropts_addrinfo {
	int              ai_flags;
	int              ai_family;
	int              ai_socktype;
	int              ai_protocol;
	socklen_t        ai_addrlen;
	struct sockaddr *ai_addr;
	char            *ai_canonname;
	struct addrinfo *ai_next;
};

int ropts_getaddrinfo(const char *node, const char *service, const struct ropts_addrinfo *hints, struct ropts_addrinfo **res);

void ropts_freeaddrinfo(struct ropts_addrinfo *res);

char *ropts_gai_strerror(int error);

#define ROPTS_EAI_ADDRFAMILY	1
#define ROPTS_EAI_AGAIN			2
#define ROPTS_EAI_BADFLAGS		3
#define ROPTS_EAI_FAIL			4
#define ROPTS_EAI_FAMILY		5
#define ROPTS_EAI_MEMORY		6
#define ROPTS_EAI_NODATA		7
#define ROPTS_EAI_NONAME		8
#define ROPTS_EAI_SERVICE		9
#define ROPTS_EAI_SOCKTYPE		10
#define ROPTS_EAI_SYSTEM		11
#define ROPTS_EAI_OVERFLOW		12
#define ROPTS_EAI_COMM			13