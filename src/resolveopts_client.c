#include <stdio.h>
#include <string.h>
#include "asn1/Result.h"
#include "asn1/Request.h"


int resolveopts_getaddrinfo(const char *node, const char *service, const struct resolveopts_addrinfo *hints, struct resolveopts_addrinfo **res) {

	struct Request myRq;
	int ret;
	memset(&myRq, 0, sizeof(struct Request));
	myRq.node.size=4;
	myRq.node.buf="Test";
	myRq.intents.category=calloc(1, sizeof(long));
	*myRq.intents.category=category_controlTraffic;
	myRq.intents.fileSize=malloc(sizeof(long));
	*myRq.intents.fileSize=1000;

	ret=xer_fprint(stdout, &asn_DEF_Request, &myRq);

	return 0;

}