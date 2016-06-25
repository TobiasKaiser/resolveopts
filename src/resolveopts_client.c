#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "asn1/Response.h"
#include "asn1/Request.h"
#include <unistd.h>

#include <resolveopts/resolveopts.h>


/*
 * EXPECTED RETURN VALUES:
 *  -1: Failed to consume bytes. Abort the mission.
 * Non-negative return values indicate success, and ignored.
 */
static int write_stream(const void *buffer, size_t size, void *application_specific_key) {
	int fd=(int) application_specific_key;
	ssize_t bytes_written=write(fd, buffer, size);
	if(bytes_written!=size)
		return -1;

	return 0;
	// TODO: Fix that we return an error if write returns early but without error!
}


int resolveopts_getaddrinfo(const char *node, const char *service, const struct resolveopts_addrinfo *hints, struct resolveopts_addrinfo **res) {

	struct Request req;
	asn_enc_rval_t retenc;
	int reti;
	

	// Create request

	memset(&req, 0, sizeof(struct Request));
	req.node.size=4;
	req.node.buf="Test";
	req.intents.category=calloc(1, sizeof(long));
	*req.intents.category=category_controlTraffic;
	req.intents.fileSize=malloc(sizeof(long));
	*req.intents.fileSize=1000;

	// Connect to server
	struct sockaddr_un addr;
	int fd;
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family=AF_UNIX;
	strcpy(addr.sun_path, "/tmp/resolveopts");
	fd=socket(PF_UNIX, SOCK_STREAM, 0);
	connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));

	// Send request
	retenc=der_encode(&asn_DEF_Request, &req, write_stream, (void*)fd);

	//ret=xer_fprint(stdout, &asn_DEF_Request, &myRq);

	return 0;

}