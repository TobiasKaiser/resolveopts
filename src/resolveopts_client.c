#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/un.h>
#include "asn1/Response.h"
#include "asn1/Request.h"
#include <unistd.h>
#include "ber_rw_helper.h"


#include <resolveopts/resolveopts.h>


/*
 * EXPECTED RETURN VALUES:
 *  -1: Failed to consume bytes. Abort the mission.
 * Non-negative return values indicate success, and ignored.
 */
static int write_stream(const void *buffer, size_t size, void *application_specific_key) {
	int fd=*((int*) application_specific_key);
	ssize_t bytes_written=write(fd, buffer, size);
	if(bytes_written!=size)
		return -1;

	return 0;
	// TODO: Fix that we return an error if write returns early but without error!
}


int resolveopts_getaddrinfo(const char *node, const char *service, const struct resolveopts_addrinfo *hints, struct resolveopts_addrinfo **res) {


	struct Request *req;
	asn_enc_rval_t retenc;
	asn_dec_rval_t retdec;
	int reti;
	int own_retval=0;	

	/* Create request */

	if((req=malloc(sizeof(struct Request)))==NULL) {
		own_retval=RESOLVEOPTS_EAI_MEMORY;
		goto error;
	}
	memset(req, 0, sizeof(struct Request));

	if(OCTET_STRING_fromString(&req->node, node)<0) {
		own_retval=RESOLVEOPTS_EAI_MEMORY;
		goto error;
	}
	if(OCTET_STRING_fromString(&req->service, service)<0) {
		own_retval=RESOLVEOPTS_EAI_MEMORY;
		goto error;
	}
	if(hints) {
		if((req->hints=malloc(sizeof(struct Request__hints)))==NULL) {
			own_retval=RESOLVEOPTS_EAI_MEMORY;
			goto error;
		}
		memset(req->hints, 0, sizeof(struct Request__hints));
		req->hints->aiFlags=hints->ai_flags;
		req->hints->aiFamily=hints->ai_family;
		req->hints->aiSocktype=hints->ai_socktype;
		req->hints->aiProtocol=hints->ai_protocol;
	}

	/* Connect to server */
	struct sockaddr_un addr;
	int fd=-1;
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family=AF_UNIX;
	strcpy(addr.sun_path, "/tmp/resolveopts");
	fd=socket(PF_UNIX, SOCK_STREAM, 0);
	connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un));

	/* Send request */
	retenc=der_encode(&asn_DEF_Request, req, write_stream, &fd);

	if(retenc.encoded<0) {
		printf("a");
		own_retval=RESOLVEOPTS_EAI_COMM;
		goto error;
	}

	struct Response *resp=NULL;
	char recv_buf[1024];
	ssize_t bytes_read=0;
	size_t b;
	do {
		b=read(fd, recv_buf+bytes_read, sizeof(recv_buf)-bytes_read);
		if(b<0) {
			own_retval=RESOLVEOPTS_EAI_COMM;
			goto error;
		}
		bytes_read+=b;
	} while(b!=0);
	
	retdec=ber_decode(0, &asn_DEF_Response, (void **) &resp, recv_buf, bytes_read);

	if(retdec.code!=RC_OK) {
		own_retval=RESOLVEOPTS_EAI_COMM;
		goto error;
	}


	asn_fprint(stdout, &asn_DEF_Response, resp);

	goto cleanup;
error:
	
cleanup:
	if(fd>0)
		close(fd);
	asn_DEF_Request.free_struct(&asn_DEF_Request, req, 0);
	//asn_DEF_Response.free_struct(&asn_DEF_Response, resp, 0);

	return own_retval;
}