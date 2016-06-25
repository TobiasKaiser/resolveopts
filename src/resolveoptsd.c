#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <error.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include "asn1/Response.h"
#include "asn1/Request.h"

const static char *server_socket_path="/tmp/resolveopts";

static bool debug=true;

/* malloc with safe return value + memset to 0 */
void *xmalloc(size_t s) {
	void *ret=malloc(s);
	if(ret==NULL) {
		fprintf(stderr, "Error: malloc failed, exiting.\n");
		exit(1);
	}
	memset(ret, 0, s);
	return ret;
}

/*
 * EXPECTED RETURN VALUES:
 *  -1: Failed to consume bytes. Abort the mission.
 * Non-negative return values indicate success, and ignored.
 */
static int write_stream(const void *buffer, size_t size, void *application_specific_key) {
	int fd=*((int*) application_specific_key);
	ssize_t bytes_written=write(fd, buffer, size);
	if(bytes_written!=size) {
		printf("XXX\n");
		return -1;
	}

	return 0;
	// TODO: Fix that we return an error if write returns early but without error!
}


void handle_socket(int connfd) {
	struct Request *req=NULL;
	asn_dec_rval_t retdec;
	int reti;
	
	/* Read request */
	if(debug)
		printf("fd %i: connected, reading request now\n", connfd);
	do {
		char recv_buf[1024];

		ssize_t bytes_read=read(connfd, recv_buf, sizeof(recv_buf));
		if(bytes_read<0) {
			perror("read failed\n");
			goto error;
		}
		if(debug)
			printf("fd %i: received %zi bytes\n", connfd, bytes_read);
		if(bytes_read==0) {
			// end-of-file
			printf("read reached eof\n");
			goto error;
		}
		retdec=ber_decode(0, &asn_DEF_Request, (void **) &req, recv_buf, bytes_read);
	} while(retdec.code==RC_WMORE);
	if(retdec.code!=RC_OK) {
		printf("decoding failed\n");
		goto error;
	}
	if(debug) {
		printf("fd %i: request decoded:\n", connfd);
		asn_fprint(stdout, &asn_DEF_Request, req);
	}

	/* Create response */
	struct Response *resp=NULL;
	resp=xmalloc(sizeof(struct Response));


	/* Perform requested name resolution
 	 * At the moment, we just do a native name resolution here.
	 */
	struct addrinfo hints, *res=NULL;
	memset(&hints, 0, sizeof(struct addrinfo));
	if(req->hints) {
		hints.ai_family=req->hints->aiFamily;
		hints.ai_socktype=req->hints->aiSocktype;
		hints.ai_protocol=req->hints->aiProtocol;
		hints.ai_flags=req->hints->aiFlags;
	}

	reti=getaddrinfo((char*)req->node.buf, (char*)req->service.buf, req->hints?&hints:NULL, &res);

	if(reti) {
		/* Error occured, return error code to client */
		resp->present=Response_PR_error;
		
	} else {
		assert(res!=NULL); //TODO: make this prettier
		/* Successful resolution, return first element of res to client */
		resp->present=Response_PR_addrinfo;
		resp->choice.addrinfo.aiFlags=res->ai_flags;
		resp->choice.addrinfo.aiFamily=res->ai_family;
		resp->choice.addrinfo.aiSocktype=res->ai_socktype;
		resp->choice.addrinfo.aiProtocol=res->ai_protocol;
		if(res->ai_canonname) {
			if(OCTET_STRING_fromString(resp->choice.addrinfo.aiCanonname, res->ai_canonname)<0) {
				goto error;
			}
		}
		 OCTET_STRING_fromBuf(&resp->choice.addrinfo.aiAddr, (char *) res->ai_addr, res->ai_addrlen);
	}


	

	/* Send response */
	asn_enc_rval_t retenc;
	retenc=der_encode(&asn_DEF_Response, &resp, write_stream, &connfd);

	if(debug) {
		printf("fd %i: sent %zi bytes:\n", connfd, retenc.encoded);
		asn_fprint(stdout, &asn_DEF_Response, resp);
	}

	goto cleanup;
error:
	/* ... */
cleanup:
	asn_DEF_Request.free_struct(&asn_DEF_Request, req, 0);
	asn_DEF_Response.free_struct(&asn_DEF_Response, resp, 0);
	return;
}

int main(int argc, char *argv[]) { // Stevens: TCP Concurrent Server, One Child per Client (30.5, p. 822)
	int listenfd;


	struct sockaddr_un bindaddr;
	bindaddr.sun_family=AF_UNIX;
	strcpy(bindaddr.sun_path, server_socket_path);
	unlink(server_socket_path);

	listenfd=socket(PF_UNIX, SOCK_STREAM, 0);
	bind(listenfd, (struct sockaddr*)&bindaddr, sizeof(struct sockaddr_un));

	listen(listenfd, 5);

	while(1) {
		pid_t childpid;
		int connfd;

		if((connfd=accept(listenfd, NULL, NULL))<0) {
			if(errno==EINTR) {
				continue;
			} else {
				perror("accept failed: ");
			}
		}
		if((childpid=fork())==0) {
			close(listenfd);
			handle_socket(connfd);
			exit(0);
		}
		close(connfd);
	}
}