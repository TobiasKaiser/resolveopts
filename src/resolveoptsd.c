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
#include "ber_rw_helper.h"


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


void handle_socket(int connfd) {
	struct Request *req=NULL;
	
	int reti;
	
	/* Read request */
	if(debug)
		printf("fd %i: connected, reading request now\n", connfd);

	if(ber_read_helper(&asn_DEF_Request, (void **) &req, connfd)<0) {
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

	if(reti || !res) {
		/* Error occured, return error code to client */
		resp->present=Response_PR_error;
		resp->choice.error=Response__error_eaiAgain;
		
	} else {
		resp->present=Response_PR_addrinfo;

		assert(res!=NULL); //TODO: make this prettier
		/* Successful resolution, return first element of res to client */

		resp->choice.addrinfo.aiFlags=res->ai_flags;
		resp->choice.addrinfo.aiFamily=res->ai_family;
		resp->choice.addrinfo.aiSocktype=res->ai_socktype;
		resp->choice.addrinfo.aiProtocol=res->ai_protocol;
		printf("a\n");

		if(res->ai_canonname) {
			if(OCTET_STRING_fromString(resp->choice.addrinfo.aiCanonname, res->ai_canonname)<0) {
				printf("failed to encode octet string");
				goto error;
			}
		}
		if(OCTET_STRING_fromBuf(&resp->choice.addrinfo.aiAddr, (char *) res->ai_addr, res->ai_addrlen)<0) {
			printf("failed to encode octet string");
			goto error;
		}
	}

	/* Send response */
	if(ber_write_helper(&asn_DEF_Response, resp, connfd)<0) {
		printf("failed to send response");
		goto error;
	}

	if(debug) {
		printf("fd %i: sent:\n", connfd);
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