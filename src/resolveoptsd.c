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

struct addrinfo *prepare_for_getaddrinfo(struct Request *req, struct addrinfo *hints, char **nodename, char **servname) {
	/* Perform requested name resolution
 	 * At the moment, we just do a native name resolution here.
	 */

	struct addrinfo *return_hints=NULL;
	
	
	memset(hints, 0, sizeof(struct addrinfo));
	if(req->hints) {
		hints->ai_family=req->hints->aiFamily;
		hints->ai_socktype=req->hints->aiSocktype;
		hints->ai_protocol=req->hints->aiProtocol;
		hints->ai_flags=req->hints->aiFlags;
		return_hints=hints;
	}

	*nodename = (char*)req->node.buf;
	*servname = (char*)req->service.buf;

	return return_hints;
}


int postprocess_for_getaddrinfo(struct Response *resp, struct addrinfo *res, int reti) {
	if(reti==EAI_SYSTEM) {
		resp->present=Response_PR_systemError;
		resp->choice.systemError=errno;
	} else if(reti) {
		/* Error occured, return error code to client */
		resp->present=Response_PR_gaiError;

		switch(reti) {
			/* See https://sourceware.org/bugzilla/show_bug.cgi?id=6452 for why we get weird return codes */
			#ifdef EAI_ADDRFAMILY
			case EAI_ADDRFAMILY:
				resp->choice.gaiError=Response__gaiError_eaiAddrfamily;
				break;
			#endif
			case EAI_AGAIN:
				resp->choice.gaiError=Response__gaiError_eaiAgain;
				break;
			case EAI_BADFLAGS:
				resp->choice.gaiError=Response__gaiError_eaiBadflags;
				break;
			case EAI_FAIL:
				resp->choice.gaiError=Response__gaiError_eaiFail;
				break;
			case EAI_FAMILY:
				resp->choice.gaiError=Response__gaiError_eaiFamily;
				break;
			case EAI_MEMORY:
				resp->choice.gaiError=Response__gaiError_eaiMemory;
				break;
			#ifdef EAI_NODATA
			case EAI_NODATA:
				resp->choice.gaiError=Response__gaiError_eaiNodata;
				break;
			#endif
			case EAI_NONAME:
				resp->choice.gaiError=Response__gaiError_eaiNoname;
				break;
			case EAI_SERVICE:
				resp->choice.gaiError=Response__gaiError_eaiService;
				break;
			case EAI_SOCKTYPE:
				resp->choice.gaiError=Response__gaiError_eaiSocktype;
				break;
			case EAI_SYSTEM:
			default:
				printf("unresolvable return code %i from getaddrinfo translated to EAI_AGAIN\n", reti);
				resp->choice.gaiError=Response__gaiError_eaiAgain;
				return 1;
		}
	} else {
		assert(res);
		resp->present=Response_PR_addrinfo;

		assert(res!=NULL); //TODO: make this prettier
		/* Successful resolution, return first element of res to client */

		resp->choice.addrinfo.aiFlags=res->ai_flags;
		resp->choice.addrinfo.aiFamily=res->ai_family;
		resp->choice.addrinfo.aiSocktype=res->ai_socktype;
		resp->choice.addrinfo.aiProtocol=res->ai_protocol;

		if(res->ai_canonname) {
			if(OCTET_STRING_fromString(resp->choice.addrinfo.aiCanonname, res->ai_canonname)<0) {
				printf("failed to encode octet string");
				return 1;
			}
		}
		if(OCTET_STRING_fromBuf(&resp->choice.addrinfo.aiAddr, (char *) res->ai_addr, res->ai_addrlen)<0) {
			printf("failed to encode octet string");
			return 1;
		}
	}
	return 0;
}


void handle_socket(int connfd) {
	struct Request *req=NULL;
	struct Response *resp=NULL;
	struct addrinfo hints_mem, *hints_p=NULL, *res=NULL;
	char *nodename=NULL, *servname=NULL;
	
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
	resp=xmalloc(sizeof(struct Response));

	hints_p=prepare_for_getaddrinfo(req, &hints_mem, &nodename, &servname);
	reti=getaddrinfo(nodename, servname, hints_p, &res);
	if(postprocess_for_getaddrinfo(resp, res, reti)) {
		goto error;
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