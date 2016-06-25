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
#include <errno.h>


#include <resolveopts/resolveopts.h>


int resolveopts_getaddrinfo(const char *node, const char *service, const struct resolveopts_addrinfo *hints, struct resolveopts_addrinfo **res) {

	struct Request *req;
	asn_enc_rval_t retenc;
	asn_dec_rval_t retdec;
	int reti;
	int own_retval=0;
	int set_errno_at_leave=0;

	*res=NULL;

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
	if(ber_write_helper(&asn_DEF_Request, req, fd)<0) {
		own_retval=RESOLVEOPTS_EAI_COMM;
		goto error;
	}

	/* Read response */
	struct Response *resp=NULL;

	if(ber_read_helper(&asn_DEF_Response, (void**) &resp, fd)<0) {
		own_retval=RESOLVEOPTS_EAI_COMM;
		goto error;
	}

	//asn_fprint(stdout, &asn_DEF_Response, resp);

	/* Process response */
	if(resp->present==Response_PR_gaiError) {
		switch(resp->choice.gaiError) {
			case Response__gaiError_eaiAddrfamily:
				own_retval=RESOLVEOPTS_EAI_ADDRFAMILY;
				break;
			case Response__gaiError_eaiAgain:
				own_retval=RESOLVEOPTS_EAI_AGAIN;
				break;
			case Response__gaiError_eaiBadflags:
				own_retval=RESOLVEOPTS_EAI_BADFLAGS;
				break;
			case Response__gaiError_eaiFail:
				own_retval=RESOLVEOPTS_EAI_FAIL;
				break;
			case Response__gaiError_eaiFamily:
				own_retval=RESOLVEOPTS_EAI_FAMILY;
				break;
			case Response__gaiError_eaiMemory:
				own_retval=RESOLVEOPTS_EAI_MEMORY;
				break;
			case Response__gaiError_eaiNodata:
				own_retval=RESOLVEOPTS_EAI_NODATA;
				break;
			case Response__gaiError_eaiNoname:
				own_retval=RESOLVEOPTS_EAI_NONAME;
				break;
			case Response__gaiError_eaiService:
				own_retval=RESOLVEOPTS_EAI_SERVICE;
				break;
			case Response__gaiError_eaiSocktype:
				own_retval=RESOLVEOPTS_EAI_SOCKTYPE;
				break;
			default:
				own_retval=RESOLVEOPTS_EAI_COMM;
		}
	} else if(resp->present==Response_PR_systemError) {
		own_retval=RESOLVEOPTS_EAI_SYSTEM;
		set_errno_at_leave=resp->choice.systemError;
	} else if(resp->present==Response_PR_addrinfo) {
		*res=malloc(sizeof(struct resolveopts_addrinfo));
		if(*res==NULL) {
			own_retval=RESOLVEOPTS_EAI_MEMORY;
			goto error;
		}
		memset(*res, 0, sizeof(struct resolveopts_addrinfo));

		(*res)->ai_flags=resp->choice.addrinfo.aiFlags;
		(*res)->ai_family=resp->choice.addrinfo.aiFamily;
		(*res)->ai_socktype=resp->choice.addrinfo.aiSocktype;
		(*res)->ai_protocol=resp->choice.addrinfo.aiProtocol;
		(*res)->ai_addrlen=resp->choice.addrinfo.aiAddr.size;
		(*res)->ai_addr=malloc(resp->choice.addrinfo.aiAddr.size);
		if((*res)->ai_addr==NULL) {
			own_retval=RESOLVEOPTS_EAI_MEMORY;
			goto error;
		}
		memcpy((*res)->ai_addr, resp->choice.addrinfo.aiAddr.buf, resp->choice.addrinfo.aiAddr.size);
		if(resp->choice.addrinfo.aiCanonname) {
			(*res)->ai_canonname=malloc(resp->choice.addrinfo.aiCanonname->size+1);
			if((*res)->ai_canonname==NULL) {
				own_retval=RESOLVEOPTS_EAI_MEMORY;
				goto error;
			}
			strcpy((*res)->ai_canonname, (char*) resp->choice.addrinfo.aiCanonname->buf);
		}

	} else { /* resp->present = Response_PR_NOTHING */
		own_retval=RESOLVEOPTS_EAI_COMM;
	}

	goto cleanup;
error:
	if(*res) {
		// We wanted to return an addrinfo, but then an error occured and now we have to free it.
		resolveopts_freeaddrinfo(*res);
		*res=NULL;
	}

cleanup:
	
	if(fd>0)
		close(fd);
	asn_DEF_Request.free_struct(&asn_DEF_Request, req, 0);
	//asn_DEF_Response.free_struct(&asn_DEF_Response, resp, 0);

	if(set_errno_at_leave)
		errno=set_errno_at_leave;

	return own_retval;
}

void resolveopts_freeaddrinfo(struct resolveopts_addrinfo *res) {
	assert(res->ai_next==NULL); /* We never return more than one element at the moment */
	if(res->ai_canonname) {
		free(res->ai_canonname);
		res->ai_canonname=NULL;
	}
	if(res->ai_addr) {
		free(res->ai_addr);
		res->ai_addr=NULL;
	}
	free(res);
}

char *resolveopts_gai_strerror(int error) {

	switch(error) {
		case RESOLVEOPTS_EAI_ADDRFAMILY: 	return "address family not supported";
		case RESOLVEOPTS_EAI_AGAIN:			return "temporary name resolution failure";
		case RESOLVEOPTS_EAI_BADFLAGS:		return "invalid flags";
		case RESOLVEOPTS_EAI_FAIL:			return "permanent name resolution failure";
		case RESOLVEOPTS_EAI_FAMILY:		return "address family not supported";
		case RESOLVEOPTS_EAI_MEMORY:		return "memory allocation failed";
		case RESOLVEOPTS_EAI_NODATA:		return "no network address defined for host";
		case RESOLVEOPTS_EAI_NONAME:		return "host or service not known";
		case RESOLVEOPTS_EAI_SERVICE:		return "service not supported for socket type";
		case RESOLVEOPTS_EAI_SOCKTYPE:		return "socket type not supported";
		case RESOLVEOPTS_EAI_SYSTEM:		return "system error";
		case RESOLVEOPTS_EAI_OVERFLOW:		return "argument too long";
		case RESOLVEOPTS_EAI_COMM:			return "error communicating with resolveopts daemon";
	}
	return "unknown error from resolveopts_getaddrinfo";
}