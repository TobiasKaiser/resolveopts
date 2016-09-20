#include <stdio.h>
#include <string.h>
#include <uv.h>
#include <error.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include "asn1/Response.h"
#include "asn1/Request.h"

static const char *server_socket_path="/tmp/resolveopts";
static bool debug=true;
static uv_pipe_t listen_socket;
static uv_loop_t *main_loop;
static uv_signal_t sigint_handler;

struct per_client_data {
	uv_pipe_t client_stream;
	int bufferfill_lastread;
	char recv_buf[1024];
	struct Request *req;
	struct addrinfo hints_mem;
	uv_write_t write;
	uv_getaddrinfo_t gai;
	uv_buf_t send_buf;
	char send_buf_data[1024];
};

enum err_code_type {ERR_CODE_TYPE_UV, ERR_CODE_TYPE_SYSTEM};

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

void free_per_client_data(struct per_client_data *pcd) {
	if(pcd->req) {
		asn_DEF_Request.free_struct(&asn_DEF_Request, pcd->req, 0);
	}
	uv_unref((uv_handle_t *) &pcd->client_stream);
	free(pcd);
}

uv_buf_t on_alloc(uv_handle_t * handle, size_t size) {
 	return uv_buf_init((char *) xmalloc(size), size);
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

int postprocess_for_getaddrinfo(struct Response *resp, struct addrinfo *res, int reti, enum err_code_type err_code_type) {
	if(reti==EAI_SYSTEM) {
		resp->present=Response_PR_systemError;
		resp->choice.systemError=errno;
	} else if(reti) {
		/* Error occured, return error code to client */
		resp->present=Response_PR_gaiError;

		if(err_code_type==ERR_CODE_TYPE_SYSTEM) {
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
		} else if(err_code_type==ERR_CODE_TYPE_UV) {
			switch(reti) {
				/* See https://sourceware.org/bugzilla/show_bug.cgi?id=6452 for why we get weird return codes */
				case -UV_EAGAIN:
					resp->choice.gaiError=Response__gaiError_eaiAgain;
					break;
				case -UV_EBADF:
					resp->choice.gaiError=Response__gaiError_eaiBadflags;
					break;
				case -UV_EFAULT:
					resp->choice.gaiError=Response__gaiError_eaiFail;
					break;
				case -UV_EAIFAMNOSUPPORT:
					resp->choice.gaiError=Response__gaiError_eaiFamily;
					break;
				case -UV_ENOMEM:
					resp->choice.gaiError=Response__gaiError_eaiMemory;
					break;
				case -UV_ENOENT:
				case -UV_EADDRINFO:
					resp->choice.gaiError=Response__gaiError_eaiNoname;
					break;
				case -UV_EAISERVICE:
					resp->choice.gaiError=Response__gaiError_eaiService;
					break;
				case -UV_EAISOCKTYPE:
					resp->choice.gaiError=Response__gaiError_eaiSocktype;
					break;
				default: // libuv should return other gemeral UV_... error codes in case of general system errors.
					printf("unresolvable return code %i from getaddrinfo translated to EAI_AGAIN\n", reti);
					resp->choice.gaiError=Response__gaiError_eaiAgain;
					return 1;
			}
		} else {
			assert(0);
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


/******************************************************************************
 * Unix domain socket connection handling
 *****************************************************************************/

void on_connect(uv_stream_t *server, int status);
void on_read(uv_stream_t * stream, ssize_t nread, uv_buf_t buf);
void on_resolve(uv_getaddrinfo_t *req, int status, struct addrinfo *res);
void on_write(uv_write_t* req, int status);
void on_close(uv_handle_t *req);

void on_connect(uv_stream_t *server, int status) {
    if (status == -1) {
        fprintf(stderr, "Error on listening: %s.\n", 
            uv_strerror(uv_last_error(main_loop)));

        return;
    }

	//printf("new connection :)\n");

	struct per_client_data *pcd=xmalloc(sizeof(struct per_client_data));
	memset(pcd, 0, sizeof(struct per_client_data));
	uv_pipe_init(main_loop, &pcd->client_stream, false);
	pcd->client_stream.data=pcd;
	//printf("new pcd=%p\n", pcd);

    /* now let bind the client to the server to be used for incomings */
    if (uv_accept(server, (uv_stream_t *) &pcd->client_stream) == 0) {
        /* start reading from stream */
        int r = uv_read_start((uv_stream_t *) &pcd->client_stream, on_alloc, on_read);

        if (r) {
            fprintf(stderr, "Error on reading client stream: %s.\n", 
                    uv_strerror(uv_last_error(main_loop)));
        }
    } else {
        /* close client stream on error */
        uv_close((uv_handle_t *) &pcd->client_stream, on_close); 
        // TODO: not sure if this is working, especially regarding memory leaks
    }
}

void on_read(uv_stream_t * stream, ssize_t nread, uv_buf_t buf) {
	int i;

	struct per_client_data *pcd=stream->data;
	asn_dec_rval_t retdec;

	memset(&retdec, 0, sizeof(asn_dec_rval_t));

	if(nread<UV_EOF) {
		assert(nread==-UV_EOF);
		printf("unexpected EOF\n");
		// Error handling: close
		uv_close((uv_handle_t *) &pcd->client_stream, on_close); 

	} else if(nread<0) {
		printf("some error on recv\n");
		uv_close((uv_handle_t *) &pcd->client_stream, on_close); 

	} else if(nread>0) {
		size_t inbuf_size=pcd->bufferfill_lastread+nread;
		assert(inbuf_size<=sizeof(pcd->recv_buf));
		memcpy(pcd->recv_buf + pcd->bufferfill_lastread, buf.base, nread);

		retdec=ber_decode(0, &asn_DEF_Request, (void*) &pcd->req, pcd->recv_buf, inbuf_size);

		pcd->bufferfill_lastread=inbuf_size-retdec.consumed;

		memmove(pcd->recv_buf, pcd->recv_buf+retdec.consumed, pcd->bufferfill_lastread);
		//memset(pcd->recv_buf+inbuf_size, 0, sizeof(pcd->recv_buf)-inbuf_size);

		if(retdec.code==RC_WMORE) {

		} else if(retdec.code==RC_OK) {
			asn_fprint(stdout, &asn_DEF_Request, pcd->req);

			char *node, *service;
			struct addrinfo *hints_ptr;
			hints_ptr=prepare_for_getaddrinfo(pcd->req, &pcd->hints_mem, &node, &service);
			pcd->gai.data=pcd;
			uv_getaddrinfo(main_loop, &pcd->gai, on_resolve, node, service, hints_ptr);

			uv_read_stop(stream);

		} else {
			printf("ber decoding error\n");
			uv_close((uv_handle_t *) &pcd->client_stream, on_close); 

		}

		
	} else {
		/* EAGAIN */
	}

	if(buf.base) {
		free(buf.base);
	}
}

void on_resolve(uv_getaddrinfo_t *req, int status, struct addrinfo *res) {
	struct per_client_data *pcd=req->data;

	asn_enc_rval_t retenc;
	struct Response *resp=xmalloc(sizeof(struct Response));

	if(postprocess_for_getaddrinfo(resp, res, status, ERR_CODE_TYPE_UV)) {
		goto error;
	}
	pcd->send_buf.base=pcd->send_buf_data;
	pcd->send_buf.len=sizeof(pcd->send_buf_data);
	retenc=der_encode_to_buffer(&asn_DEF_Response, resp, pcd->send_buf.base, pcd->send_buf.len);
	asn_fprint(stdout, &asn_DEF_Response, resp);
	asn_DEF_Response.free_struct(&asn_DEF_Response, resp, 0);
	resp=NULL;

	if(!(retenc.encoded>0 && retenc.encoded<=pcd->send_buf.len)) {
		goto error;
	}
	pcd->send_buf.len=retenc.encoded;

	pcd->write.data=pcd;
	uv_write(&pcd->write, (uv_stream_t *) &pcd->client_stream, &pcd->send_buf, 1, on_write);

	goto cleanup;
error:
	printf("Error in on_resolve\n");
	free_per_client_data(pcd);
	pcd=NULL;
cleanup:
	uv_freeaddrinfo(res);
}


void on_write(uv_write_t* req, int status) {
	struct per_client_data *pcd=req->data;

	uv_close((uv_handle_t *)&pcd->client_stream, on_close);
}

void on_close(uv_handle_t *req) {
	struct per_client_data *pcd=req->data;

	free_per_client_data(pcd);
}

/******************************************************************************
 * SIGINT (Ctrl+C) handler
 *****************************************************************************/

void on_sigint(uv_signal_t* handle, int signum);
void on_listen_socket_close(uv_handle_t *handle);

void on_sigint(uv_signal_t* handle, int signum) {
	printf("received sigint\n");
	uv_unref((uv_handle_t*)handle);
	uv_close((uv_handle_t *)&listen_socket, on_listen_socket_close);
}

void on_listen_socket_close(uv_handle_t *handle) {
	printf("listening socket closed\n");
	uv_unref(handle);
}

/******************************************************************************
 * Main loop
 *****************************************************************************/

int main(int argc, char *argv[]) {
	main_loop=uv_default_loop();

	uv_signal_init(main_loop, &sigint_handler);
	uv_signal_start(&sigint_handler, on_sigint, SIGINT);

	uv_pipe_init(main_loop, &listen_socket, false);
	unlink(server_socket_path);
	uv_pipe_bind(&listen_socket, server_socket_path);


	int r = uv_listen((uv_stream_t *) &listen_socket, 5, on_connect);

	return uv_run(main_loop, UV_RUN_DEFAULT);
}