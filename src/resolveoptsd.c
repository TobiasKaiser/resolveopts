#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <error.h>
#include <errno.h>
#include "asn1/Result.h"
#include "asn1/Request.h"

const static char *server_socket_path="/tmp/resolveopts";

void handle_socket(int connfd) {
	printf("Got a new socket...\n");
	write(connfd, "Hallo\n", 6);
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
		struct sockaddr *cliaddr;

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