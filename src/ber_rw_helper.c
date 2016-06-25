#include "asn1/Response.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int debug=0;

/*
 * EXPECTED RETURN VALUES:
 *  -1: Failed to consume bytes. Abort the mission.
 * Non-negative return values indicate success, and ignored.
 */
static int write_stream(const void *buffer, size_t size, void *application_specific_key) {
	int fd=*((int*) application_specific_key);

	ssize_t bytes_written=write(fd, buffer, size);

	if(bytes_written!=size) {
		
		return -1;
	}

	return 0;
	// TODO: Fix that we return an error if write returns early but without error!
}

int ber_read_helper(struct asn_TYPE_descriptor_s *type_descriptor, void **struct_ptr, int readfd) {

	asn_dec_rval_t retdec;
	int bufferfill_lastread=0;
	do {
		char recv_buf[1024];

		ssize_t bytes_read=read(readfd, recv_buf+bufferfill_lastread, sizeof(recv_buf)-bufferfill_lastread);
		if(bytes_read<0) {
			perror("read failed\n");
			return -1;
		}
		if(debug)
			printf("fd %i: received %zi bytes\n", readfd, bytes_read);
		if(bytes_read==0) {
			// end-of-file
			printf("read reached eof\n");
			return -1;
		}
		bytes_read+=bufferfill_lastread;
		retdec=ber_decode(0, type_descriptor, struct_ptr, recv_buf, bytes_read);
		bufferfill_lastread=bytes_read-retdec.consumed;
		memmove(recv_buf, recv_buf+retdec.consumed, bufferfill_lastread);

	} while(retdec.code==RC_WMORE);
	if(retdec.code!=RC_OK) {
		printf("decoding failed\n");
		return -1;
	}
	return 0;
}

int ber_write_helper(struct asn_TYPE_descriptor_s *type_descriptor, void *struct_ptr, int writefd) {

	asn_enc_rval_t retenc;
	retenc=der_encode(type_descriptor, struct_ptr, write_stream, &writefd);
	return (retenc.encoded>=0)?0:-1;
}