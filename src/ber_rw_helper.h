int ber_read_helper(struct asn_TYPE_descriptor_s *type_descriptor, void **struct_ptr, int readfd);

int ber_write_helper(struct asn_TYPE_descriptor_s *type_descriptor, void *struct_ptr, int writefd);