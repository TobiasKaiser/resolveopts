ASN1_OBJS=asn1/*.o

CFLAGS=-g -fPIC -Wall -Iasn1 -I../include
CC=gcc

export CFLAGS

.PHONY: all
all: resolveoptsd libresolveopts.so.1 example_client

example_client: example_client.o libresolveopts.so.1
	gcc -o $@ -L. -lresolveopts example_client.o

asn1/resolveopts_asn1.a: asn1/Makefile asn1/resolveopts.asn1
	cd asn1 && asn1c -fnative-types resolveopts.asn1 && make
	ar rcs $@ $(ASN1_OBJS)

resolveoptsd: resolveoptsd.o asn1/resolveopts_asn1.a
	$(CC) -o $@ $^

libresolveopts.so.1: resolveopts_client.o asn1/resolveopts_asn1.a
	$(CC) -shared -Wl,-soname,libresolveopts.so.1 -o $@ $^

resolveopts_client.o: resolveopts_client.c
	$(CC) -c $(CFLAGS) $<

example_client.o: example_client.c
	$(CC) -c $(CFLAGS) $<

resolveoptsd.o: resolveoptsd.c
	$(CC) -c $(CFLAGS) $<