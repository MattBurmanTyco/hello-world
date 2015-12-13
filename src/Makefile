# Make file for osdp-tls

PROGS = osdp-tls

all:	${PROGS}

clean:
	rm -f core *.o ${PROGS}

osdp-tls:	osdp-tls.o Makefile
	clang -o osdp-tls -g osdp-tls.o -L /tester/current/lib -lgnutls

osdp-tls.o:	osdp-tls.c ../include/osdp-tls.h
	clang -c -g -I../include -I /tester/current/include -Wall -Werror osdp-tls.c

