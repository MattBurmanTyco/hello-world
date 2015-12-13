# makefile for osdp-tls

PROGS=osdp-tls

all:	${PROGS}

clean:
	rm -rf core *.o ${PROGS}

osdp-tls:	osdp-tls.o apps.o app_rand.o s_cb.o s_socket.o Makefile
	gcc -o osdp-tls -g osdp-tls.o apps.o app_rand.o s_cb.o s_socket.o \
	  -ldl -L /tester/current/lib -lssl -lcrypto

osdp-tls.o:	osdp-tls.c
	gcc -c -g -Wall -Werror \
	  -DOPENSSL_NO_HEARTBEATS -DOPENSSL_NO_SRTP -DOPENSSL_NO_TLSEXT \
	  -I /tester/current/include -I openssl -I openssl/apps \
	  osdp-tls.c

apps.o:	apps.c
	gcc -c -g -Wall -Werror \
	  -I /tester/current/include -I openssl -I openssl/apps \
	  apps.c

app_rand.o:	app_rand.c
	gcc -c -g -Wall -Werror \
	  -I /tester/current/include -I openssl -I openssl/apps \
	  app_rand.c

s_cb.o:	s_cb.c
	gcc -c -g -Wall -Werror \
	  -I /tester/current/include -I openssl -I openssl/apps \
	  s_cb.c

s_socket.o:	s_socket.c
	gcc -c -g -Wall -Werror \
	  -I /tester/current/include -I openssl -I openssl/apps \
	  s_socket.c

