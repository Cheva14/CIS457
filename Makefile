all: client server

client: client.c
	gcc client.c -o client -lcrypto

server: server.c
	gcc server.c -o server -lcrypto

clean: client server
	rm -f client server