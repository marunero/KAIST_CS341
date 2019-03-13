CC = gcc

all: server client
clobber: clean
	rm -f *~ \ 
clean:
	rm -f server *.o
	rm -f client *.o

server: server.c
	$(CC) server.c -o server
client: client.c
	$(CC) client.c -o client
