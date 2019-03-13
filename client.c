#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <endian.h>

// limitation length of 10M
#define length_10M 1024*1024*10
// define protocol packet
struct packet {
	unsigned short op;
	unsigned short checksum;
	char keyword[4];
	unsigned long long length;
	char* data;
};

typedef struct packet* packet_T;

// establish a connection with a server
// from 2018 cs230 class17 ppt
int open_clientfd(char *hostname, char *port) {
  int clientfd;
  struct addrinfo hints, *listp, *p;

  /* Get a list of potential server addresses */
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_socktype = SOCK_STREAM;  /* Open a connection */
  hints.ai_flags = AI_NUMERICSERV;  /* …using numeric port arg. */
  hints.ai_flags |= AI_ADDRCONFIG;  /* Recommended for connections */
  getaddrinfo(hostname, port, &hints, &listp);
    /* Walk the list for one that we can successfully connect to */
    for (p = listp; p; p = p->ai_next) {
        /* Create a socket descriptor */
        if ((clientfd = socket(p->ai_family, p->ai_socktype, 
                               p->ai_protocol)) < 0)
            continue; /* Socket failed, try the next */

        /* Connect to the server */
        if (connect(clientfd, p->ai_addr, p->ai_addrlen) != -1)
            break; /* Success */
        close(clientfd); /* Connect failed, try another */
    }

    /* Clean up */
    freeaddrinfo(listp);
    if (!p) /* All connects failed */
        return -1;
    else    /* The last connect succeeded */
        return clientfd;
}
// calculate the checksum from packet
// from http://locklessinc.com/articles/tcp_checksum/
unsigned short checksum(const char *buf, unsigned size)
{
	unsigned long long sum = 0;
	const unsigned long long *b = (unsigned long long *) buf;
	unsigned t1, t2;
	unsigned short t3, t4;
	// calculate the checksum for packet without data
	for(int i = 0; i<2; i++){
		unsigned long long s = *b++;
		sum += s;
		if (sum < s) sum ++;
		size -= 8;
	}
	// calculate the checksum for data in packet
	b = (unsigned long long *) ((packet_T)buf)->data;
	/* Main loop - 8 bytes at a time */
	while (size >= sizeof(unsigned long long))
	{
		unsigned long long s = *b++;
		sum += s;
		if (sum < s) sum++;
		size -= 8;
	}
	/* Handle tail less than 8-bytes long */
	buf = (const char *) b;
	if (size & 4)
	{
		unsigned s = *(unsigned *)buf;
		sum += s;
		if (sum < s) sum++;
		buf += 4;
	}
	if (size & 2)
	{
		unsigned short s = *(unsigned short *) buf;
		sum += s;
		if (sum < s) sum++;
		buf += 2;
	}
	if (size)
	{
		unsigned char s = *(unsigned char *) buf;
		sum += s;
		if (sum < s) sum++;
	}
	/* Fold down to 16 bits */
	t1 = sum;
	t2 = sum >> 32;
	t1 += t2;
	if (t1 < t2) t1++;
	t3 = t1;
	t4 = t1 >> 16;
	t3 += t4;
	if (t3 < t4) t3++;

	return ~t3;
}
// send the packet to the server
int main(int argc, char ** argv){
	// check the argument number
	if (argc != 9){
		fprintf(stderr, "Incorrect number of argument\n");
		return 0;
	}
	// allocate memory for packet
	packet_T p = (packet_T) malloc(sizeof(struct packet));
	char* host = NULL;
	char* port = NULL;
	// dedicate host & port
	if (strcmp(argv[1], "-h") == 0){
		host = argv[2];
	}
	if (strcmp(argv[3], "-p") == 0){
		port = argv[4];
	}
	// dedicate operator with network-order
	if (strcmp(argv[5], "-o") == 0){
		if (strcmp(argv[6], "0") == 0){
			p->op = htobe16((unsigned short) 0);
		}
		else if (strcmp(argv[6],"1") == 0){
			p->op = htobe16((unsigned short) 1);
		}
		else{
			p->op = (unsigned short) -1;
		}
	}
	// dedicate keyword
	if (strcmp(argv[7], "-k") == 0){
		strcpy(p->keyword,argv[8]);
	}
	// check the blank argument
	if (host == NULL || p->op == -1 || p->keyword == NULL || port == NULL){
		fprintf(stderr, "Incorrect argument\n");
		free(p);
		return 0;
	}
	int clientfd;
	// connect with server
	if ((clientfd = open_clientfd(host, port)) <= -1){
		fprintf(stderr, "Failed to connect\n");
		free(p);
		return 0;
	}
	// allocate the data in packet
	p->data = (char *) malloc(length_10M);
	*(p->data) = '\0';
	char buf[1024];
	unsigned long long len = 16;
	unsigned short checks = 0;
	// calculated the length of data and copy to data array in packet
	while(fgets(buf, sizeof(buf), stdin) != NULL){
		len += strlen(buf);
		strcat(p->data, buf);
	}
	// dedicate the length and checksum for packet
	p->length = htobe64(len);
	p->checksum = checksum((char*)p, len);

	// send the packet without data 
	write(clientfd, (char *) p, 16);
	// send the data in pakcet
	write(clientfd, p->data, len-16);
	
	// receive the whole packet from server
	read(clientfd, (char *) p, 16);
	read(clientfd, p->data, len - 16);

	// compare the data and checksum
	// And, print the data which is received
	checks = p->checksum;
	p->checksum = 0;
	if (checksum((char*)p, len) == checks){
		printf("%s", p->data);
	}
	// close the connection
	close(clientfd);
	
	// free the data in packet and packet
	free(p->data);
	free(p);
	return 0;
}