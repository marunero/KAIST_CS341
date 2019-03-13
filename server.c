#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <endian.h>

#define LISTENQ 1024
#define length_10M 1024*1024*10
// socket address sturcter
typedef struct sockaddr SA;

// define protocol packet
struct packet {
    unsigned short op;
    unsigned short checksum;
    char keyword[4];
    unsigned long long length;
    char* data;
};
// packet pointer structer
typedef struct packet* packet_T;

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
// create a listening descriptor that can be used 
// to accept connection requests from clients
// from 2018 cs230 class17 ppt
int open_listenfd(char *port)
{
    struct addrinfo hints, *listp, *p;
    int listenfd, optval=1;

    /* Get a list of potential server addresses */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_socktype = SOCK_STREAM;             /* Accept connect. */
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG; /* …on any IP addr */
    hints.ai_flags |= AI_NUMERICSERV;            /* …using port no. */
    getaddrinfo(NULL, port, &hints, &listp);

        /* Walk the list for one that we can bind to */
    for (p = listp; p; p = p->ai_next) {
        /* Create a socket descriptor */
        if ((listenfd = socket(p->ai_family, p->ai_socktype, 
                               p->ai_protocol)) < 0)
            continue;  /* Socket failed, try the next */

        /* Eliminates "Address already in use" error from bind */
        setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, 
                   (const void *)&optval , sizeof(int));

        /* Bind the descriptor to the address */
        if (bind(listenfd, p->ai_addr, p->ai_addrlen) == 0)
            break; /* Success */
        close(listenfd); /* Bind failed, try the next */
    }
    /* Clean up */
    freeaddrinfo(listp);
    if (!p) /* No address worked */
        return -1;

    /* Make it a listening socket ready to accept conn. requests */
    if (listen(listenfd, LISTENQ) < 0) {
        close(listenfd);
        return -1;
    }
    return listenfd;
}
// execute the server
int main(int argc, char** argv){
    pid_t iPid;
    int listenfd, connfd, i;
    socklen_t clientlen;
    struct sockaddr_storage clientaddr; /* Enough room for any addr */  
    unsigned short checks;
    char* port = NULL;

    // check the argument number
    if (argc != 3){
        fprintf(stderr, "Incorrect Argument\n");
        return 0;
    }

    // check the correctness of argument
    if (strcmp(argv[1], "-p") == 0){
        port = argv[2];
    }
    // check the black port number
    if (port == NULL){
        fprintf(stderr, "No port\n");
        return 0;
    }
    // create a listening descriptor
    listenfd = open_listenfd(port);

    // allocate the memory for packet and data
    packet_T p = (packet_T) malloc(sizeof(struct packet));
    p->data = (char *) malloc(length_10M);

    
    while(1){
        // accept the listening descriptor from client
        clientlen = sizeof(struct sockaddr_storage);
        connfd = accept(listenfd, (SA *)&clientaddr, &clientlen);

        // fork the process
        if(fork() == 0){
            int key = 0;
            // read the packet from client
            read(connfd, (char *) p, 16);
            read(connfd, p->data, be64toh(p->length) - 16);

            // compare the data and checksum
            // And, if they are same, then send the packet with data 
            // which is encrypted/decrypted to client
            checks = p->checksum;
            p->checksum = 0;
            if (checksum((char *)p, be64toh(p->length)) == checks){
                // when operator is 0, that means purpose is encrypt
                if (be16toh(p->op) == 0){
                    // encrypt the alphabet
                    for (i = 0; i < be64toh(p->length) - 16; i++){
                        // uppercase -> lowercase
                        if (p->data[i] >= 65 && p->data[i] <= 90){
                            p->data[i] += 32;
                        }
                        if (p->data[i] >= 97 && p->data[i] <= 122){
                            if (p->data[i] == 'v' && p->keyword[key] == 'k'){
                                p->data[i] = 'f';
                            }
                            else{
                                p->data[i] += p->keyword[key] - 97;
                                if (p->data[i] > 'z'){
                                    p->data[i] -= 26;
                                }
                            }
                            key += 1;
                            if (key == 4){
                                key = 0;
                            }
                        }   
                        if (p->data[i] == 102) p->data[i] = 'f';
                    }
                    // change the checksum by the data which is encrypted
                    p->checksum = checksum((char*)p, be64toh(p->length));

                    // send the packet to client
                    write(connfd, (char *) p, 16);
                    write(connfd, p->data, be64toh(p->length) - 16);
                }        
                // when operator is 1, that means the purpose is decrypt
                else if (be16toh(p->op) == 1){
                    // decrypt the alphabet
                    for (i = 0; i < be64toh(p->length) - 16; i++){
                        // uppercase -> lowercase
                        if (p->data[i] >= 65 && p->data[i] <= 90){
                            p->data[i] += 32;
                        }
                        if (p->data[i] >= 97 && p->data[i] <= 122){
                            p->data[i] -= p->keyword[key%4] - 97;
                            if (p->data[i] < 'a'){
                                p->data[i] += 26;
                            }
                            key += 1;
                        }
                    }
                    // calculate the checksum by the data which is decrypted
                    p->checksum = checksum((char*)p, be64toh(p->length));
                    // send the packet to client
                    write(connfd, (char *) p, 16);
                    write(connfd, p->data, be64toh(p->length) - 16);
                }
            }
            // disconnection
            close(connfd);
            exit(0);
        }
        else {
            // disconnection
            close(connfd);
        }
    }
    // free the data and packet
    free(p->data);
    free(p);

    return 0;
}