#include<stdio.h>
#include<string.h>
#include<stdlib.h>

#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include <netdb.h>
#include<stdbool.h>
#include<time.h>

int main(int agrc, char *argv[])
{
    struct hostent *tmp = gethostbyname(argv[1]);
    
    if(!tmp)
    {
        perror("Err getting host.\n");
        exit(1);
    }

    for(int i=0; tmp->h_addr_list[i]; ++i)
    {
        printf("h_addr_list[%d] : %s\n", i, inet_ntoa( (struct in_addr) *((struct in_addr *) tmp->h_addr_list[i])));
    }
}