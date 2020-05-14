/*
 * dns_server.c
 *
 *  Created on: Apr 26, 2016
 *      Author: jiaziyi
 */


#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<stdbool.h>
#include<time.h>

#include "dns.h"

int main(int argc, char *argv[])
{
	int sockfd;
	struct sockaddr server;

	char *dns_server = "8.8.8.8";
	int port = 53; //the default port of DNS service
	FILE * parttern_file = NULL;

	//to keep the information received.
	res_record answers[ANS_SIZE], auth[ANS_SIZE], addit[ANS_SIZE];
	query queries[ANS_SIZE];


	if(argc >= 2)
	{
		port = atoi(argv[1]); //if we need to define the DNS to a specific port
	}

	if(argc >= 3)
	{
		parttern_file = fopen(argv[2], "r");
		if(!parttern_file)
		{
			char str_err[100];
			fprintf(str_err, "Err openning file %s : ", argv[2]);
			perror(str_err);
		}
	}


	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	int enable = 1;

	if(sockfd <0 )
	{
		perror("socket creation error");
		exit_with_error("Socket creation failed");
	}

	//in some operating systems, you probably need to set the REUSEADDR
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
	{
	    perror("setsockopt(SO_REUSEADDR) failed");
	}

	//for v4 address
	struct sockaddr_in *server_v4 = (struct sockaddr_in*)(&server);
	server_v4->sin_family = AF_INET;
	server_v4->sin_addr.s_addr = htonl(INADDR_ANY);
	server_v4->sin_port = htons(port);

	//bind the socket
	if(bind(sockfd, &server, sizeof(*server_v4))<0){
		perror("Binding error");
		exit_with_error("Socket binding failed");
	}

	printf("The dns_server is now listening on port %d ... \n", port);
	//print out
	uint8_t buf[BUF_SIZE], send_buf[BUF_SIZE]; //receiving buffer and sending buffer
	struct sockaddr remote;
	int n;
	socklen_t addr_len = sizeof(remote);
	struct sockaddr_in *remote_v4 = (struct sockaddr_in*)(&remote);

	while(1)
	{
		//an infinite loop that keeps receiving DNS queries and send back a reply
		//complete your code here
		memset(buf, 0, BUF_SIZE);
		memset(send_buf, 0, BUF_SIZE);
		if(recvfrom(sockfd, (char *)buf, BUFSIZ, 0, &remote, &addr_len) < 0)
		{
			perror("Err receiving msg.");
			exit(1);
		}

		// Process the request.
		int size = process_query(buf, send_buf, parttern_file);
		// Send back the answer.
		if(sendto(sockfd, (char *)send_buf, size, 0, &remote, addr_len) < 0)
		{
			perror("Err sending answer.");
		}
		else
		{
			printf("\nAnswer sent successfully.\n");
		}
		

	}
}

