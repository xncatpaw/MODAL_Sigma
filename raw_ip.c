/**
 * Defining functions to send a raw ip packet.
 * Ip addr and ports are specified by params.
 * Author : Benxin ZHONG, 10 Avr. 2020.
*/
#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<stdlib.h>
#include<netinet/in.h>
#include<arpa/inet.h>

#include "header.h"
#include "raw_ip.h"

const int BUF_SIZE = 65535;


/**
 * Name : gen_packet
 *  Function used to generate the raw ip packet.
 * Param(s) :   
 *  # Out :
 *  pkt_buf,    uint8_t *,  the buffer to the packet to be generated.
 *  p_pkt_len,  uint16_t *, the pointer to the length of packet generated.
 *  # IN : 
 *  _pkt_buf_len uint16_t,  the size of buffer pkt_buf.
 *  _msg_buf,   uint8_t *,  the buffer to message.
 *  _msg_len,   uint16_t,   length of msg.
 *  _src_ip,    char *,     a string of the source ip addr.
 *  _src_prt,   uint16_t,   the source port num.
 *  _dst_ip,    char *,     a string of the dest ip addr.
 *  _dst_prt,   uint16_t,   the dest port num.
 * Return :
 *  None
*/
void gen_udp_packet(uint8_t * pkt_buf, uint16_t * p_pkt_len, uint16_t _pkt_buf_len,
                uint8_t * _msg_buf, uint16_t _msg_len,
                char * _src_ip, uint16_t _src_prt, 
                char * _dst_ip, uint16_t _dst_prt)
{
    // pointer to the whole packet
    uint8_t * p_pkt = pkt_buf;
    /*
    // pointer to the eth header.
    struct ethhdr * p_ethhdr = (struct ethhdr *) p_pkt;
    uint16_t ethhdr_len = sizeof(struct ethhdr);
    */
    // pointer to the ip header.
    struct iphdr * p_iphdr = (struct iphdr *) (p_pkt);
    uint16_t iphdr_len = sizeof(struct iphdr);
    // pointer to the udp header.
    struct udphdr * p_udphdr = (struct udphdr *) (p_pkt + iphdr_len);
    uint16_t udphdr_len = sizeof(struct udphdr);
    // pointer to the data field.
    uint8_t * p_data = p_pkt  + iphdr_len + udphdr_len;
    uint16_t hdr_len = (iphdr_len + udphdr_len);
    uint16_t data_len = _msg_len;
    uint16_t tot_len = hdr_len + data_len;
    tot_len += tot_len % 2;

    // init the buffer as 0.
    memset(pkt_buf, 0, (size_t)_pkt_buf_len);

    /*
    // Fill the eth header.
    for(int i=0; i < ETH_ALEN; ++ i)
    {
        p_ethhdr->h_dest[i] = _dst_l2[i];
        p_ethhdr->h_source[i] = _src_l2[i];
    }
    p_ethhdr->h_proto = 8;
    */

    // Data field
    memcpy(p_data, _msg_buf, (size_t)_msg_len);

    // Fill the ip header.
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(_dst_prt);
    inet_pton(AF_INET, _dst_ip, &(dest.sin_addr));

    p_iphdr->ihl = 5;
    p_iphdr->version = 4;
    p_iphdr->tos = 0;
    p_iphdr->tot_len = htons(tot_len);
    p_iphdr->frag_off = 0;
    p_iphdr->ttl = 64;
    p_iphdr->protocol = 17;
    p_iphdr->check = 0;
    inet_pton(AF_INET, _src_ip, &(p_iphdr->saddr));
    p_iphdr->daddr = dest.sin_addr.s_addr;
    p_iphdr->check = checksum(p_iphdr, iphdr_len);


    // Fill the UDP header.
    p_udphdr->source = htons(_src_prt);
    p_udphdr->dest = dest.sin_port;
    p_udphdr->len = htons(tot_len-iphdr_len);
    p_udphdr->check = 0;
    // pseudo header.
    uint8_t * psd_udp_pyld = malloc(_pkt_buf_len);
    memset(psd_udp_pyld, 0, _pkt_buf_len);
    struct pseudo_udp_header *p_psh = (struct pseudo_udp_header *)psd_udp_pyld;
    p_psh->source_address = p_iphdr->saddr;
    p_psh->dest_address = p_iphdr->daddr;
    p_psh->protocol = p_iphdr->protocol;
    p_psh->udp_length = p_udphdr->len;

    uint8_t *udp_hdr_cpy = psd_udp_pyld + sizeof(struct pseudo_udp_header);
    // copy
    memcpy(udp_hdr_cpy, p_udphdr, (size_t)ntohs(p_udphdr->len));
    // checksum
    p_udphdr->check = checksum(psd_udp_pyld, 
                                sizeof(struct pseudo_udp_header)+ntohs(p_udphdr->len));
    free(psd_udp_pyld);



    // Return .
    *p_pkt_len = tot_len;
    return;
}


/**
 * Name : gen_tcp_packet
 *  Function used to generate the raw ip tcp packet.
 * Param(s) :   
 *  # Out :
 *  pkt_buf,    uint8_t *,  the buffer to the packet to be generated.
 *  p_pkt_len,  uint16_t *, the pointer to the length of packet generated.
 *  # IN : 
 *  _pkt_buf_len uint16_t,  the size of buffer pkt_buf.
 *  _msg_buf,   uint8_t *,  the buffer to message.
 *  _msg_len,   uint16_t,   length of msg.
 *  _src_ip,    char *,     a string of the source ip addr.
 *  _src_prt,   uint16_t,   the source port num.
 *  _dst_ip,    char *,     a string of the dest ip addr.
 *  _dst_prt,   uint16_t,   the dest port num.
 * Return :
 *  None
*/
void gen_tcp_packet(uint8_t * pkt_buf, uint16_t * p_pkt_len, uint16_t _pkt_buf_len,
                uint8_t * _msg_buf, uint16_t _msg_len,
                char * _src_ip, uint16_t _src_prt, 
                char * _dst_ip, uint16_t _dst_prt)
{
    // pointer to the whole packet
    uint8_t * p_pkt = pkt_buf;
    /*
    // pointer to the eth header.
    struct ethhdr * p_ethhdr = (struct ethhdr *) p_pkt;
    uint16_t ethhdr_len = sizeof(struct ethhdr);
    */
    // pointer to the ip header.
    struct iphdr * p_iphdr = (struct iphdr *) (p_pkt);
    uint16_t iphdr_len = sizeof(struct iphdr);
    // pointer to the udp header.
    struct tcphdr * p_tcphdr = (struct tcphdr *) (p_pkt + iphdr_len);
    uint16_t tcphdr_len = sizeof(struct tcphdr);
    // pointer to the data field.
    uint8_t * p_data = p_pkt  + iphdr_len + tcphdr_len;
    uint16_t hdr_len = (iphdr_len + tcphdr_len);
    uint16_t data_len = _msg_len;
    uint16_t tot_len = hdr_len + data_len;
    tot_len += tot_len % 2;

    // init the buffer as 0.
    memset(pkt_buf, 0, (size_t)_pkt_buf_len);

    // Data field
    memcpy(p_data, _msg_buf, (size_t)_msg_len);

    // Fill the ip header.
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(_dst_prt);
    inet_pton(AF_INET, _dst_ip, &(dest.sin_addr));

    p_iphdr->ihl = 5;
    p_iphdr->version = 4;
    p_iphdr->tos = 0;
    p_iphdr->tot_len = htons(tot_len);
    p_iphdr->frag_off = 0;
    p_iphdr->ttl = 64;
    p_iphdr->protocol = 6;      // TCP protocol
    p_iphdr->check = 0;
    inet_pton(AF_INET, _src_ip, &(p_iphdr->saddr));
    p_iphdr->daddr = dest.sin_addr.s_addr;
    p_iphdr->check = checksum(p_iphdr, iphdr_len);


    // Fill the UDP header.
    p_tcphdr->source = htons(_src_prt);
    p_tcphdr->dest = dest.sin_port;
    p_tcphdr->seq = htonl(0);
    p_tcphdr->ack_seq = htonl(0);
    p_tcphdr->doff = tcphdr_len/4;
    p_tcphdr->syn = 1;
    p_tcphdr->check = 0;
    // TCP and UDP pseudo header has the same structure.
    uint8_t * psd_tcp_pyld = malloc(_pkt_buf_len);
    memset(psd_tcp_pyld, 0, _pkt_buf_len);
    struct pseudo_udp_header *p_psh = (struct pseudo_udp_header *)psd_tcp_pyld;
    p_psh->source_address = p_iphdr->saddr;
    p_psh->dest_address = p_iphdr->daddr;
    p_psh->protocol = p_iphdr->protocol;
    p_psh->udp_length = htons(tot_len-iphdr_len);

    uint8_t *tcp_hdr_cpy = psd_tcp_pyld + sizeof(struct pseudo_udp_header);
    // copy
    memcpy(tcp_hdr_cpy, p_tcphdr, (size_t)(tot_len-iphdr_len));
    // checksum
    p_tcphdr->check = checksum(psd_tcp_pyld, 
                                sizeof(struct pseudo_udp_header)+(tot_len-iphdr_len));
    free(psd_tcp_pyld);


    // Return .
    *p_pkt_len = tot_len;
    return;
}


/**
 * Name : send_raw_udp
 * Param(s) : 
 *  # IN :
 *  _msg_buf,   uint8_t *,  the buffer to message.
 *  _msg_len,   uint16_t,   length of msg.
 *  _src_ip,    char *,     a string of the source ip addr.
 *  _src_prt,   uint16_t,   the source port num.
 *  _dst_ip,    char *,     a string of the dest ip addr.
 *  _dst_prt,   uint16_t,   the dest port num.
 *  PRINT,      int,        whether print the errs and sucs.
 * Return :
 *  result,     int,        0 if success. -1 if not.
*/
int send_raw_udp(uint8_t * _msg_buf, uint16_t _msg_len,
                char * _src_ip, uint16_t _src_prt,
                char * _dst_ip, uint16_t _dst_prt,
                int PRINT)
{
    // Get the socket number.
    int sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sock_fd < 0)
    {
        if(PRINT)
            perror("Err creating raw socket.\n");
        return -1;
    }
    else
    {
        if(PRINT)
            printf("Raw socket created.\n");
    }
    
    // 1 = on, 0 = off.
    int hincl = 1;  
    setsockopt(sock_fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));
	if(sock_fd < 0)
	{
        if(PRINT)
		    perror("Error configuring raw socket. ");
        close(sock_fd);
        return -1;
	}
	else
	{
		//printf("Raw socket configured.\n");
	}

    // The destination
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(_dst_prt);
    inet_pton(AF_INET, _dst_ip, &(dest.sin_addr));

    // Define the buffer.
    uint8_t * pkt_buf = malloc(BUF_SIZE);
    memset(pkt_buf, 0, BUF_SIZE);
    // The lenth of packet.
    uint16_t tot_len = 0;

    // Generate the packet.
    gen_udp_packet(pkt_buf, &tot_len, BUF_SIZE, 
                _msg_buf, _msg_len,
                _src_ip, _src_prt,
                _dst_ip, _dst_prt);

    // Send the msg.
    logfile = fopen("log.txt", "a");
    if(logfile==NULL)
    {
        if(PRINT)
            perror("Unable to open log file.\n");
    }

    if(sendto(sock_fd, pkt_buf, tot_len, 0,
                (struct sockaddr *) &dest, sizeof(dest)) < 0)
    {
        if(PRINT)
            perror("Error sending raw socket. \n");
        close(sock_fd);
        return -1;
    }
    else
    {
        printf("Raw socket sent, total length is %d.\n", tot_len);
        if(logfile != NULL)
        {
            // to show the packet.
            uint8_t *packet_cpy = malloc(BUF_SIZE);
            memset(packet_cpy, 0, BUF_SIZE);
            int ethhdr_size = sizeof(struct ethhdr);
            uint8_t *iphdr_cpy = packet_cpy + ethhdr_size;
            memcpy(iphdr_cpy, pkt_buf, tot_len);
            print_udp_packet(packet_cpy, ethhdr_size+tot_len);

            free(packet_cpy);
        }

        close(sock_fd);
        return 0;
    }
    
}


/**
 * Name : send_raw_tcp
 * Param(s) : 
 *  # IN :
 *  _msg_buf,   uint8_t *,  the buffer to message.
 *  _msg_len,   uint16_t,   length of msg.
 *  _src_ip,    char *,     a string of the source ip addr.
 *  _src_prt,   uint16_t,   the source port num.
 *  _dst_ip,    char *,     a string of the dest ip addr.
 *  _dst_prt,   uint16_t,   the dest port num.
 *  PRINT,      int,        whether print the errs and sucs.
 * Return :
 *  result,     int,        0 if success. -1 if not.
*/
int send_raw_tcp(uint8_t * _msg_buf, uint16_t _msg_len,
                char * _src_ip, uint16_t _src_prt,
                char * _dst_ip, uint16_t _dst_prt,
                int PRINT)
{
    // Get the socket number.
    int sock_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sock_fd < 0)
    {
        if(PRINT)
            perror("Err creating raw socket.\n");
        return -1;
    }
    else
    {
        if(PRINT)
            printf("Raw socket created.\n");
    }
    
    // 1 = on, 0 = off.
    int hincl = 1;  
    setsockopt(sock_fd, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));
	if(sock_fd < 0)
	{
        if(PRINT)
		    perror("Error configuring raw socket. ");

        close(sock_fd);
        return -1;
	}
	else
	{
		//printf("Raw socket configured.\n");
	}

    // The destination
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(_dst_prt);
    inet_pton(AF_INET, _dst_ip, &(dest.sin_addr));

    // Define the buffer.
    uint8_t * pkt_buf = malloc(BUF_SIZE);
    memset(pkt_buf, 0, BUF_SIZE);
    // The lenth of packet.
    uint16_t tot_len = 0;

    // Generate the packet.
    gen_tcp_packet(pkt_buf, &tot_len, BUF_SIZE, 
                _msg_buf, _msg_len,
                _src_ip, _src_prt,
                _dst_ip, _dst_prt);

    // Send the msg.
    logfile = fopen("log.txt", "a");
    if(logfile==NULL)
    {
        if(PRINT)
            perror("Unable to open log file.\n");
    }

    if(sendto(sock_fd, pkt_buf, tot_len, 0,
                (struct sockaddr *) &dest, sizeof(dest)) < 0)
    {
        if(PRINT)
            perror("Error sending raw socket. \n");
        close(sock_fd);
        return -1;
    }
    else
    {
        printf("Raw socket sent, total length is %d.\n", tot_len);
        if(logfile != NULL)
        {
            // to show the packet.
            uint8_t *packet_cpy = malloc(BUF_SIZE);
            memset(packet_cpy, 0, BUF_SIZE);
            int ethhdr_size = sizeof(struct ethhdr);
            uint8_t *iphdr_cpy = packet_cpy + ethhdr_size;
            memcpy(iphdr_cpy, pkt_buf, tot_len);
            print_tcp_packet(packet_cpy, ethhdr_size+tot_len);

            free(packet_cpy);
        }

        close(sock_fd);
        return 0;
    }
    
}