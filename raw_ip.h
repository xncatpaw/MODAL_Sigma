#ifndef RAW_IP_H_
#define RAW_IP_H_

#include<stdint.h>

const static char * DEFAULT_IF = "eth0";


int send_raw_udp(int _sock_fd, 
                uint8_t * _msg_buf, uint16_t _msg_len,
                char * _src_ip, uint16_t _src_prt,
                char * _dst_ip, uint16_t _dst_prt,
                int PRINT);

int send_raw_tcp(int _sock_fd,
                uint8_t * _msg_buf, uint16_t _msg_len,
                char * _src_ip, uint16_t _src_prt,
                char * _dst_ip, uint16_t _dst_prt,
                int PRINT);

int send_raw_eth(int _sock_fd, int _ip_proto,
                uint8_t * _msg_buf, uint16_t _msg_len,
                uint8_t * _src_eth, uint8_t * _dst_eth,
                char * _src_ip, uint16_t _src_prt,
                char * _dst_ip, uint16_t _dst_prt,
                int PRINT);

#endif