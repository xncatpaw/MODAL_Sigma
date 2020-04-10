#ifndef RAW_IP_H_
#define RAW_IP_H_

#include<stdint.h>


int send_raw_udp(uint8_t * _msg_buf, uint16_t _msg_len,
                char * _src_ip, uint16_t _src_prt,
                char * _dst_ip, uint16_t _dst_prt,
                int PRINT);

int send_raw_tcp(uint8_t * _msg_buf, uint16_t _msg_len,
                char * _src_ip, uint16_t _src_prt,
                char * _dst_ip, uint16_t _dst_prt,
                int PRINT);

#endif