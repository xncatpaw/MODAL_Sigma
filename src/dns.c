/*
 * dns.c
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
#include<netdb.h>
#include<stdbool.h>
#include<time.h>

#include "dns.h"




void send_dns_query(int sockfd, char *dns_server, char *host_name)
{
	//BEGIN_SOLUTION
	uint8_t buf[BUF_SIZE], *qname;
	struct sockaddr server;
	struct sockaddr_in *server_v4 = (struct sockaddr_in *)(&server);

	dns_header *dns = NULL;
	question *qdata = NULL;

	printf("The host name being resolved is: %s\n", host_name);

	server_v4->sin_family = AF_INET;
	server_v4->sin_port = htons(53);
	server_v4->sin_addr.s_addr = inet_addr(dns_server);

	//begin building the header

	//dns = (dns_header*)&buf;
	dns = (dns_header*)buf;
	build_dns_header(dns, 0, 0, 1, 0, 0, 0);

	//now the query part
	qname = (uint8_t*)&buf[sizeof(dns_header)]; //the query position
//	get_dns_name(qname, (uint8_t*)host_name);
//
//	qdata = (question*)&buf[sizeof(dns_header) + strlen((char*)qname) +1];
//	qdata->qtype = htons(TYPE_A);
//	qdata->qclass = htons(CLASS_IN);

	int offset = 0;
	build_name_section(qname, host_name, &offset);

	qdata = (question*)(qname + offset);

	qdata->qtype = htons(TYPE_A);
	qdata->qclass = htons(CLASS_IN);

	if(sendto(sockfd, (char*)buf,
			sizeof(dns_header) + sizeof(question) + strlen((char*)qname)+1,
			0, &server, sizeof(server)) < 0)
	{
		perror("DNS query sending failed. ");
	} else
	{
		printf("DNS query for %s sent out to %s \n\n", host_name, dns_server);
	}
	//END_SOLUTION
}





int parse_dns_query(uint8_t *buf, query *queries,
		res_record *answers, res_record *auth, res_record *addit)
{
	//BEGIN_SOLUTION
	dns_header *dns = NULL;
	dns = (dns_header*)buf;
	printf("The message header:\n");
	printf("\t Transaction ID: %d;\n", ntohs(dns->id));
	printf("\t Query(0)/Response(1): %d\n", dns->qr);
	printf("\t %d questions; \n", ntohs(dns->qd_count));
	printf("\t %d answers; \n", ntohs(dns->an_count));
	printf("\t %d authoritative servers; \n", ntohs(dns->ns_count));
	printf("\t %d additional records. \n\n", ntohs(dns->ar_count));

	uint8_t *p;
//	p = &buf[sizeof(dns_header) + strlen((char*)qname) +1 + sizeof(question)]; //jump to the answer part
	p = &buf[sizeof(dns_header)]; //jump over the dns header


	printf("==========================\n");
	printf("=====Queries section======\n");

	for(int i=0; i<ntohs(dns->qd_count); i++)
	{
		printf("Query No. %d\n", i+1);

		uint8_t qname[HOST_NAME_SIZE];
		int position = 0;
		get_domain_name(p, buf, qname, &position);
		queries[i].qname = malloc(HOST_NAME_SIZE);
		memset(queries[i].qname, 0, HOST_NAME_SIZE);
		strncpy((char*)(queries[i].qname), (char*)qname, strlen((char*)qname));
		printf("name: %s \n", queries[i].qname);
		p+= position;

		queries[i].ques = (question*)p;
		printf("query type: %d, class: %d\n",
				ntohs(queries[i].ques->qtype), ntohs(queries[i].ques->qclass));
		p+= sizeof(question);
	}

	if(ntohs(dns->an_count) > 0)
	{
		printf("=====Answers section======\n");
	}
	// answers
	for(int i=0; i<ntohs(dns->an_count); i++)
	{
		printf("Answers %d\n", i+1);
		//get the name field
		uint8_t name[HOST_NAME_SIZE];
		int position = 0;
		get_domain_name(p, buf, name, &position);
		answers[i].name = calloc(1, HOST_NAME_SIZE);
		strncpy((char*)(answers[i].name), (char*)name, strlen((char*)name));
		printf("name: %s \n", answers[i].name);

		p += position ; //jump to the next section
		answers[i].element = (r_element*)(p);
		printf("type: %d, class: %d, ttl: %d, rdlength: %d\n",
				ntohs(answers[i].element->type), ntohs(answers[i].element->_class),
				ntohl(answers[i].element->ttl), ntohs(answers[i].element->rdlength));

		int length = ntohs(answers[i].element->rdlength);
		p += sizeof(r_element); //2B type, 2B class, 4B ttl, 2B rdlength
			//pay attention that we can't simply use sizeof(r_element) here, because of padding
			//or we need to specify __attribute((packed)) when declaring the r_element
		if(ntohs(answers[i].element->type) == TYPE_A) //ipv4 address
		{
			answers[i].rdata = (uint8_t *)malloc(length);
			memset(answers[i].rdata, 0, length);
			memcpy(answers[i].rdata, p, length);

			char ip4[INET_ADDRSTRLEN];  // space to hold the IPv4 string
			inet_ntop(AF_INET, answers[i].rdata, ip4, INET_ADDRSTRLEN);
			printf("The IPv4 address is: %s\n", ip4);

		}
		p+=length;

		printf("====\n");
	}

	//authorities
	for(int i=0; i<ntohs(dns->ns_count); i++)
	{

	}

	//additional
	for(int i=0; i<ntohs(dns->ar_count); i++)
	{

	}

	printf("===========END============\n");
	printf("==========================\n");
	return ntohs(dns->id);
	//END_SOLUTION
}


void get_domain_name(uint8_t *p, uint8_t *buff, uint8_t *name, int *position)
{
	//this function is improved by Pierre-Jean. Thx
    // true if the buffer uses compression (see below)
    bool compressed = false;

    int i = 0;

    // real length of the buffer, that is if we use compression,
    // the length will be smaller
    //     eg. 01 62 c0 5f will have buffer_len 4
    //         but the actual host_name is longer, because
    //         we use compression and concatenate what is
    //         at position 5f immediatly after 01 62
    int buffer_len = -1;

    while(*p!=0)
    {
        // the rest of the chain points to somewhere else
        if ((*p & 0xc0) == 0xc0) {
            //	The pointer takes the form of a two octet sequence:
            //
            //	    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            //	    | 1  1|                OFFSET                   |
            //	    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            //
            //	The first two bits are ones. The OFFSET field specifies an offset from
            //	the start of the message (i.e., the first octet of the ID field in the
            //	domain header).

            uint16_t offset = ntohs(*((uint16_t*)p)) & 0x3fff;
            p = buff+offset;
            compressed = true;

            // +2 comes from c0 xx, where xx is the address
            // the pointer points to
            buffer_len = i+2;
        }
        uint8_t num = *((uint8_t*)p);
        strncpy((char*)(name+i), (char*)(p+1), num);
        p+= (num+1);
        i+= num;
        strncpy((char*)(name+i), ".", 1);
        i++;
    }
    *(name+i)='\0';

    // +1 because we take into account the nul length end character,
    // which is not present when using a pointer (ie. when we use
    // compression). Indeed, the pointer points to a chain already
    // ending by the \0 char
    if (compressed == false) buffer_len = i+1;

    // position can change both when there is compression
    // and when there is not. Thus, use not_compressed_len to see
    // if we moved forward in the chain
    if(buffer_len > 0) *position = buffer_len;
}

void get_dns_name(uint8_t *dns, uint8_t *host)
{
	char host_cp[HOST_NAME_SIZE];
	strncpy(host_cp, (char*)host, HOST_NAME_SIZE);

//	printf("host name: %s\n", host_cp);

	char *tk;
	tk = strtok(host_cp, ".");
	int i = 0;
	while(tk!=NULL)
	{
		//		sprintf(length, "%lu", strlen(tk));
		*(dns+i) = (uint8_t)(strlen(tk)); //set the number of chars in the label

		i++;
		strncpy((char*)(dns+i), tk, strlen(tk)); //the label

		i+= strlen(tk);
		tk = strtok(NULL,".");
	}
	*(dns+i) = '\0';
}

/**
 * exit with an error message
 */

void exit_with_error(char *message)
{
	fprintf(stderr, "%s\n", message);
	exit(EXIT_FAILURE);
}


void build_dns_header(dns_header *dns, int id, int query, int qd_count,
		int an_count, int ns_count, int ar_count)
{
//BEGIN_SOLUTION
	srand(time(NULL));

	if(id == 0)
		dns->id = (uint16_t)htons(rand()); //set a random id
	else
		dns->id = (uint16_t)htons(id);

	dns->qr = query;	//query
	dns->opcode = 0;	//standard query
	dns->aa = 0;	//no aa
	dns->tc = 0;	//not truncated
	dns->rd = 1;	//recursion desired

	dns->ra = 0;	//recursion not available
	dns->z = 0;	//must be 0
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0; //no error condition

	dns->qd_count = htons(qd_count); //  question
	dns->an_count = htons(an_count); //answer
	dns->ns_count = htons(ns_count); //authenticate
	dns->ar_count = htons(ar_count); //additional
//END_SOLUTION
}

void build_name_section(uint8_t *qname, char *host_name, int *position)
{
//BEGIN_SOLUTION
	get_dns_name(qname, (uint8_t*)host_name);
	*position = strlen((char*)qname) + 1; //calculate the offset
//END_SOLUTION
}



// In the first version, we do not use pattern match, but just str match.
int process_query(uint8_t *buf, uint8_t *send_buf, FILE *pattern_file)
{
	query queries[ANS_SIZE];
	res_record answers[ANS_SIZE], auth[ANS_SIZE], addit[ANS_SIZE];
	parse_dns_query(buf, queries, answers, auth, addit);
	dns_header *p_qur_hdr = (dns_header *)buf;
	int n_query = ntohs(((dns_header *)buf)->qd_count);

	// Copy the query header to the send header.
	//memcpy(send_buf, buf, sizeof(dns_header));
	// Build the DNS header.
	dns_header *p_ans_hdr = (dns_header *)send_buf;
	build_dns_header(p_ans_hdr, ntohs(p_qur_hdr->id), 0, n_query, n_query, 0, 0);
	uint8_t *p_data = send_buf + sizeof(dns_header);	// Pointer to the data part.
	uint8_t *p_data_orig = buf + sizeof(dns_header);
	uint8_t *p_current = p_data;
	

	// Build the Question section.
	question * qdata = NULL;
	//uint8_t *p_head_rr = NULL;	// Head of the current resource-record.
	for(int i=0; i<n_query; ++i)
	{
		const query * ptr_q = queries+i;	// Current query.

		int offset = 0;
		build_name_section(p_current, ptr_q->qname, &offset);
		qdata = (question *)(p_current + offset);
		qdata->qclass = ptr_q->ques->qclass;
		qdata->qtype = ptr_q->ques->qtype;

		p_current += (offset + sizeof(question));
	}

	// Build the Answer section.
	int an_count = 0;
	for(int i=0; i<n_query; ++i)
	{
		const query * ptr_q = queries+i; // The query to be processed.
		char qname[HOST_NAME_SIZE];		// The host name to resolve.
		uint8_t ip_addr[4];				//The buf to save ip addr resolved.
		memset(qname, 0, HOST_NAME_SIZE);
		memset(ip_addr, 0, 4);
		strncpy(qname, ptr_q->qname, strlen(ptr_q->qname));

		// Firstly we try to resolve the hostname.
		// If success, we construct this RR.
		// If not, we skip it, and change nothing to the send_buf.
		int SOLVED = 0;
		// If the pattern file is specified.
		if(pattern_file)
		{
			// Get back to the start of file.
			rewind(pattern_file);
			char * line_buf = NULL;
			size_t line_buf_size = 0;
			int line_size = 0;
			// Traverse all lines.
			do
			{
				line_size = getline(&line_buf, &line_buf_size, pattern_file);
				// Check the match.
				if(strstr(line_buf, qname) == NULL) // if no match.
					continue;
				// If match found.
				else
				{
					char * pos_end = strchr(line_buf, ' ');
					*pos_end = '\0';
					// Copy the resolved addr.
					inet_pton(AF_INET, line_buf, ip_addr);
					//p_current += 4;	// 4 is the length of IP addr.
					SOLVED = 1; // Indicating found in File.
					//SOLVED = 1;
					break;	// Stop the searching.
				}
			} while (line_size > 0);
		}
		if(SOLVED == 0)	// Not found in file.
		{
			// use gethostbyname.
    		struct hostent *tmp = gethostbyname(qname);
			if(!tmp)
			{
				char str_err[100];
				sprintf(str_err, "Err getting host for %s : ", qname);
				perror(str_err);
			}
			else
			{
				if(!tmp->h_addr_list)
				{
					char str_err[100];
					sprintf(str_err, "No host found for %s : ", qname);
					perror(str_err);
				}
				else
				{
					// copy the addr.
					memcpy(ip_addr, tmp->h_addr_list, 4);
					SOLVED = 1;	// SOLVED.
				}
			}
		}

		if(!SOLVED)	// If the hostname cannot be solved.
		{
			continue;
		}

		// This part will be executed only when the host is solved.
		// The name part.
		int offset = 0;
		build_name_section(p_current, qname, &offset);
		p_current += offset;
		// The r_element part.
		r_element * p_element = (r_element *)p_current;
		p_element->type = htons(TYPE_A);
		p_element->_class = htons(CLASS_IN);
		p_element->ttl = htonl(3600);
		p_element->rdlength = htons(4);
		offset = sizeof(r_element);
		p_current += offset;
		// The data.
		memcpy(p_current, ip_addr, 4);
		p_current += 4;

		++an_count;
	}

	// Check the an_count.
	if(an_count != n_query)
	{
		build_dns_header(p_ans_hdr, ntohs(p_qur_hdr->id), 1, n_query, an_count, 0, 0);
	}

	return (p_current - send_buf);
}