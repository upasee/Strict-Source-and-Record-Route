#include <stdio.h>
#include "unp.h"
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <netinet/ip_icmp.h>
#include "hw_addrs.h"

#define RT_PROTOCOL 155
#define MULTICAST_PORT "8000"
#define MULTICAST_ADDR "225.0.0.1"
#define ID 328
#define ICMP_ID 123
#define IP4_HDRLEN 20
#define ICMP_HDRLEN 8
#define DATALENGTH 56


struct ip_list {
	char ip_addr[30][15];
	int total_ips;
	int curr_ip_pos;
	char multicast_addr[30];
	char multicast_port[5];
};

char my_vm[5];

struct node_list{
    char ip[15];
    int seq;
    int ret_seq;
    struct node_list *next;
};
