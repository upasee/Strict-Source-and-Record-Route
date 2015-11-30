#include <stdio.h>
#include "unp.h"
#include <netinet/in.h>
#include <linux/if_ether.h>

#define RT_PROTOCOL 15526
#define MULTICAST_PORT 8000
#define MULTICAST_ADDR "225.0.0.1"

struct ip_list {
	char **ip_addr;
	int total_ips;
	int curr_ip_pos;
	char multicast_addr[30];
	int multicast_port;
};

char my_vm[5];
