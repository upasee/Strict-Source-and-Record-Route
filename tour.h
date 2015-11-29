#include <stdio.h>
#include "unp.h"
#include <netinet/in.h>
#include <linux/if_ether.h>

#define RT_PROTOCOL 15526

struct ip_list {
	char ip_addr[30];
	struct ip_list *ip_next;
};

char my_vm[5];
struct ip_list *ip_head;
