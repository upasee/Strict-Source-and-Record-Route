#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "unp.h"
#include <linux/if_packet.h>
#include <netinet/if_ether.h>

#define SUN_PATH_ARP "/tmp/umehta"
#define ARP_REQ 1
#define ARP_REP	2
#define ARP_ID 15526

struct areq_packet {
	struct sockaddr *IPaddr;
	struct hwaddr *HWaddr;
};


struct hw_addr {
	int sll_ifindex;
	unsigned short sll_hatype;
	unsigned char sll_halen;
	unsigned char mac_addr[6];
};

struct arp_packet {
	int id;
	unsigned char src_mac[6];
	unsigned char dest_mac[6];
	int op;
	char src_IP[20];
	char dest_IP[20];
};

struct arp_cache {
	char ip_addr[20];
	unsigned char hw_addr[6];
	int sll_ifindex;
	int sll_hatype;
	int sockfd;
	struct arp_cache *cache_next;
};

struct arp_cache *arp_cache_head;
