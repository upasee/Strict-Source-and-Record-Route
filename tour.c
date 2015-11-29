#include "tour.h"

int create_rt_socket() {

	int sockfd;
	const int on=1;
	sockfd = Socket(AF_INET, SOCK_RAW, RT_PROTOCOL);
	Setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
	return sockfd;
}

int create_pg_socket() {
	
	int sockfd;
	sockfd = Socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	return sockfd;
}

int create_pf_pack_socket() {
	int sockfd;
	sockfd = Socket(PF_PACKET, SOCK_RAW, ETH_P_IP);
	return sockfd;
}

int create_udp_socket() {
	int sockfd;
	return 0;
}

void get_my_vm() {
	gethostname(my_vm, 5);

}

int check_tour(int argc, char **argv) {
	int i=0;
	char prev_vm[5];
	struct hostent *host;

	strcpy(prev_vm, "");

	while(i != argc) {
		if(i != 0) {
			if(i == 1 && strcmp(argv[i],my_vm) == 0) {
				printf("Invalid input \n");
				return -1;
			}

			if(strncmp(argv[i],"vm",2) != 0) {
				printf("Invalid input \n");
				return -1;
			}

			if((host = gethostbyname(argv[i])) == NULL) {
				printf("Invalid input \n");
				return -1;
			}

			if(strcmp(prev_vm, argv[i]) == 0) {
				printf("Invalid input \n");
				return -1;
			}
			strcpy(prev_vm, argv[i]);
		}
		i++;
	}
	return 0;
}

void create_ip_list(int argc, char **argv) {
	
	int i=0;
	struct hostent *host;
	struct in_addr **addr_list;
	
	host = gethostbyname(my_vm);
	addr_list = (struct in_addr **)host->h_addr_list;	

	ip_head = malloc(sizeof(struct ip_list));
	strcpy(ip_head->ip_addr, inet_ntoa(*addr_list[0]));
	ip_head->ip_next = NULL;

	while(i != argc) {
		if(i != 0) {
			
			host = gethostbyname(argv[i]);
			addr_list = (struct in_addr **)host->h_addr_list;

			struct ip_list *new_ip = malloc(sizeof(struct ip_list));
			strcpy(new_ip->ip_addr, inet_ntoa(*addr_list[0]));
			new_ip->ip_next = NULL;

			struct ip_list *ip_temp = ip_head;
			while(ip_temp->ip_next != NULL) {
				ip_temp = ip_temp->ip_next;
			}
			ip_temp->ip_next = new_ip;
		}
		i++;
	}
}

void print_ip_list() {
	struct ip_list *ip_temp = ip_head;
	while(ip_temp != NULL) {
		printf("IP is %s \n",ip_temp->ip_addr);
		ip_temp = ip_temp->ip_next;
	}
}

void main(int argc, char **argv) {
	
	int rt_sockfd = create_rt_socket();
	int pg_sockfd = create_pg_socket();
	int pf_sockfd = create_pf_pack_socket();
	int udp_sockfd = create_udp_socket();

	get_my_vm();

	// Check whether the order is valid or not and check the vm name too
	if(check_tour(argc, argv)) {
		exit(0);
	}

	create_ip_list(argc, argv);
	print_ip_list();

}