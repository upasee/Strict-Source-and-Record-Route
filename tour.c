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

void main() {
	
	int rt_sockfd = create_rt_socket();
	int pg_sockfd = create_pg_socket();
	int pf_sockfd = create_pf_pack_socket();
	int udp_sockfd = create_udp_socket();

	printf("rt socket returned is %d \n", rt_sockfd);
	printf("pg socket returned is %d \n", pg_sockfd);
	printf("pf packet socket returned is %d \n", pf_sockfd);
}