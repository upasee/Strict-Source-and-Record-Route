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
    sockfd = Socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    return sockfd;
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

void create_ip_list(struct ip_list *ipl, int argc, char **argv) {

    int i=0;
    struct hostent *host;
    struct in_addr **addr_list;

    host = gethostbyname(my_vm);
    addr_list = (struct in_addr **)host->h_addr_list;	

    ipl->total_ips = argc;
    ipl->ip_addr = malloc(argc*sizeof(char *));
    ipl->ip_addr[0] = malloc(sizeof(20*sizeof(char)));
    strcpy(ipl->ip_addr[0], inet_ntoa(*addr_list[0]));

    while(i != argc) {
        if(i != 0) {
            host = gethostbyname(argv[i]);
            addr_list = (struct in_addr **)host->h_addr_list;
            ipl->ip_addr[i] = malloc(sizeof(20*sizeof(char)));
            strcpy(ipl->ip_addr[i], inet_ntoa(*addr_list[0]));
        }
        i++;
    }

    ipl->curr_ip_pos = 0;
    strcpy(ipl->multicast_addr, MULTICAST_ADDR); 
    strcpy(ipl->multicast_port, MULTICAST_PORT);
}

void print_ip_list(struct ip_list *ipl) {
    int i=0;
    while(i != ipl->total_ips) {
        printf("IP is %s \n", ipl->ip_addr[i]);
        i++;
    }
}

void send_tour_packet(int sockfd, struct ip_list *ipl) {

    struct iphdr *ip_hdr;
    struct sockaddr_in sin;
    char datagram[4096];

    printf("here1\n");
    ip_hdr = (struct iphdr *)malloc(sizeof(struct iphdr));

    ip_hdr->ihl = 5;
    ip_hdr->version = 4;
    ip_hdr->tot_len = sizeof(struct iphdr) + sizeof(struct ip_list);
    ip_hdr->protocol = RT_PROTOCOL;
    printf("here2\n");

    printf("current position %d\n", ipl->curr_ip_pos);
    printf("source ip %s\n", ipl->ip_addr[ipl->curr_ip_pos]);
    printf("dest ip %s\n", ipl->ip_addr[ipl->curr_ip_pos+1]);
    ip_hdr->saddr = inet_addr(ipl->ip_addr[ipl->curr_ip_pos]);
    ip_hdr->daddr = inet_addr(ipl->ip_addr[ipl->curr_ip_pos + 1]);
    ip_hdr->check = NULL;
    ip_hdr->ttl = 1;
    ip_hdr->id = 328;
    printf("here3\n");

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr  = ip_hdr->daddr;
    sin.sin_port = htons(15526);

    memcpy(datagram, ip_hdr, sizeof(struct iphdr));

    memcpy((datagram + sizeof(struct iphdr)), ipl, sizeof(ipl));

    socklen_t len;
    len = sizeof(sin);
    printf("sending\n");
    int ret =  sendto(sockfd, datagram, ip_hdr->tot_len, 0, (struct sockaddr *)&sin, len);
    printf("sent : return value %d\n", ret);

}

void main(int argc, char **argv) {

    int rt_sockfd = create_rt_socket();
    int pg_sockfd = create_pg_socket();
    int pf_sockfd = create_pf_pack_socket();
    struct ip_list ipl;
    int send_mcast_sockfd, recv_mcast_sockfd;
    struct sockaddr *sasend, *sarecv;
    socklen_t salen;
    const int on=1;

    get_my_vm();

    // Check whether the order is valid or not and check the vm name too
    if(check_tour(argc, argv)) {
        exit(0);
    }

    create_ip_list(&ipl, argc, argv);
    print_ip_list(&ipl);

    /* Send tour packet */
    //    send_tour_packet(rt_sockfd);

    /* UDP Socket */
    send_mcast_sockfd = Udp_client(MULTICAST_ADDR, MULTICAST_PORT, &sasend, &salen);
    recv_mcast_sockfd = Socket(sasend->sa_family, SOCK_DGRAM, 0);
    Setsockopt(recv_mcast_sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    sarecv = Malloc(salen);
    memcpy(sarecv, sasend, salen);
    Bind(recv_mcast_sockfd, sarecv, salen);

    Mcast_join(recv_mcast_sockfd, sasend, salen, NULL, 0);
    Mcast_set_loop(send_mcast_sockfd, 0);

    //Create IP Header
    if(ipl.total_ips != 1)
        send_tour_packet(rt_sockfd, &ipl);

    else{

        fd_set rset;
        FD_ZERO(&rset);
        FD_SET(rt_sockfd, &rset);


        Select(rt_sockfd+1, &rset, NULL, NULL, NULL);

        if (FD_ISSET(rt_sockfd, &rset)){
            struct sockaddr_in cliaddr;
            socklen_t len = sizeof(cliaddr);
            char mesg[4096];
            recvfrom(rt_sockfd, mesg, sizeof(mesg), 0, (SA *)&cliaddr, &len); 
            struct iphdr *iph = mesg;
            struct ip_list *ipl1 = (struct ip_list *)(mesg + sizeof(struct iphdr));
            ipl1->curr_ip_pos = ipl1->curr_ip_pos + 1;
            if (ipl1->curr_ip_pos == ipl1->total_ips - 1)
                printf("I am the destination\n");
            else{
                printf("forwarding the packet\n");
                send_tour_packet(rt_sockfd, ipl1);
            }
        }

    }

}
