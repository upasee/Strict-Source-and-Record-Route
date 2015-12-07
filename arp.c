#include "arp.h"
#include "hw_addrs.h"

int create_pf_pack_socket() {
    int sockfd;
    sockfd = Socket(PF_PACKET, SOCK_RAW, htons(PF_PACK_PROTO));
    return sockfd;
}

int create_listen_socket() {
    int sockfd;
    struct sockaddr_un servaddr;

    sockfd = Socket(AF_LOCAL, SOCK_STREAM, 0);
    unlink(SUN_PATH_ARP);
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sun_family = AF_LOCAL;
    strcpy(servaddr.sun_path, SUN_PATH_ARP);
    Bind(sockfd, (SA *) &servaddr, sizeof(servaddr));

    return sockfd;
}

void print_mac_to_string(char mac[6])
{
    int i =6;
    char *ptr = mac;
    do {
        printf("%.2x%s", *ptr++ & 0xff, (i == 1) ? " " : ":");
    } while (--i > 0);
    printf("\n");
}

void print_ethernet_and_arp(char *src_mac, char *dest_mac, struct arp_packet *arp){
    printf("\n");
    printf("Printing Ethernet Packet:\n");
    printf("Ethernet src HW address: ");
    print_mac_to_string(src_mac);
    printf("Ethernet dest HW address: ");
    print_mac_to_string(dest_mac);
    printf("\n");
    printf("Printing ARP Packet:\n");
    printf("ARP ID: %d\n", arp->id);
    printf("ARP source IP: %s\n", arp->src_IP);
    printf("ARP dest IP %s\n", arp->dest_IP);
    printf("ARP source HW address ");
    print_mac_to_string(arp->src_mac);
    printf("ARP dest HW address ");
    print_mac_to_string(arp->dest_mac);
    printf("\n");
}

void print_arp_cache_list() {
    struct arp_cache *arp_temp = arp_cache_head;
    while(arp_temp != NULL) {
        printf("IP address:\n");
        printf("%s\n", arp_temp->ip_addr);
        printf("MAC address:\n");
        print_mac_to_string(arp_temp->hw_addr);
        printf("Index: %d\n", arp_temp->sll_ifindex);
        printf("HAtype: %d\n", arp_temp->sll_hatype);
        printf("SOCKFD: %d\n", arp_temp->sockfd);
        arp_temp = arp_temp->cache_next;
    }
}

void add_to_arp_cache_list(char *ip_addr, unsigned char hw_addr[6], int sll_ifindex, int sll_hatype, int sockfd, int mac_flag) {
    struct arp_cache *arp_new = malloc(sizeof(struct arp_cache));
    int i;
    //	print_mac_to_string(hw_addr);
    strcpy(arp_new->ip_addr, ip_addr);
    if(mac_flag == 0)  {
        strcpy(arp_new->hw_addr,"");
    }
    else
        memcpy(arp_new->hw_addr, hw_addr, 6);
    arp_new->sll_ifindex = sll_ifindex;
    arp_new->sockfd = sockfd;
    arp_new->cache_next = NULL;

    if(arp_cache_head != NULL) {
        struct arp_cache *arp_temp = malloc(sizeof(struct arp_cache));
        while(arp_temp->cache_next != NULL) {
            arp_temp = arp_temp->cache_next;
        }
        arp_temp->cache_next = arp_new;
    }
    else {
        arp_cache_head = arp_new;
    }
}

int lookup_arp_cache(char *ip_addr, unsigned char hw_addr[6], int *sll_ifindex, int *sll_hatype, int *l_flag) {
    struct arp_cache *arp_temp = arp_cache_head;
    int i;
    int result = 0;

    strcpy(hw_addr, "");
    while(arp_temp != NULL) {
        if((strcmp(ip_addr, arp_temp->ip_addr) == 0) && arp_temp->hw_addr != NULL) {
            memcpy(hw_addr, arp_temp->hw_addr, 6);
            *sll_ifindex = arp_temp->sll_ifindex;
            *sll_hatype = arp_temp->sll_hatype;
            result = 1;
            *l_flag = 1;
            break;
        }
        arp_temp = arp_temp->cache_next;
    }
    return result;
}

void update_arp_cache(char *ip_addr, unsigned char hw_addr[6], int sll_ifindex, int sll_hatype, int sockfd) {
    struct arp_cache *arp_temp = arp_cache_head;
    int i;

    while(arp_temp != NULL) {
        if(strcmp(ip_addr, arp_temp->ip_addr) == 0) {
            memcpy(arp_temp->hw_addr, hw_addr, 6);
            arp_temp->sll_ifindex = sll_ifindex;
            arp_temp->sll_hatype = sll_hatype;
            arp_temp->sockfd = sockfd;
            break;
        }
        arp_temp = arp_temp->cache_next;
    }
}

void delete_from_arp_cache(char *ip_addr) {

    if(arp_cache_head != NULL) {
        if (strcmp(ip_addr, arp_cache_head->ip_addr) == 0)
        {
            struct arp_cache *temp = arp_cache_head;
            arp_cache_head = arp_cache_head->cache_next;
            return;
        }

        struct arp_cache *current = arp_cache_head->cache_next;
        struct arp_cache *previous = arp_cache_head;
        while (current != NULL && previous != NULL)
        {
            if (strcmp(ip_addr, current->ip_addr) == 0)
            {
                struct arp_cache *temp = current;
                previous->cache_next = current->cache_next;
                return;
            }
            previous = current;
            current = current->cache_next;
        }
    }

    return;
}

void send_arp_request(int sockfd, struct arp_packet *arp_req, struct hw_ip_pair *hi_pair, int conn_sockfd) {

    struct sockaddr_ll socket_address;
    void *buffer = (void *)malloc(ETH_FRAME_LEN);
    memset(buffer, 0, ETH_FRAME_LEN);
    unsigned char *etherhead = buffer;
    unsigned char *data = buffer + 14;
    struct ethhdr *eh = (struct ethhdr *)etherhead;
    int i;

    socket_address.sll_family = PF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_IP);
    socket_address.sll_hatype   = ARPHRD_ETHER;
    socket_address.sll_pkttype  = PACKET_BROADCAST;
    socket_address.sll_halen    = ETH_ALEN; 
    socket_address.sll_ifindex = hi_pair->if_index;

    for(i=0; i< 6; i++) {
        socket_address.sll_addr[i] = arp_req->dest_mac[i];
    }

    socket_address.sll_addr[6]  = 0x00;
    socket_address.sll_addr[7]  = 0x00;

    memcpy((void*)buffer, (void*)arp_req->dest_mac, ETH_ALEN);
    memcpy((void*)(buffer+ETH_ALEN), (void*)arp_req->src_mac, ETH_ALEN);
    eh->h_proto = htons(PF_PACK_PROTO);
    memcpy((void *)data, (void *)arp_req, sizeof(struct arp_packet));

    // Add partial entry to the ARP cache
    add_to_arp_cache_list(arp_req->dest_IP,"", -1, 0, conn_sockfd, 0);
    //	print_arp_cache_list();

    printf("Printing Ethernet Header and ARP Request Packet Sent\n");
    print_ethernet_and_arp(arp_req->src_mac, arp_req->dest_mac, arp_req);

    int send_result = sendto(sockfd, buffer, ETH_FRAME_LEN, 0, (struct sockaddr*)&socket_address, sizeof(socket_address));
}

void send_arp_reply(int sockfd, struct arp_packet *arp_rep, struct hw_ip_pair *hi_pair, int index) {

    struct sockaddr_ll socket_address;
    void *buffer = (void *)malloc(ETH_FRAME_LEN);
    memset(buffer, 0, ETH_FRAME_LEN);
    unsigned char *etherhead = buffer;
    unsigned char *data = buffer + 14;
    struct ethhdr *eh = (struct ethhdr *)etherhead;
    int i;

    socket_address.sll_family = PF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_IP);
    socket_address.sll_hatype   = ARPHRD_ETHER;
    socket_address.sll_pkttype  = PACKET_BROADCAST;
    socket_address.sll_halen    = ETH_ALEN; 
    socket_address.sll_ifindex = index;

    for(i=0; i<6; i++) {
        socket_address.sll_addr[i] = arp_rep->dest_mac[i];
    }

    socket_address.sll_addr[6]  = 0x00;
    socket_address.sll_addr[7]  = 0x00;

    memcpy((void*)buffer, (void*)arp_rep->dest_mac, ETH_ALEN);
    memcpy((void*)(buffer+ETH_ALEN), (void*)arp_rep->src_mac, ETH_ALEN);
    eh->h_proto = htons(PF_PACK_PROTO);
    memcpy((void *)data, (void *)arp_rep, sizeof(struct arp_packet));

    printf("Printing Ethernet Header and ARP Reply Packet Sent\n");
    print_ethernet_and_arp(arp_rep->src_mac, arp_rep->dest_mac, arp_rep);

    int send_result = sendto(sockfd, buffer, ETH_FRAME_LEN, 0, (struct sockaddr*)&socket_address, sizeof(socket_address));
}

void create_arp_request_packet(struct arp_packet *arp_req, char *destIP, struct hw_ip_pair *hi_pair) {
    int i=0;

    arp_req->dest_mac[0] = 0xff;
    arp_req->dest_mac[1] = 0xff;
    arp_req->dest_mac[2] = 0xff;
    arp_req->dest_mac[3] = 0xff;
    arp_req->dest_mac[4] = 0xff;
    arp_req->dest_mac[5] = 0xff;

    memcpy(arp_req->src_mac, hi_pair->hw_addr, 6);
    arp_req->id = ARP_ID;
    strcpy(arp_req->dest_IP, destIP);
    strcpy(arp_req->src_IP, hi_pair->ip_addr);
    arp_req->op = ARP_REQ;
}

void create_arp_reply_packet(struct arp_packet *arp_rep, char *destIP, struct hw_ip_pair *hi_pair, unsigned char dest_mac[6], int id) {

    memcpy(arp_rep->src_mac, hi_pair->hw_addr, 6);
    memcpy(arp_rep->dest_mac, dest_mac, 6);
    arp_rep->id = id;
    strcpy(arp_rep->dest_IP, destIP);
    strcpy(arp_rep->src_IP, hi_pair->ip_addr);
    arp_rep->op = ARP_REP;
}

void main() {

    struct hw_ip_pair *hi_pair;
    char IP_str[20], cache_hw_addr[6];
    fd_set rset;
    int cache_ifindex, cache_hatype;
    struct hw_addr HWaddr;

    hi_pair = malloc(sizeof(struct hw_ip_pair));
    get_hw_ip_pair(hi_pair);

    printf("My IP :%s,\t HW addr", hi_pair->ip_addr);
    print_mac_to_string(hi_pair->hw_addr);
    printf("\n");

    int pf_pack_sockfd = create_pf_pack_socket();
    void* buffer = (void*)malloc(ETH_FRAME_LEN);

    int listen_sockfd, conn_sockfd, clilen, n;
    struct sockaddr_un servaddr, cliaddr;
    char sendline[MAXLINE], recvline[MAXLINE];
    struct sockaddr_in *destIP = malloc(sizeof(struct sockaddr_in));
    char ip_addr[20];
    struct arp_packet *arp_req = malloc(sizeof(struct arp_packet));
    struct arp_packet *arp_rep = malloc(sizeof(struct arp_packet));
    struct arp_packet *arp_recv = malloc(sizeof(struct arp_packet));
    struct sockaddr_ll socket_address; 
    int ll_len = sizeof(struct sockaddr_ll);
    int i=0;

    listen_sockfd = Socket(AF_LOCAL, SOCK_STREAM, 0);
    unlink(SUN_PATH_ARP);
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sun_family = AF_LOCAL;
    strcpy(servaddr.sun_path, SUN_PATH_ARP);
    Bind(listen_sockfd, (SA *) &servaddr, sizeof(servaddr));
    Listen(listen_sockfd, LISTENQ);

    int lookup_flag=0;
    clilen = sizeof(struct sockaddr_un);
    while(1) {

        FD_ZERO(&rset);

        FD_SET(listen_sockfd, &rset);
        FD_SET(pf_pack_sockfd, &rset);
        FD_SET(conn_sockfd, &rset);
        int max;

        if(conn_sockfd != 0)
            max = max(max(listen_sockfd, conn_sockfd),pf_pack_sockfd);
        else	
            max = max(listen_sockfd,pf_pack_sockfd);
        int ret = select(max+1, &rset, NULL, NULL, NULL);

        if(FD_ISSET(listen_sockfd, &rset)) {
            conn_sockfd = Accept(listen_sockfd, (SA *) &cliaddr, &clilen);
            /*			n = read(conn_sockfd, destIP, sizeof(struct sockaddr_in));
                        Inet_ntop(AF_INET, &(destIP->sin_addr), ip_addr, 20);

            // Lookup for the <HW,IP> pair in the ARP cache
            lookup_arp_cache(ip_addr, cache_hw_addr, &cache_ifindex, &cache_hatype,&lookup_flag);


            if(lookup_flag == 0) {
            printf("Entry not found from cache\n");
            create_arp_request_packet(arp_req, ip_addr, hi_pair);
            send_arp_request(pf_pack_sockfd, arp_req, hi_pair, conn_sockfd);
            }
            else{
            printf("Entry found from cache\n");
            // Send from cache
            HWaddr.sll_ifindex = cache_ifindex;
            HWaddr.sll_hatype = cache_hatype;
            HWaddr.sll_halen = sizeof(cache_hatype);

            memcpy(HWaddr.mac_addr, cache_hw_addr,6); 

            print_mac_to_string(HWaddr.mac_addr);
            Write(conn_sockfd, (void *)&HWaddr, sizeof(HWaddr));
            close(conn_sockfd);

            }
            printf("Sent ARP request\n");
             */		}

        else if(ret!= -1 && FD_ISSET(conn_sockfd, &rset)) {
            n = read(conn_sockfd, destIP, sizeof(struct sockaddr_in));
            Inet_ntop(AF_INET, &(destIP->sin_addr), ip_addr, 20);

            // Lookup for the <HW,IP> pair in the ARP cache
            lookup_arp_cache(ip_addr, cache_hw_addr, &cache_ifindex, &cache_hatype,&lookup_flag);


            if(lookup_flag == 0) {
                create_arp_request_packet(arp_req, ip_addr, hi_pair);
                printf("send 1\n");
                send_arp_request(pf_pack_sockfd, arp_req, hi_pair, conn_sockfd);
            }   
            else{
                // Send from cache
                HWaddr.sll_ifindex = cache_ifindex;
                HWaddr.sll_hatype = cache_hatype;
                HWaddr.sll_halen = sizeof(cache_hatype);

                memcpy(HWaddr.mac_addr, cache_hw_addr,6);

                //				print_mac_to_string(HWaddr.mac_addr);
                Write(conn_sockfd, (void *)&HWaddr, sizeof(HWaddr));
                close(conn_sockfd);
                conn_sockfd = 0;
            }
        }

        else if(FD_ISSET(pf_pack_sockfd, &rset)) {

            Recvfrom(pf_pack_sockfd, buffer, ETH_FRAME_LEN, 0, (SA *)&socket_address, &ll_len);
            void *data = buffer + 14;
            arp_rep = (struct arp_packet *)data;
            if (arp_rep->id == ARP_ID){
                if(arp_rep->op == ARP_REQ) {
                    if(strcmp(arp_rep->dest_IP, hi_pair->ip_addr) == 0) {

                        printf("Printing Ethernet Header and ARP Request Packet Received\n");
                        print_ethernet_and_arp(arp_rep->src_mac, arp_rep->dest_mac, arp_rep);
                        add_to_arp_cache_list(arp_rep->src_IP, arp_rep->src_mac, socket_address.sll_ifindex, socket_address.sll_hatype, conn_sockfd, 1);
                        //						print_arp_cache_list();
                        create_arp_reply_packet(arp_recv, arp_rep->src_IP, hi_pair, arp_rep->src_mac, arp_rep->id);
                        send_arp_reply(pf_pack_sockfd, arp_recv, hi_pair, socket_address.sll_ifindex);
                    }
                    else {
                        update_arp_cache(arp_rep->src_IP, arp_rep->src_mac, socket_address.sll_ifindex, 0, conn_sockfd);
                    }
                    continue;
                }
                else if(arp_rep->op == ARP_REP) {
                    if(ret == -1) {
                        delete_from_arp_cache(arp_rep->src_IP);
                        //						print_arp_cache_list();
                        continue;
                    }

                    printf("Printing Ethernet Header and ARP Reply Packet Received\n");
                    print_ethernet_and_arp(arp_rep->src_mac, arp_rep->dest_mac, arp_rep);

                    update_arp_cache(arp_rep->src_IP, arp_rep->src_mac, socket_address.sll_ifindex, 0, conn_sockfd);
                    //					print_arp_cache_list();
                    HWaddr.sll_ifindex = socket_address.sll_ifindex;
                    HWaddr.sll_hatype = socket_address.sll_hatype;
                    HWaddr.sll_halen = socket_address.sll_halen;

                    memcpy(HWaddr.mac_addr, arp_rep->src_mac,6); 

                    //					print_mac_to_string(HWaddr.mac_addr);
                    Write(conn_sockfd, (void *)&HWaddr, sizeof(HWaddr));
                    close(conn_sockfd);
                    conn_sockfd = 0;
                    update_arp_cache(arp_rep->src_IP, arp_rep->src_mac, socket_address.sll_ifindex, 0, -1);
                    //					print_arp_cache_list();
                }
            }

        }
    }
}
