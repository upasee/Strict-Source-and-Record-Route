#include "tour.h"
#include "arp.h"

char my_hw_addr[6];
int eth0_index;
char *my_ip;
struct node_list *head;
int stop_ping_flag = 0;

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


int areq(struct sockaddr_in *IPaddr, socklen_t sockaddrlen, struct hw_addr *HWaddr) {
    int sockfd;
    struct sockaddr_un servaddr;
    int listen_sockfd;
    unsigned char hw_temp[6];
    struct timeval tval;
    fd_set rset;

    tval.tv_sec = 5;
    tval.tv_usec = 0;
    listen_sockfd = Socket(AF_LOCAL, SOCK_STREAM, 0);

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sun_family = AF_LOCAL;
    strcpy(servaddr.sun_path, SUN_PATH_ARP);
    Connect(listen_sockfd, (SA *) &servaddr, sizeof(servaddr));

    Write(listen_sockfd, IPaddr, sockaddrlen);

    FD_ZERO(&rset);
    FD_SET(listen_sockfd, &rset);

    Select(listen_sockfd+1, &rset, NULL, NULL, &tval);

    if(FD_ISSET(listen_sockfd, &rset)) {
        Read(listen_sockfd, (void *)HWaddr, sizeof(struct hw_addr));
    }
    return listen_sockfd;
}

void create_ip_list(struct ip_list *ipl, int argc, char **argv) {

    int i=0;
    struct hostent *host;
    struct in_addr **addr_list;

    host = gethostbyname(my_vm);
    addr_list = (struct in_addr **)host->h_addr_list;	

    ipl->total_ips = argc;
    strcpy(ipl->ip_addr[0], inet_ntoa(*addr_list[0]));

    while(i != argc) {
        if(i != 0) {
            host = gethostbyname(argv[i]);
            addr_list = (struct in_addr **)host->h_addr_list;
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

    ip_hdr = (struct iphdr *)malloc(sizeof(struct iphdr));

    ip_hdr->ihl = 5;
    ip_hdr->version = 4;
    ip_hdr->tot_len = sizeof(struct iphdr) + sizeof(struct ip_list);
    ip_hdr->protocol = RT_PROTOCOL;

    ip_hdr->saddr = inet_addr(ipl->ip_addr[ipl->curr_ip_pos]);
    ip_hdr->daddr = inet_addr(ipl->ip_addr[ipl->curr_ip_pos + 1]);
    ip_hdr->check = 0;
    ip_hdr->ttl = 1;
    ip_hdr->id = ID;

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr  = ip_hdr->daddr;
    sin.sin_port = htons(15526);

    memcpy(datagram, ip_hdr, sizeof(struct iphdr));

    memcpy((datagram + sizeof(struct iphdr)), ipl, sizeof(struct ip_list));

    socklen_t len;
    len = sizeof(sin);
    sendto(sockfd, datagram, ip_hdr->tot_len, 0, (struct sockaddr *)&sin, len);


}

int get_vm_num(char *ip){
    struct in_addr ipv4addr;
    Inet_pton(AF_INET, ip, &ipv4addr);

    struct hostent *host = gethostbyaddr(&ipv4addr, sizeof(ipv4addr), AF_INET);
    char *num_str = host->h_name;
    char str[4];
    strcpy(str, num_str+2);
    int num = atoi(str);
    return num;
}

uint16_t checksum (uint16_t *addr, int len)
{
    int count = len;
    register uint32_t sum = 0;
    uint16_t answer = 0;

    // Sum up 2-byte values until none or only one byte left.
    while (count > 1) {
        sum += *(addr++);
        count -= 2;
    }

    // Add left-over byte, if any.
    if (count > 0) {
        sum += *(uint8_t *) addr;
    }

    // Fold 32-bit sum into 16 bits; we lose information by doing this,
    // increasing the chances of a collision.
    // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Checksum is one's compliment of sum.
    answer = ~sum;

    return (answer);
}

uint16_t icmp4_checksum (struct icmp *icmphdr, uint8_t *payload, int payloadlen)
{
    char buf[IP_MAXPACKET];
    char *ptr;
    int chksumlen = 0;
    int i;

    ptr = &buf[0];  // ptr points to beginning of buffer buf

    // Copy Message Type to buf (8 bits)
    memcpy (ptr, &(icmphdr->icmp_type), sizeof (icmphdr->icmp_type));
    ptr += sizeof (icmphdr->icmp_type);
    chksumlen += sizeof (icmphdr->icmp_type);

    // Copy Message Code to buf (8 bits)
    memcpy (ptr, &(icmphdr->icmp_code), sizeof (icmphdr->icmp_code));
    ptr += sizeof (icmphdr->icmp_code);
    chksumlen += sizeof (icmphdr->icmp_code);

    // Copy ICMP checksum to buf (16 bits)
    // Zero, since we don't know it yet
    *ptr = 0; ptr++;
    *ptr = 0; ptr++;
    chksumlen += 2;

    // Copy Identifier to buf (16 bits)
    memcpy (ptr, &(icmphdr->icmp_id), sizeof (icmphdr->icmp_id));
    ptr += sizeof (icmphdr->icmp_id);
    chksumlen += sizeof (icmphdr->icmp_id);

    // Copy Sequence Number to buf (16 bits)
    memcpy (ptr, &(icmphdr->icmp_seq), sizeof (icmphdr->icmp_seq));
    ptr += sizeof (icmphdr->icmp_seq);
    chksumlen += sizeof (icmphdr->icmp_seq);

    // Copy payload to buf
    memcpy (ptr, payload, payloadlen);
    ptr += payloadlen;
    chksumlen += payloadlen;

    // Pad to the next 16-bit boundary
    for (i=0; i<payloadlen%2; i++, ptr++) {
        *ptr = 0;
        ptr++;
        chksumlen++;
    }

    return checksum ((uint16_t *) buf, chksumlen);
}

void get_vm_name(int no, char *vm){
    vm[0] = 'v';
    vm[1] = 'm';
    vm[2] = no + '0';
    return;
}

void send_icmp_echo_request(int sockfd, char *ip, int seq){
    struct sockaddr_ll socket_address;
    void *buffer = (void *)malloc(ETH_FRAME_LEN);
    unsigned char *etherhead = buffer;
    unsigned char *data = buffer + 14;
    struct ethhdr *eh = (struct ethhdr *)etherhead;

    memset(&socket_address, 0, sizeof(struct sockaddr_ll));
    memset(buffer, 0, ETH_FRAME_LEN);

    int target_vmno = get_vm_num(ip);
    char target_vm[5];
    get_vm_name(target_vmno, target_vm);
    struct hw_addr *HWaddr = malloc(sizeof(struct hw_addr));
    struct hostent *host = gethostbyname(target_vm);
    struct in_addr **addr_list;
    char IPaddr[15];
    addr_list = (struct in_addr **)host->h_addr_list;
    strcpy(IPaddr, inet_ntoa(*addr_list[0]));

    struct sockaddr_in *destIP = malloc(sizeof(struct sockaddr_in));
    inet_pton(AF_INET, IPaddr, &(destIP->sin_addr));

    areq(destIP, sizeof(struct sockaddr_in), HWaddr);



    unsigned char dest_mac[6];

    memcpy(dest_mac, HWaddr->mac_addr, 6);


    socket_address.sll_family   = PF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_IP);
    socket_address.sll_pkttype  = PACKET_OUTGOING;
    socket_address.sll_halen    = ETH_ALEN;

    memcpy((void*)buffer, (void*)dest_mac, ETH_ALEN);


    socket_address.sll_addr[0]  = HWaddr->mac_addr[0];
    socket_address.sll_addr[1]  = HWaddr->mac_addr[1];
    socket_address.sll_addr[2]  = HWaddr->mac_addr[2];
    socket_address.sll_addr[3]  = HWaddr->mac_addr[3];
    socket_address.sll_addr[4]  = HWaddr->mac_addr[4];
    socket_address.sll_addr[5]  = HWaddr->mac_addr[5];

    socket_address.sll_addr[6]  = 0x00;/*not used*/
    socket_address.sll_addr[7]  = 0x00;/*not used*/

    eh->h_proto = htons(ETH_P_IP);


    unsigned char src_mac[6];

    strcpy(src_mac, my_hw_addr);

    socket_address.sll_ifindex  = eth0_index;

    memcpy((void*)(buffer+ETH_ALEN), (void*)src_mac, ETH_ALEN);

    struct ip *iphdr = (struct ip *)malloc(sizeof(struct ip));
    memset(iphdr, 0, sizeof(struct ip));

    iphdr->ip_hl = 5;
    iphdr->ip_v = 4;
    iphdr->ip_tos = 0;

    iphdr->ip_len = htons (IP4_HDRLEN + ICMP_HDRLEN + DATALENGTH);

    iphdr->ip_id = ID;


    int ret1 = inet_pton (AF_INET, ip, &(iphdr->ip_dst));
    int ret2 = inet_pton (AF_INET, my_ip, &(iphdr->ip_src));


    int ip_flags[4];
    ip_flags[0] = 0;

    // Do not fragment flag (1 bit)
    ip_flags[1] = 0;

    // More fragments following flag (1 bit)
    ip_flags[2] = 0;

    // Fragmentation offset (13 bits)
    ip_flags[3] = 0;

    iphdr->ip_off = htons ((ip_flags[0] << 15)
            + (ip_flags[1] << 14)
            + (ip_flags[2] << 13)
            +  ip_flags[3]);

    iphdr->ip_ttl = 1;
    iphdr->ip_p = IPPROTO_ICMP;

    iphdr->ip_sum = 0;
    iphdr->ip_sum = checksum((uint16_t *)iphdr, 20);
    memcpy(data, iphdr, sizeof(struct ip));

    struct icmp *icmp = (struct icmp *)malloc(sizeof(struct icmp));


    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_id = ICMP_ID;
    icmp->icmp_seq = seq;


    char icmp_dat[DATALENGTH];
    memset(icmp_dat, 0xa5, DATALENGTH);
    Gettimeofday((struct timeval *)icmp_dat, NULL);


    icmp->icmp_cksum = icmp4_checksum (icmp, icmp_dat, DATALENGTH);


    memcpy((data + sizeof(struct ip)), icmp, sizeof(struct icmp));

    memcpy((data + sizeof(struct ip) + ICMP_HDRLEN), icmp_dat, DATALENGTH);

    int send_result;
    int sz = 14 + 20 + 8 + 56;
    send_result = sendto(sockfd, buffer, sz, 0,  (struct sockaddr*)&socket_address, sizeof(socket_address));


}


void ping(int pf_sockfd, int last_node)
{
    struct node_list *node = head;
    while(node != NULL)
    {
        if (node->ret_seq >= 5 && last_node == 1) {
            return;
        } else{
            int vm_no = get_vm_num(node->ip);
            if (node->seq == 0)
                printf("PING vm%d (%s) : %d data bytes\n", vm_no, node->ip, DATALENGTH);
            send_icmp_echo_request(pf_sockfd, node->ip, node->seq);
            node->seq = node->seq + 1;
        }
        node = node->next;
    }
}



void get_my_hw_addr() {
    struct hwa_info *hwa, *hwahead;
    struct sockaddr *sa;
    int i, j, prflag;
    char *ptr;

    for (hwahead = hwa = Get_hw_addrs(); hwa != NULL; hwa = hwa->hwa_next) {
        i=0;
        j=0;
        prflag=0;
        if(strcmp(hwa->if_name,"eth0") == 0) {

            do {
                if (hwa->if_haddr[i] != '\0') {
                    prflag = 1;
                    break;
                }
            } while (++i < IF_HADDR);

            if(prflag == 1) {
                eth0_index = hwa->if_index;
                ptr = hwa->if_haddr;
                i = IF_HADDR;
                do {
                    my_hw_addr[j++] = (*ptr++ & 0xff);
                } while (--i > 0);
                struct sockaddr *ip = hwa->ip_addr;
                my_ip = Sock_ntop_host(ip, sizeof(*ip));
            }

        }
    }

    free_hwa_info(hwahead);
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

int check_in_list(char *ip){
    struct node_list *node = head;
    while(node != NULL){
        if (strcmp(ip, node->ip) == 0)
            return 0;
        else
            node = node->next;
    }
    return 1;
}

struct node_list* get_node_from_list(char *ip){
    struct node_list *node = head;
    while(node != NULL){
        if (strcmp(ip, node->ip) == 0)
            return node;
        else
            node = node->next;
    }
    return NULL;

}

void add_to_list(char *ip){
    if (check_in_list(ip) == 0)
        return;
    struct node_list *node = (struct node_list *)malloc(sizeof(struct node_list));
    strcpy(node->ip, ip);
    node->seq = 0;
    node->ret_seq = 0;
    node->next = NULL;
    if (head == NULL)
        head = node;
    else{
        struct node_list *nd = head;
        while(nd != NULL){
            nd = nd->next;        
        }
        nd = node;
    }
}

void send_multicast_message(int send_fd, SA *sasend, socklen_t salen, char *msg){
    char line[MAXLINE];
    strcpy(line, msg);
    printf("Node %s. Sending: %s\n", my_vm, line);
    int ret = sendto(send_fd, line, strlen(line), 0, sasend, salen);
}

void recv_multicast_message(int sendfd, int recvfd, SA *sasend, socklen_t salen){
    int n;
    char line[MAXLINE + 1];
    socklen_t len;
    struct sockaddr *safrom;

    safrom = Malloc(salen);

    len = salen;
    n = recvfrom(recvfd, line, MAXLINE, 0, safrom, &len);

    line[n] = 0; /*null terminate*/

    printf("Node %s. Received: %s\n", my_vm, line);

    stop_ping_flag = 1;

    char msg[MAXLINE];
    snprintf(msg, sizeof(msg), "<<<<<Node %s. I am a member of the group>>>>>", my_vm);

    if(strstr(line, "Tour has ended") != NULL)
        send_multicast_message(sendfd, sasend, salen, msg);

}


int max_fd(int rt_sockfd, int pg_sockfd, int recv_mcast_sockfd){
    if (rt_sockfd > pg_sockfd && rt_sockfd > recv_mcast_sockfd)
        return rt_sockfd;
    else if (pg_sockfd > rt_sockfd && pg_sockfd > recv_mcast_sockfd)
        return pg_sockfd;
    return recv_mcast_sockfd;
}

void sig_alarm(int signo){
    printf("Terminating the Tour process\n");
    exit(0);
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
    int start_flag = 1;
    int last_node = 0;
    char scnd_last_node[15];

    get_my_vm();

    Signal(SIGALRM, sig_alarm);


    // Check whether the order is valid or not and check the vm name too
    if(check_tour(argc, argv)) {
        exit(0);
    }

    create_ip_list(&ipl, argc, argv);
    //        print_ip_list(&ipl);

    get_my_hw_addr();


    while(1)
    {
        //Create IP Header
        if((ipl.total_ips != 1) && start_flag == 1)
        {
            send_mcast_sockfd = Udp_client(MULTICAST_ADDR, MULTICAST_PORT, &sasend, &salen);
            recv_mcast_sockfd = Socket(sasend->sa_family, SOCK_DGRAM, 0);
            Setsockopt(recv_mcast_sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

            sarecv = Malloc(salen);
            memcpy(sarecv, sasend, salen);
            Bind(recv_mcast_sockfd, sarecv, salen);

            Mcast_join(recv_mcast_sockfd, sasend, salen, NULL, 0);
            //            Mcast_set_loop(send_mcast_sockfd, 0);

            send_tour_packet(rt_sockfd, &ipl);
            start_flag = 0;

        }

        else{

            fd_set rset;
            FD_ZERO(&rset);
            FD_SET(rt_sockfd, &rset);
            FD_SET(pg_sockfd, &rset);
            FD_SET(recv_mcast_sockfd, &rset);


            int max = max_fd(rt_sockfd, pg_sockfd, recv_mcast_sockfd);

            struct timeval *tm;
            tm = (struct timeval*)malloc(sizeof(struct timeval));
            tm->tv_sec = 1;
            tm->tv_usec = 0;


            int ret = select(max+1, &rset, NULL, NULL, tm);

            if (FD_ISSET(rt_sockfd, &rset)){

                struct sockaddr_in cliaddr;
                socklen_t len = sizeof(cliaddr);
                char mesg[4096];
                recvfrom(rt_sockfd, mesg, sizeof(mesg), 0, (SA *)&cliaddr, &len); 
                struct iphdr *iph = (struct iphdr *)mesg;
                if (iph->id == ID)
                {
                    struct ip_list *ipl1 = (struct ip_list *)(mesg + sizeof(struct iphdr));
                    ipl1->curr_ip_pos = ipl1->curr_ip_pos + 1;

                    if (start_flag == 1){
                        send_mcast_sockfd = Udp_client(ipl1->multicast_addr, ipl1->multicast_port, &sasend, &salen);
                        recv_mcast_sockfd = Socket(sasend->sa_family, SOCK_DGRAM, 0);
                        Setsockopt(recv_mcast_sockfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

                        sarecv = Malloc(salen);
                        memcpy(sarecv, sasend, salen);
                        Bind(recv_mcast_sockfd, sarecv, salen);

                        Mcast_join(recv_mcast_sockfd, sasend, salen, NULL, 0);
                        //                        Mcast_set_loop(send_mcast_sockfd, 0);
                        start_flag = 0;
                    }


                    time_t tm = time(NULL);
                    char buff[50];
                    snprintf(buff, sizeof(buff), "%.24s", ctime(&tm));
                    struct in_addr src;
                    src.s_addr = iph->saddr;
                    char *src_ip = inet_ntoa(src);
                    add_to_list(src_ip);
                    int vm_no = get_vm_num(src_ip);
                    printf("%s received source routing packet from vm%d\n", buff, vm_no);
                    if (ipl1->curr_ip_pos == ipl1->total_ips - 1){
                        last_node = 1;
                        strcpy(scnd_last_node, src_ip);
                    }    
                    else{
                        send_tour_packet(rt_sockfd, ipl1);
                    }

                }
                else
                    continue;
            }
            else if (FD_ISSET(pg_sockfd, &rset)){
                void* buffer = (void*)malloc(ETH_FRAME_LEN);
                struct sockaddr_ll socket_address;
                int size;
                int length = recvfrom(pg_sockfd, buffer, ETH_FRAME_LEN, 0, (struct sockaddr*)&socket_address, &size);
                struct ip *iphdr = (struct ip *)buffer;
                //                if (iphdr->ip_id == ID)
                char *src_ip = inet_ntoa(iphdr->ip_src);
                int vm = get_vm_num(src_ip);
                struct icmp *icmp_recv = (struct icmp *)(buffer  +  20);
                struct timeval *tvsend, *tvrecv;
                if (icmp_recv->icmp_type == ICMP_ECHOREPLY && icmp_recv->icmp_id == ICMP_ID){
                    struct node_list *node = get_node_from_list(src_ip);
                    if (node != NULL){
                        node->ret_seq = node->ret_seq + 1;
                    }
                    tvsend = (struct timeval *)(buffer + IP4_HDRLEN + ICMP_HDRLEN);
                    tvrecv = (struct timeval *)malloc(sizeof(struct timeval));
                    gettimeofday(tvrecv, NULL);
                    double rtt = (tvrecv->tv_sec - tvsend->tv_sec) * 1000.0 + (tvrecv->tv_usec - tvsend->tv_usec) / 1000.0;
                    printf("%d bytes from vm%d (%s): seq=%u, ttl=%d rtt=%.3f ms\n", length - IP4_HDRLEN, vm, src_ip, icmp_recv->icmp_seq, iphdr->ip_ttl, rtt);
                    if (last_node == 1 && strcmp(scnd_last_node, src_ip) == 0 && icmp_recv->icmp_seq == 4){
                        char line[MAXLINE];
                        snprintf(line, sizeof(line), "<<<<< This is %s. Tour has ended. Group members please identify yourselves.>>>>>", my_vm);
                        send_multicast_message(send_mcast_sockfd, sasend, salen, line);
                    }
                }

            }
            else if(FD_ISSET(recv_mcast_sockfd, &rset)){
                alarm(5);
                recv_multicast_message(send_mcast_sockfd, recv_mcast_sockfd, sasend, salen);
            }
            if (ret == 0 && stop_ping_flag == 0)
                ping(pf_sockfd, last_node);

        }
    }
}
