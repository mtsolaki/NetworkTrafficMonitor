#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <string.h>

#include <pcap.h>
#include <sys/socket.h>
#include <inttypes.h>

#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

/* Counters XD */
u_int64_t net_flow_c;
u_int64_t net_flow_c4;
u_int64_t net_flow_c6;
u_int64_t net_flow_tcp_c;
u_int64_t net_flow_udp_c;
u_int64_t pack_c;
u_int64_t pack_tcp_c;
u_int64_t pack_udp_c;
u_int64_t bytes_tcp_c;
u_int64_t bytes_udp_c;

/* struct for network_flow ipv4*/
typedef struct net_flow_ip4{
    union{
        uint32_t s_ip;
        uint8_t s_ip_part[4];
    }s_addr;
    union 
    {
        uint32_t d_ip;
        uint8_t d_ip_part[4];
    }d_addr;
    uint16_t s_port;
    uint16_t d_port;
    uint8_t protocol;

}net_flow_ip4;

/* struct for network_flow ipv6*/
typedef struct net_flow_ip6{

    struct in6_addr s_ip;
    struct in6_addr d_ip;
    uint16_t s_port;
    uint16_t d_port;
    uint8_t protocol;

}net_flow_ip6;

net_flow_ip4 *n_fl;
net_flow_ip6 *n_fl_6;

void usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-r <filename>, Packet capture filename\n"
		   "-i <interfaceName>, Network interface name \n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}

void signal_handler(int signum)
{
    if (signum != SIGINT && signum != SIGQUIT && signum != SIGSTOP )
        return;
    
    printf("\nNetwork flows captured     :%" PRIu64 "\n", net_flow_c);
    printf("TCP Network flows captured :%" PRIu64 "\n", net_flow_tcp_c);
    printf("UDP Network flows captured :%" PRIu64 "\n", net_flow_udp_c);
    printf("Number of packets received :%" PRIu64 "\n", pack_c);
    printf("TCP packets received       :%" PRIu64 "\n", pack_tcp_c);
    printf("UDP packets received       :%" PRIu64 "\n", pack_udp_c);
    printf("TCP bytes received         :%" PRIu64 "\n", bytes_tcp_c);
    printf("UDP bytes received         :%" PRIu64 "\n", bytes_udp_c);
    exit(1);
}

void manage_network_flow_ip4(uint32_t s_ip,uint32_t d_ip, uint16_t s_port, uint16_t d_port, uint8_t protocol)
{   
    
    u_int64_t i;
    if (net_flow_c == 0)
    {
        n_fl[0].s_addr.s_ip = s_ip;
        n_fl[0].d_addr.d_ip = d_ip;
        n_fl[0].s_port = s_port;
        n_fl[0].d_port = d_port;
        n_fl[0].protocol = protocol;
        net_flow_c++;
        net_flow_c4++;
        if (protocol == IPPROTO_TCP)
        {
            net_flow_tcp_c++;
        }
        else if (protocol == IPPROTO_UDP)
        {
            net_flow_udp_c++;
        }
    }
    else
    {
        for(i = 0; i < net_flow_c4; i++)
        {
            if (n_fl[i].s_addr.s_ip == s_ip && n_fl[i].d_addr.d_ip == d_ip && n_fl[i].s_port == s_port &&n_fl[i].d_port == d_port && n_fl[i].protocol == protocol)
            {
                return;
            }
        }
        net_flow_c++;
        net_flow_c4++;
        //printf("c4 %" PRIu64, net_flow_c4);
        n_fl = (net_flow_ip4 *)realloc(n_fl, sizeof(net_flow_ip4)*net_flow_c4);
        //perror("realloc");
        n_fl[net_flow_c4-1].s_addr.s_ip = s_ip;
        n_fl[net_flow_c4-1].d_addr.d_ip = d_ip;
        n_fl[net_flow_c4-1].s_port = s_port;
        n_fl[net_flow_c4-1].d_port = d_port;
        n_fl[net_flow_c4-1].protocol = protocol;

        if (protocol == IPPROTO_TCP)
        {
            net_flow_tcp_c++;
        }
        else if (protocol == IPPROTO_UDP)
        {
            net_flow_udp_c++;
        }
    }
    
    
    
    
}

void manage_network_flow_ip6(struct in6_addr s_ip,struct in6_addr d_ip, uint16_t s_port, uint16_t d_port, uint8_t protocol)
{
    u_int64_t i;
    if (net_flow_c == 0)
    {
        n_fl_6[0].s_ip = s_ip;

        n_fl_6[0].d_ip = d_ip;
        n_fl_6[0].s_port = s_port;
        n_fl_6[0].d_port = d_port;
        n_fl_6[0].protocol = protocol;
        net_flow_c++;
        net_flow_c6++;
        if (protocol == IPPROTO_TCP)
        {
            net_flow_tcp_c++;
        }
        else if (protocol == IPPROTO_UDP)
        {
            net_flow_udp_c++;
        }
    }
    else
    {   
        for(i = 0; i < net_flow_c6; i++)
        {
           if ( n_fl_6[i].s_port == s_port &&n_fl_6[i].d_port == d_port && n_fl_6[i].protocol == protocol)
                if (n_fl_6[i].s_ip.s6_addr32[0] == s_ip.s6_addr32[0] && n_fl_6[i].s_ip.s6_addr32[1] == s_ip.s6_addr32[1] && n_fl_6[i].s_ip.s6_addr32[2] == s_ip.s6_addr32[2] && n_fl_6[i].s_ip.s6_addr32[3] == s_ip.s6_addr32[3] )
                    if (n_fl_6[i].d_ip.s6_addr32[0] == d_ip.s6_addr32[0] && n_fl_6[i].d_ip.s6_addr32[1] == d_ip.s6_addr32[1] && n_fl_6[i].d_ip.s6_addr32[2] == d_ip.s6_addr32[2] && n_fl_6[i].d_ip.s6_addr32[3] == d_ip.s6_addr32[3]  )
                    return;
        }
        net_flow_c++;
        net_flow_c6++;
        n_fl_6 = (net_flow_ip6 *)realloc(n_fl_6, sizeof(net_flow_ip6)*net_flow_c6);
        //perror("realloc");
        n_fl_6[net_flow_c6-1].s_ip = s_ip;

        n_fl_6[net_flow_c6-1].d_ip = d_ip;
        n_fl_6[net_flow_c6-1].s_port = s_port;
        n_fl_6[net_flow_c6-1].d_port = d_port;
        n_fl_6[net_flow_c6-1].protocol = protocol;

        if (protocol == IPPROTO_TCP)
        {
            net_flow_tcp_c++;
        }
        else if (protocol == IPPROTO_UDP)
        {
            net_flow_udp_c++;
        }
    }
        
}

void print_pack4(uint8_t s_ip[4], uint8_t d_ip[4], uint16_t s_port, uint16_t d_port,uint8_t protocol, uint8_t hdr_len, uint16_t pay_len )
{
    printf("S_IP %d:%d:%d:%d", s_ip[0], s_ip[1], s_ip[2],s_ip[3]);
    printf("\tD_IP %d:%d:%d:%d", d_ip[0], d_ip[1], d_ip[2],d_ip[3]);
    printf("\tS_PORT %8d", s_port);
    printf("\tD_PORT %8d", d_port);
    if (protocol == IPPROTO_TCP)
        {
           printf("\tProtocol TCP");
        }
        else if (protocol == IPPROTO_UDP)
        {
            printf("\tProtocol UDP");
        }
    printf("\tHEAD_LEN %8d" , hdr_len);
    printf("\tPAY_LEN %8d \n", pay_len);

}

void print_pack6(uint8_t s_ip[16], uint8_t d_ip[16], uint16_t s_port, uint16_t d_port,uint8_t protocol, uint8_t hdr_len, uint16_t pay_len )
{
    printf("S_IP %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", s_ip[0], s_ip[1], s_ip[2],s_ip[3], s_ip[4], s_ip[5], s_ip[6],s_ip[7], s_ip[8], s_ip[9], s_ip[10],s_ip[11], s_ip[12], s_ip[13], s_ip[14],s_ip[15]);
    printf("\tD_IP %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", d_ip[0], d_ip[1], d_ip[2],d_ip[3], d_ip[4], d_ip[5], d_ip[6],d_ip[7], d_ip[8], d_ip[9], d_ip[10],d_ip[11], d_ip[12], d_ip[13], d_ip[14],d_ip[15]);
    printf("\tS_PORT %8d", s_port);
    printf("\tD_PORT %8d", d_port);
    if (protocol == IPPROTO_TCP)
        {
           printf("\tProtocol TCP");
        }
        else if (protocol == IPPROTO_UDP)
        {
            printf("\tProtocol UDP");
        }
    printf("\tHEAD_LEN %8d" , hdr_len);
    printf("\tPAY_LEN %8d \n", pay_len);
}

void my_packet_handler(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    net_flow_ip4 *gen_n_fl = (net_flow_ip4 *)malloc(sizeof(net_flow_ip4));
    net_flow_ip6 *gen_n_fl6 = (net_flow_ip6 *)malloc(sizeof(net_flow_ip6));
    struct ether_header *ethernet_ptr;  /* net/ethernet.h */
    struct ip *ip4;
    struct ip6_hdr *ip6;
    struct tcphdr *tcp;
    struct udphdr *udp;

    const u_char *ip4_h;
    const u_char *ip6_h;
    const u_char *tcp_h;
    const u_char *udp_h;
    const u_char *payload;
    
        /* Header lengths in bytes */
    int ethernet_header_len = 14; /* Doesn't change */
    int ip4_h_len = sizeof(struct ip);
    int ip6_h_len = sizeof(struct ip6_hdr);
    int tcp_h_len = sizeof(struct tcphdr);
    int udp_h_len = sizeof(struct udphdr);
    u_int32_t pay_len;
    pack_c++;

    ethernet_ptr = (struct ether_header *) packet;
    if (ntohs(ethernet_ptr->ether_type) != ETHERTYPE_IP && ntohs(ethernet_ptr->ether_type) != ETHERTYPE_IPV6) 
    {
        return;
    }
    
    if (ntohs(ethernet_ptr->ether_type) == ETHERTYPE_IP)
    {
        ip4 = (struct ip *)(packet + ethernet_header_len);
        if (ip4->ip_p != IPPROTO_TCP && ip4->ip_p != IPPROTO_UDP)
        {
            return;
        }
        if (ip4->ip_p == IPPROTO_TCP)
        {
            pack_tcp_c++;
            tcp = (struct tcphdr *)(packet + ethernet_header_len + ip4_h_len);
            manage_network_flow_ip4(ip4->ip_src.s_addr, ip4->ip_dst.s_addr, ntohs(tcp->source), ntohs(tcp->dest), ip4->ip_p);
            bytes_tcp_c += pkthdr->len;
            pay_len = pkthdr->len - ethernet_header_len - ip4_h_len -tcp_h_len;
            gen_n_fl->s_addr.s_ip = ip4->ip_src.s_addr;
            gen_n_fl->d_addr.d_ip = ip4->ip_dst.s_addr;
            print_pack4(gen_n_fl->s_addr.s_ip_part, gen_n_fl->d_addr.d_ip_part,ntohs(tcp->source), ntohs(tcp->dest), ip4->ip_p, tcp->th_off *4, pay_len);
        }
        else if (ip4->ip_p == IPPROTO_UDP)
        {
            pack_udp_c++;
            udp = (struct udphdr *)(packet + ethernet_header_len + ip4_h_len);
            manage_network_flow_ip4(ip4->ip_src.s_addr, ip4->ip_dst.s_addr, ntohs(udp->uh_sport), ntohs(udp->uh_dport), ip4->ip_p);
            bytes_udp_c += pkthdr->len;
            pay_len = pkthdr->len - ethernet_header_len - ip4_h_len -udp_h_len;
            gen_n_fl->s_addr.s_ip = ip4->ip_src.s_addr;
            gen_n_fl->d_addr.d_ip = ip4->ip_dst.s_addr;
            print_pack4(gen_n_fl->s_addr.s_ip_part, gen_n_fl->d_addr.d_ip_part, ntohs(udp->uh_sport), ntohs(udp->uh_dport), ip4->ip_p, udp->len, pay_len);
        }
        
    }
    else if (ntohs(ethernet_ptr->ether_type) == ETHERTYPE_IPV6)
    {
        ip6 = (struct ip6_hdr *)(packet + ethernet_header_len);
        if (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_TCP && ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_UDP)
        {
            printf("Not a TCP or UDP packet. Skipping...\n\n");
            return;
        }
        if (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP)
        {
            pack_tcp_c++;
            tcp = (struct tcphdr *)(packet + ethernet_header_len + ip6_h_len);
            manage_network_flow_ip6(ip6->ip6_src, ip6->ip6_dst,ntohs(tcp->source), ntohs(tcp->dest), ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
            bytes_tcp_c += pkthdr->len;
            pay_len = pkthdr->len - ethernet_header_len - ip4_h_len -tcp_h_len;
            gen_n_fl6->s_ip = ip6->ip6_src;
            gen_n_fl6->d_ip = ip6->ip6_dst;
            print_pack6(gen_n_fl6->s_ip.s6_addr, gen_n_fl6->d_ip.s6_addr,ntohs(tcp->source), ntohs(tcp->dest), ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt,tcp->th_off *4, pay_len);
        }
        else if (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_UDP)
        {   
            pack_udp_c++;
            udp = (struct udphdr *)(packet + ethernet_header_len + ip6_h_len);
            manage_network_flow_ip6(ip6->ip6_src, ip6->ip6_dst, ntohs(udp->uh_sport), ntohs(udp->uh_dport), ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);
            bytes_udp_c += pkthdr->len;
            pay_len = pkthdr->len - ethernet_header_len - ip4_h_len -udp_h_len;
            gen_n_fl6->s_ip = ip6->ip6_src;
            gen_n_fl6->d_ip = ip6->ip6_dst;
            print_pack6(gen_n_fl6->s_ip.s6_addr, gen_n_fl6->d_ip.s6_addr, ntohs(udp->uh_sport), ntohs(udp->uh_dport), ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt,udp->len, pay_len);
        }
    }

}

void network_monitor(char * device)
{
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;

    struct pcap_pkthdr hdr;     /* pcap.h */
    struct ether_header *ethernet_ptr;  /* net/ethernet.h */

    u_char *ptr; /* printing out hardware header info */

    descr = pcap_open_live(device,BUFSIZ,0,-1,errbuf); /* open the device for sniffing. */
    if(descr == NULL) /* if open fails prints error message */
    {
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }

    // packet = pcap_next(descr,&hdr); /* read packet */
    // if(packet == NULL)
    // {
    //     printf("Didn't grab packet\n");
    //     exit(1);
    // }
    /* Sett Counters  and net_flow list*/
    net_flow_c = 0;
    net_flow_c4 = 0;
    net_flow_c6 = 0;
    net_flow_tcp_c = 0;
    net_flow_udp_c = 0;
    pack_c = 0;
    pack_tcp_c = 0;
    pack_udp_c = 0;
    bytes_tcp_c = 0;
    bytes_udp_c = 0;

    n_fl = (net_flow_ip4 *)malloc(sizeof(net_flow_ip4));
    n_fl_6 = (net_flow_ip6 *)malloc(sizeof(net_flow_ip6));
    // ethernet_ptr = (struct ether_header *)packet;
    pcap_loop(descr,0,my_packet_handler,NULL);


}

void file_monitor(char * filename)
{
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;

    struct pcap_pkthdr hdr;     /* pcap.h */
    struct ether_header *ethernet_ptr;  /* net/ethernet.h */

    u_char *ptr; /* printing out hardware header info */

    descr = pcap_open_offline(filename,errbuf); /* open the file for sniffing. */
    if(descr == NULL) /* if open fails prints error message */
    {
        printf("pcap_open_offline(): %s\n",errbuf);
        exit(1);
    }

    // packet = pcap_next(descr,&hdr); /* read packet */
    // if(packet == NULL)
    // {
    //     printf("Didn't grab packet\n");
    //     exit(1);
    // }
    /* Sett Counters  and net_flow list*/
    net_flow_c = 0;
    net_flow_c4 = 0;
    net_flow_c6 = 0;
    net_flow_tcp_c = 0;
    net_flow_udp_c = 0;
    pack_c = 0;
    pack_tcp_c = 0;
    pack_udp_c = 0;
    bytes_tcp_c = 0;
    bytes_udp_c = 0;

    n_fl = (net_flow_ip4 *)malloc(sizeof(net_flow_ip4));
    n_fl_6 = (net_flow_ip6 *)malloc(sizeof(net_flow_ip6));
    // ethernet_ptr = (struct ether_header *)packet;
    pcap_loop(descr,0,my_packet_handler,NULL);
    
    printf("\nNetwork flows captured     :%" PRIu64 "\n", net_flow_c);
    printf("TCP Network flows captured :%" PRIu64 "\n", net_flow_tcp_c);
    printf("UDP Network flows captured :%" PRIu64 "\n", net_flow_udp_c);
    printf("Number of packets received :%" PRIu64 "\n", pack_c);
    printf("TCP packets received       :%" PRIu64 "\n", pack_tcp_c);
    printf("UDP packets received       :%" PRIu64 "\n", pack_udp_c);
    printf("TCP bytes received         :%" PRIu64 "\n", bytes_tcp_c);
    printf("UDP bytes received         :%" PRIu64 "\n", bytes_udp_c);
}

int  main(int argc, char *argv[])
{   
    signal(SIGINT, signal_handler);
    char ch;
    	while ((ch = getopt(argc, argv, "hi:r:")) != -1) {
		switch (ch) {		
		case 'i':
			network_monitor(optarg);
			break;
		case 'r':
			file_monitor(optarg);
			break;
		default:
			usage();
		}
        }
}
