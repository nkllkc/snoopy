#include <arpa/inet.h>
#include <netinet/ether.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#include "udp_processor.h"
#include "util.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    const struct snoop_ethernet *ethernet; /* The ethernet header */
    const struct snoop_ip *ip;             /* The IP header */
    const struct snoop_tcp *tcp;           /* The TCP header */
    const struct snoop_udp *udp;           /* The UDP header */
    const u_char *payload;                 /* Packet payload */

    u_int size_ip;
    u_int size_tcp;

    ethernet = (struct snoop_ethernet *)(packet);
    ip = (struct snoop_ip *)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip) * 4;
    if (size_ip < 20)
    {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    /* print source and destination IP addresses */
    printf("       From: %s\n", inet_ntoa(ip->ip_src));
    printf("         To: %s\n", inet_ntoa(ip->ip_dst));

    /* determine protocol */
    switch (ip->ip_p)
    {
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            break;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            process_udp(args, header, packet);
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        case IPPROTO_IP:
            printf("   Protocol: IP\n");
            return;
        default:
            printf("   Protocol: unknown\n");
            return;
    }
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("Usage: %s <interface1>\n", argv[0]);
        exit(1);
    }

    const char *if_name = argv[1];

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    // const u_char *packet;
    // struct pcap_pkthdr packet_header;

    // Obtain a packet capture handle to the given interface.
    handle = pcap_open_live(
        /*interface*/ if_name,
        /*snaplen*/ BUFSIZ,
        /*promisc*/ 1,
        /*to_ms*/ 1000, error_buffer);

    if (handle == NULL)
    {
        printf("Couldn't open device: %s\n", error_buffer);
        return 1;
    }

    struct bpf_program filter;
    // Compile the string `str` into a filter program.
    if (pcap_compile(handle, &filter,
                     // /*str*/ "ether proto 0x0800",
                     "udp dst port 53",
                     /*optimize*/ 1, PCAP_NETMASK_UNKNOWN) == -1)
    {
        printf("Couldn't compile filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    if (pcap_setfilter(handle, &filter) == -1)
    {
        printf("Couldn't set filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    // The `cnt` value of -1 indicates that inifite number of packages should be
    // processed. Call `process_packet` on every packet received.
    // pcap_loop(handle, -1, process_packet, NULL);
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}
