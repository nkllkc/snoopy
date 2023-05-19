#include <arpa/inet.h>
#include <netinet/ether.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#include "util.h"

void print_eth_frame(const u_char *packet_body,
                     struct pcap_pkthdr packet_header)
{
    struct ether_header *eth_header = (struct ether_header *)packet_body;
    printf("Source MAC: %s\n",
           ether_ntoa((const struct ether_addr *)eth_header->ether_shost));
    printf("Destination MAC: %s\n",
           ether_ntoa((const struct ether_addr *)eth_header->ether_dhost));
    printf("Type: %x\n", ntohs(eth_header->ether_type));

    printf("caplen: %d\n", packet_header.caplen);
    printf("len: %d\n", packet_header.len);
    printf("sizeof(struct ether_header): %d\n", sizeof(struct ether_header));

    // Calculate the size of the packet body
    int packet_size = packet_header.caplen - sizeof(struct ether_header);
    printf("Packet size without header: %d bytes\n", packet_size);

    // Extract and print the payload
    int payload_offset = sizeof(struct ether_header);
    int payload_size = packet_size - 4;  // subtract the FCS size
    printf("Payload size: %d bytes\n", payload_size);
    printf("Payload:\n");
    for (int i = payload_offset; i < payload_offset + payload_size; i++)
    {
        printf("%02x ", packet_body[i]);
    }
    printf("\n");

    // Extract and print the FCS field
    uint32_t fcs = *(uint32_t *)(packet_body + packet_header.caplen - 4);
    printf("FCS: %08x\n", ntohl(fcs));
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip;             /* The IP header */
    const struct sniff_tcp *tcp;           /* The TCP header */
    const u_char *payload;                 /* Packet payload */

    u_int size_ip;
    u_int size_tcp;

    ethernet = (struct sniff_ethernet *)(packet);
    ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
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

    // tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
    // size_tcp = TH_OFF(tcp) * 4;
    // if (size_tcp < 20)
    // {
    //     printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
    //     return;
    // }
    // payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
}

void process_packet(u_char *args, const struct pcap_pkthdr *packet_header,
                    const u_char *packet_body)
{
    print_eth_frame(packet_body, *packet_header);
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
                     "udp port 53",
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
