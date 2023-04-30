#include <arpa/inet.h>
#include <netinet/ether.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

void print_eth_frame(const u_char *packet, struct pcap_pkthdr packet_header)
{
    struct ether_header *eth_header = (struct ether_header *)packet;
    printf("Source MAC: %s\n",
           ether_ntoa((const struct ether_addr *)eth_header->ether_shost));
    printf("Destination MAC: %s\n",
           ether_ntoa((const struct ether_addr *)eth_header->ether_dhost));
    printf("Type: %x\n", ntohs(eth_header->ether_type));
    // print the rest of the packet here
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
    const u_char *packet;
    struct pcap_pkthdr packet_header;
    struct bpf_program filter;

    handle = pcap_open_live(if_name, BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL)
    {
        printf("Couldn't open device: %s\n", error_buffer);
        return 1;
    }

    if (pcap_compile(handle, &filter, "ether proto 0x0800", 1,
                     PCAP_NETMASK_UNKNOWN) == -1)
    {
        printf("Couldn't compile filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    if (pcap_setfilter(handle, &filter) == -1)
    {
        printf("Couldn't set filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    pcap_loop(handle, -1, process_packet, NULL);

    pcap_close(handle);
    return 0;
}
