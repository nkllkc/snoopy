#include <arpa/inet.h>
#include <netinet/ether.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

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
    if (pcap_compile(handle, &filter, /*str*/ "ether proto 0x0800",
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
    pcap_loop(handle, 10, process_packet, NULL);

    pcap_close(handle);
    return 0;
}
