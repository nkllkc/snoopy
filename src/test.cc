#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <stdio.h>

#include "udp_processor.h"

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle = pcap_open_live("br0", 65536, 1, 1000, errbuf);
    if (handle == NULL)
    {
        printf("Couldn't open device: %s\n", errbuf);
        return 1;
    }

    // Set the pcap filter expression for UDP packets with destination port 53
    // (DNS)
    struct bpf_program fp;
    char filter_exp[] = "udp dst port 53";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        printf("Couldn't parse filter expression: %s\n", pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        printf("Couldn't install filter: %s\n", pcap_geterr(handle));
        return 1;
    }

    // Start capturing packets
    pcap_loop(handle, 0, process_udp, NULL);

    pcap_close(handle);
    return 0;
}
