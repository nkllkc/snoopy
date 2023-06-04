#include "udp_processor.h"

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>

void process_udp(u_char *user_data, const struct pcap_pkthdr *pkthdr,
                 const u_char *packet)
{
    struct ip *iph = (struct ip *)(packet + 14);  // Skip Ethernet header
    if (iph->ip_p != IPPROTO_UDP)
    {
        printf("Not a UDP packet.\n");
        return;
    }

    struct udphdr *udph =
        (struct udphdr *)(packet + 14 + iph->ip_hl * 4);  // Skip IP header

    unsigned char *udp_payload =
        (unsigned char *)(packet + 14 + iph->ip_hl * 4 + 8);  // Skip UDP header

    // Check the destination port.
    switch (ntohs(udph->dest))
    {
        case 53:
            // DNS:
            process_dns(udp_payload);
            break;
    }
}

void process_dns(const u_char *dns)
{
    printf("   Protocol: DNS\n");

    // Extract the hostname from the DNS question section
    const u_char *question = dns + 12;  // Skip DNS header
    u_char hostname[256];
    u_int hostnameIdx = 0;

    // Read the domain name labels
    while (*question != 0)
    {
        if (*question >= 192)  // Compressed label
        {
            question += 2;  // Skip the 2-byte compression pointer
            break;
        }

        int labelLen = *question;
        for (int i = 0; i < labelLen; i++)
        {
            hostname[hostnameIdx++] = *(question + i + 1);
        }
        hostname[hostnameIdx++] = '.';
        question += labelLen + 1;  // Move to the next label
    }

    hostname[hostnameIdx - 1] =
        '\0';  // Replace the last '.' with null terminator

    printf("   Hostname: %s\n", hostname);
}