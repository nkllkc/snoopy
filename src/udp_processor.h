#ifndef _SNOOPY_UDP_PROCESSOR_
#define _SNOOPY_UDP_PROCESSOR_

#include <arpa/inet.h>

void process_udp(u_char *user_data, const struct pcap_pkthdr *pkthdr,
                 const u_char *packet);

void process_dns(const u_char *dns);

#endif  // _SNOOPY_UDP_PROCESSOR_