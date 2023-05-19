#include <pcap/pcap.h>
#include <stdio.h>

int main()
{
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_if_t *alldevsp;
    if (pcap_findalldevs(&alldevsp, errbuf) != 0)
    {
        printf("Couldn't not list devices: %s\n", errbuf);
        return 1;
    };

    pcap_if_t *current_dev = alldevsp;
    while (current_dev != nullptr)
    {
        printf("Device with name: %s\n", current_dev->name);
        printf("\t Description: %s\n", current_dev->description);
        current_dev = current_dev->next;
    }

    pcap_freealldevs(alldevsp);
    return 0;
}