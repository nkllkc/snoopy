#include <iostream>
#include <pcap.h>
#include <cstring>

#define BUFFER_SIZE 65536

int main() {
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    const char* interface_in = "eth0";  // Interface to read packets from
    const char* interface_out = "eth1"; // Interface to forward packets to

    // Open the input interface for capturing
    handle = pcap_open_live(interface_in, BUFFER_SIZE, 1, 1000, error_buffer);
    if (handle == nullptr) {
        std::cerr << "Failed to open input interface: " << error_buffer << std::endl;
        return -1;
    }

    // Open the output interface for sending packets
    pcap_t* handle_out;
    handle_out = pcap_open_live(interface_out, BUFFER_SIZE, 1, 1000, error_buffer);
    if (handle_out == nullptr) {
        std::cerr << "Failed to open output interface: " << error_buffer << std::endl;
        pcap_close(handle);
        return -1;
    }

    // Start capturing and forwarding packets in a loop
    while (true) {
        struct pcap_pkthdr header;
        const u_char* packet;

        // Read a packet from the input interface
        packet = pcap_next(handle, &header);
        if (packet == nullptr) {
            continue;
        }

        // Forward the packet to the output interface
        if (pcap_sendpacket(handle_out, packet, header.len) != 0) {
            std::cerr << "Failed to send packet: " << pcap_geterr(handle_out) << std::endl;
        }
    }

    // Close the handles
    pcap_close(handle);
    pcap_close(handle_out);

    return 0;
}
