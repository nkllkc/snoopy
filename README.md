# Snoopy - Let's snoop some ethernet

This is a simple, educational, implementation of a [network packet analyzer](https://en.wikipedia.org/wiki/Packet_analyzer).

## Hardware Used

We use [Orange Pi R1 Plus LTS](http://www.orangepi.org/html/hardWare/computerAndMicrocontrollers/details/orange-pi-R1-Plus-LTS.html), running `Orange Pi Bionic with Linux 5.10.44-rockchip64`.

## Setup Ethernet Bridge

Get names of devices, by running something like `ifconfig`. In my case this was `eth0` and `lan0`.

Now, append the `/etc/network/interfaces` with the following:

```sh
auto eth0
iface eth0 inet manual

auto lan0
iface lan0 inet manual

auto br0
iface br0 inet dhcp
    bridge_ports eth0 lan0

```

After making changes to the `/etc/network/interfaces` file, you can either restart the networking service by running:

```
sudo systemctl restart networking
```

or reboot your system to apply the changes.

You can confirm if new bridge interface is created by running `ifconfig`.

# Read Ethernet Frames on Bridge

For this purpose we will use [pcap library](https://www.tcpdump.org/manpages/pcap.3pcap.html). The full code is available at [snoopy_printer.cc](./src/snoopy_printer.cc).

First we obtain a pcap handle for the given interface:

```cpp
    // Obtain a packet capture handle to the given interface.
    handle = pcap_open_live(
        /*interface*/ if_name,
        /*snaplen*/ BUFSIZ,
        /*promisc*/ 1,
        /*to_ms*/ 1000, error_buffer);
```

We relly on the interface to be in [promiscous mode](https://en.wikipedia.org/wiki/Promiscuous_mode).

We can alternatively achieve the same by combining [pcap_create()](https://www.tcpdump.org/manpages/pcap_create.3pcap.html) and then [pcap_activate()](https://www.tcpdump.org/manpages/pcap_activate.3pcap.html).

Since at this point we want to sniff on Ethernet frames, the following filter needs to be set:

```cpp
    // Compile the string `str` into a filter program.
    if (pcap_compile(handle, &filter, /*str*/ "ether proto 0x0800",
                     /*optimize*/ 1, PCAP_NETMASK_UNKNOWN) == -1)
    {
        printf("Couldn't compile filter: %s\n", pcap_geterr(handle));
        return 1;
    }
```

There are other values 


# Log Types of Data Packets