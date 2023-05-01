# Snoopy - Let's snoop some ethernet

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
