# Utility class used by the other files to do things like look up MAC addresses
# Author: Maxwell Bland

from scapy.all import *

def get_mac(targetIP, interface):
    """
    Gets the MAC for a given IP on a given interface
    :param targetIP:  the IP
    :param interface:  the interface
    :return:  the MAC
    """
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=targetIP), iface=interface, timeout=2)
    return ans[0][1][ARP].hwsrc
