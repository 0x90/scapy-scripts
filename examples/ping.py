#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

__author__ = '090h'
__license__ = 'GPL'

from sys import argv, exit
from os import path
from scapy.all import *

def arp_ping(host):
    '''ARP Ping'''

    # The fastest way to discover hosts on a local ethernet network is to use the ARP Ping method:
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=host), timeout=2)

    # Answers can be reviewed with the following command:
    ans.summary(lambda (s, r): r.sprintf("%Ether.src% %ARP.psrc%"))


def icmp_ping(host):
    ''' ICMP Ping '''

    # Classical ICMP Ping can be emulated using the following command:
    ans, unans = sr(IP(dst=host)/ICMP())

    # Information on live hosts can be collected with the following request:
    ans.summary(lambda (s, r): r.sprintf("%IP.src% is alive"))


def tcp_ping(host, port):
    ''' TCP Ping '''

    # In cases where ICMP echo requests are blocked, we can still use various TCP Pings
    # such as TCP SYN Ping below:
    ans, unans = sr(IP(dst=host)/TCP(dport=port, flags="S"))

    # Any response to our probes will indicate a live host. We can collect results with the following command:
    ans.summary(lambda(s, r): r.sprintf("%IP.src% is alive"))

def udp_ping(host, port=0):
    ''' UDP Ping '''
    # If all else fails there is always UDP Ping which will produce ICMP Port unreachable errors
    # from live hosts. Here you can pick any port which is most likely to be closed,
    # such as port 0:
    ans, unans = sr(IP(dst=host)/UDP(dport=port))

    # Once again, results can be collected with this command:
    ans.summary(lambda(s, r): r.sprintf("%IP.src% is alive"))

if __name__ == '__main__':
    # own variant
    arp_ping('10.0.0.1/24')

    # Scapy also includes a built-in arping() function which performs similar to the above two commands:
    arping("10.0.0.*")

    icmp_ping('10')

    tcp_ping()