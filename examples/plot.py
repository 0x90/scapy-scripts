#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

__author__ = '090h'
__license__ = 'GPL'

from sys import argv, exit
from os import path
from scapy.all import *

def plot():
    a, b = sr(IP(dst="www.target.com")/TCP(sport=[RandShort()]*1000))
    a.plot(lambda x: x[1].id)

def traceroute_graph():
    res, unans = traceroute(
        ["www.microsoft.com", "www.cisco.com", "www.yahoo.com", "www.wanadoo.fr", "www.pacsec.com"],
        dport=[80,443],
        maxttl=20,
        retry=-2)

    res.graph()                          # piped to ImageMagick's display program. Image below.
    # res.graph(type="ps",target="| lp")   # piped to postscript printer
    # res.graph(target="> /tmp/graph.svg") # saved to file

    res.trace3D()

# Graphical dumps (PDF, PS)
# If you have PyX installed, you can make a graphical
# PostScript/PDF dump of a packet or a list of packets
# (see the ugly PNG image below. PostScript/PDF are far better quality...):

a[423].pdfdump(layer_shift=1)
a[423].psdump("/tmp/isakmp_pkt.eps",layer_shift=1)


if __name__ == '__main__':
    pass