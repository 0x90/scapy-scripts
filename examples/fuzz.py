#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

__author__ = '090h'
__license__ = 'GPL'

from sys import argv, exit
from os import path

send(IP(dst="target")/fuzz(UDP()/NTP(version=4)),loop=1)

if __name__ == '__main__':
    pass