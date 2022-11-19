#!/usr/bin/env python3

import sys

class EthernetFrame:
    IPV4 = 0x0800
    ARP  = 0x0806

    def __init__(self, src_mac: str, dest_mac: str, data, typ=None):
        self.src_mac = src_mac
        self.dest_mac = dest_mac
        self._data = data
        self.type = typ
        self.preamble = 0
        self.crc = 0
        self.length = 26 + len(data) if data else 0

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, new_data):
        self._data = new_data
        self.length = 26 + len(new_data)


class EthernetCable:
    def __init__(self):
        self.end1 = None
        self.end2 = None

    def connect(self, port):
        if self.end1 and self.end2:
            print("Cable already connected on both of its side")
            sys.exit(1)
            return

        if not self.end1:
            self.end1 = port
        else:
            self.end2 = port


class EthernetPort:
    def __init__(self):
        self.connected_device = None

    def connect(self, device):
        self.connected_device = device

    def disconnect(self):
        self.connected_device = None
