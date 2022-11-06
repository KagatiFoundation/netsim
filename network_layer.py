#!/usr/bin/env python3

from enum import Enum

from ethernet import *
from transport_layer import *

class IPv4Packet:
    NO_FRAG = 0b10
    MORE_FRAG = 0b1

    class UpperLayerProtocol(Enum):
        TCP = 6
        UDP = 17

    def __init__(self, src_ip, dest_ip, upper_layer_protocol, data: TransportLayerPacket, options = None):
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.data = data
        self.upper_layer_protocol = upper_layer_protocol
        self.header_length = 20 # 20 bytes if there aren't any extra options
        self.datagram_length =  self.header_length + len(data)
        self.identifier = 0
        self.type_of_service = 0
        self.ttl = 128
        self.header_checksum = 1111
        self.fragment_offset = 0
        self.flags = 0b000
        self.options = options


class Router():
    def __init__(self):
        self.interfaces = dict()
        self.routing_table = dict()
        self.arp_table = dict()

    def connect(self, port, device):
        pass

    def send(self, dest_ip: str, frame: EthernetFrame):
        pass

    def receive(self, src_ip: str, frame: EthernetFrame):
        pass
