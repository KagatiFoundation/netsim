#!/usr/bin/env python3

from enum import Enum

from ethernet import *
from transport_layer import *
from node import Node

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
        self.datagram_length =  len(self)
        self.identifier = 0
        self.type_of_service = 0
        self.ttl = 128
        self.header_checksum = 1111
        self.fragment_offset = 0
        self.flags = 0b000
        self.options = options

    def __len__(self):
        return self.header_length + len(self.data)


class Router(Node):
    def __init__(self, interf_count: int):
        self.interfaces = {interf_no: EthernetPort() for interf_no in range(interf_count)}
        self.routing_table = dict()
        self.arp_table = dict()

    def connect(self, device):
        print("Use method 'connect_on_interface': this method is not supported")
        sys.exit(1)

    def connect_on_interface(self, interface_no: int, device):
        self.interfaces.get(interface_no).connect(device)

    def send(self, frame: EthernetFrame):
        pass

    def receive(self, frame: EthernetFrame):
        pass
