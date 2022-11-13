#!/usr/bin/env python3

from enum import Enum

from ethernet import *
from transport_layer import *
from node import Node
from protocols.arp import ARP

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
    def __init__(self, ip_addr: str, mac_addr: str, interf_count: int):
        self.interfaces = {interf_no + 1: EthernetPort() for interf_no in range(interf_count)}
        self.routing_table = None
        self.arp_table = dict()
        self.ip_addr = ip_addr
        self.mac_addr = mac_addr

    def configure(self, configs = {"routing_table": None}):
        self.routing_table = configs.get("routing_table")

    def connect(self, device):
        print("Use method 'connect_on_interface': this method is not supported")
        sys.exit(1)

    def connect_on_interface(self, interface_no: int, device):
        self.interfaces.get(interface_no).connect(device)

    def send(self, frame: EthernetFrame):
        return self.send_on_interface(self.routing_table.get("11.11.11.0/24"), frame)

    def send_on_interface(self, inter_no: int, frame: EthernetFrame):
        return self.interfaces.get(inter_no).connected_device.receive(frame)

    def receive(self, frame: EthernetFrame):
        if frame.type == EthernetFrame.ARP:
            arp = frame.data
            src_ip = arp.sender_protocol_addr
            self.arp_table[src_ip] = arp.sender_hardware_addr
            if arp.type == ARP.REQUEST:
                if arp.target_protocol_addr == self.ip_addr:
                    arpp = ARP(
                            self.mac_addr, 
                            self.ip_addr, 
                            arp.sender_hardware_addr, 
                            arp.sender_protocol_addr, 
                            typ=ARP.REPLY
                        )
                    fram = EthernetFrame(self.mac_addr, frame.src_mac, arpp, EthernetFrame.ARP)
                    self.send_on_interface(1, fram)
            elif arp.type == ARP.REPLY:
                pass
            else: return False
        else:
            ippacket = frame.data
        return True