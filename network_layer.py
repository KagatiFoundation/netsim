#!/usr/bin/env python3

from ethernet import *
from transport_layer import *
from node import Node
from protocols.arp import ARP

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