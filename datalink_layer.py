#!/usr/bin/env python3

from ethernet import *
from node import Node
import sys

class Switch(Node):
    def __init__(self, port_count: int = 4):
        self.port_count = port_count
        self.mac_table = dict()
        self.hosts = dict()
        self.ports = {port_number + 1: EthernetPort() for port_number in range(port_count)}

    def connect(self, node = None) -> None:
        print("Use method 'connect_on_port': this method is not supported")
        sys.exit(1)

    def connect_on_port(self, port_number: int, device) -> None:
        if port_number in self.mac_table.keys():
            return
        if port_number < 1 or port_number > self.port_count:
            return
        self.ports.get(port_number).connect(device)
        self.mac_table[device.mac_addr] = port_number

    def send(self, frame: EthernetFrame):
        dest_mac = frame.dest_mac
        port = self.mac_table.get(dest_mac)
        return self.send_through_port(port, frame)

    def send_through_port(self, port_number: int, frame: EthernetFrame):
        return self.ports.get(port_number).connected_device.receive(frame)

    def receive(self, frame: EthernetFrame):
        if frame.dest_mac == "ffff:ffff:ffff:ffff": return self.flood(frame)
        else: return self.send(frame)

    def flood(self, frame: EthernetFrame):
        arp_sender_ip = frame.data.sender_protocol_addr
        for port in self.ports.values():
            receiver = port.connected_device
            if receiver:
                if arp_sender_ip != receiver.ip_addr:
                    if receiver.receive(frame): return True
        return False