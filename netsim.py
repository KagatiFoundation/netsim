#!/usr/bin/env python3

from ethernet import *
from transport_layer import *
from datalink_layer import *
from node import Node
from protocols import ipv4
from protocols.arp import ARP
from protocols.icmp import ICMP
import frame_dumper

import pickle
import random as rand

class Host(Node):
    def __init__(self, ip_addr: str, mac_addr: str):
        self.mac_addr = mac_addr
        self.ip_addr = ip_addr
        self.ether_connection = None
        self.arp_table = {"localhost": self.mac_addr, "127.0.0.1": self.mac_addr}
        self.default_gateway = "192.168.1.254"
        self.subnet_mask = "255.255.255.0"
        self.ethernet_port = EthernetPort()
        self.mtu = 1500 # Maximum Transmission Unit

    def connect(self, device) -> None:
        self.ether_connection = device
        self.ethernet_port.connect(device)

    def make_arp_request(self, ip_addr: str) -> str:
        arp = ARP(self.mac_addr, self.ip_addr, None, ip_addr, ARP.REQUEST)
        frame = EthernetFrame(self.mac_addr, "ffff:ffff:ffff:ffff", arp, typ=EthernetFrame.ARP)
        result = self.ethernet_port.connected_device.receive(frame)
        if not result:
            print(f"\n{'ARP request timeout':.^50}")
            print(f"{'Host unreachable':.^50}")
            return False
        return True

    def on_same_subnetwork(self, dest_ip):
        src = int(f'0b{ipv4.IPv4.ipv4_to_binary(self.ip_addr)}', 2)
        sub = int(f'0b{ipv4.IPv4.ipv4_to_binary(self.subnet_mask)}', 2)
        dest = int(f'0b{ipv4.IPv4.ipv4_to_binary(dest_ip)}', 2)
        my_network = src & sub
        return my_network == (sub & dest)

    def create_transport_packet(self, src_port: int, dest_port: int, protocol, data: bytes):
        if protocol == TransportLayerPacket.UDP:
            return UDPPacket(src_port, dest_port, data)
        else: return None

    '''
    This method returns fragmented IP packets given the data.
    If the data size is greater than MTU, then this fragments data to fit into 
    the MTU size.
    '''
    def create_network_packet(self, src_ip, dest_ip, upper_layer_protocol: ipv4.IPv4Packet.UpperLayerProtocol, tpacket):
        raw_bytes = pickle.dumps(tpacket)
        data_length = len(raw_bytes)
        identifier = rand.randint(0xFFFF, 0xFFFFFFFF)

        if data_length <= self.mtu:
            yield ipv4.IPv4Packet(src_ip, dest_ip, upper_layer_protocol, raw_bytes, identifier=identifier)

        buffer_pointer = 0
        while True:
            yield ipv4.IPv4Packet(src_ip, dest_ip, upper_layer_protocol, raw_bytes[buffer_pointer:buffer_pointer + self.mtu], identifier=identifier, flags=0b001)
            buffer_pointer += self.mtu
            left_data = raw_bytes[buffer_pointer:]
            if len(left_data) > self.mtu:
                continue
            else:
                yield ipv4.IPv4Packet(src_ip, dest_ip, upper_layer_protocol, left_data, identifier=identifier)
                break

    def create_ethernet_frame(self, src_mac, dest_mac, data, typ):
        return EthernetFrame(src_mac, dest_mac, data, typ)

    def send(self, frame: EthernetFrame):
        device = self.ethernet_port.connected_device
        device.receive(frame)
        return True

    def send_data(self, dest_ip: str, dest_port: int, packet_type, data: bytes):
        proto = None
        if packet_type == ipv4.IPv4Packet.UpperLayerProtocol.ICMP:
            proto = ipv4.IPv4Packet.UpperLayerProtocol.ICMP
            data = ICMP(8, 0, None, b'')
        elif packet_type == ipv4.IPv4Packet.UpperLayerProtocol.TCP:
            proto = ipv4.IPv4Packet.UpperLayerProtocol.TCP
            data = self.create_transport_packet(1000, dest_port, TransportLayerPacket.TCP, data)
        elif packet_type == ipv4.IPv4Packet.UpperLayerProtocol.UDP:
            proto = ipv4.IPv4Packet.UpperLayerProtocol.UDP
            data = self.create_transport_packet(1000, dest_port, TransportLayerPacket.UDP, data)

        dest_mac = self.arp_table.get(dest_ip)
        arp_result = True
        if not dest_mac:
            same_subnet = self.on_same_subnetwork(dest_ip)
            if same_subnet:
                arp_result = self.make_arp_request(dest_ip)
            else:
                arp_result = self.make_arp_request(self.default_gateway)

        ether_data = self.create_network_packet(
                    self.ip_addr, 
                    dest_ip, 
                    proto,
                    data
                )
        frame = self.create_ethernet_frame(
            self.mac_addr, 
            None, 
            None, 
            EthernetFrame.IPV4
        )

        if arp_result:
            frame.dest_mac = self.arp_table.get(dest_ip)
            for ippacket in ether_data:
                frame.data = ippacket
                self.send(frame)

    def receive(self, frame: EthernetFrame):
        if not frame: return False 
        '''
        if frame.dest_mac != self.mac_addr:
            return False
        '''

        if frame.type == EthernetFrame.ARP:
            arp: ARP = frame.data
            src_ip = arp.sender_protocol_addr
            self.arp_table[src_ip] = arp.sender_hardware_addr

            if arp.type == ARP.REQUEST:
                if arp.target_protocol_addr != self.ip_addr:
                    return False
                
                frame_dumper.dump_ethernet_frame(frame)
                arpp = ARP(
                        self.mac_addr, 
                        self.ip_addr, 
                        arp.sender_hardware_addr, 
                        arp.sender_protocol_addr, 
                        typ=ARP.REPLY
                    )
                fram = EthernetFrame(self.mac_addr, frame.src_mac, arpp, EthernetFrame.ARP)
                self.send(fram)
            elif arp.type == ARP.REPLY:
                if arp.target_protocol_addr == self.ip_addr:
                    frame_dumper.dump_ethernet_frame(frame)
            else: return False
        elif frame.type == EthernetFrame.IPV4:
            ippacket: ipv4.IPv4Packet = frame.data
            if ippacket.dest_ip != self.ip_addr: return False

            frame_dumper.dump_ethernet_frame(frame)
            if ippacket.upper_layer_protocol == ipv4.IPv4Packet.UpperLayerProtocol.ICMP:
                icmpp:ICMP = ippacket.data
                if icmpp.type == ICMP.REQUEST:
                    icmpp_reply = ICMP(ICMP.REPLY, 0, None, b'')
                    net_pack = self.create_network_packet(self.ip_addr, ippacket.src_ip, ipv4.IPv4Packet.UpperLayerProtocol.ICMP, icmpp_reply)
                    fram = EthernetFrame(self.mac_addr, frame.src_mac, net_pack, EthernetFrame.IPV4)
                    self.send(fram)
        return True

if __name__ == "__main__":
    pass