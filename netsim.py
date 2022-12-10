#!/usr/bin/env python3

from ethernet import *
from transport_layer import *
from network_layer import *
from datalink_layer import *
from node import Node
from protocols import ipv4
from protocols.arp import ARP
from protocols.icmp import ICMP

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

    def dump_ethernet_frame(self, frame: EthernetFrame):
        print()

        if frame.type == EthernetFrame.ARP:
            typp = f'ARP ({hex(EthernetFrame.ARP)})'
        elif frame.type == EthernetFrame.IPV4:
            typp = f'IPv4 ({hex(EthernetFrame.IPV4)})'

        ETHERNET_FRAME_BORDER_LEN = 100
        print('+' + ('-' * (ETHERNET_FRAME_BORDER_LEN - 2)) + '+')
        length = frame.length
        messages = [
            f'|        Frame length: {length} bytes ({length * 8} bits)',
            f'|        Destination: {frame.dest_mac}',
            f'|        Source: {frame.src_mac}',
            f'|        Type: {typp}'
        ]

        frame_start_border_title = '| --- Ethernet frame ---'
        print(frame_start_border_title+ (ETHERNET_FRAME_BORDER_LEN - len(frame_start_border_title) - 1) * ' ' + '|')
        for message in messages:
            print(message + (ETHERNET_FRAME_BORDER_LEN - len(message) - 1) * ' ' + '|')

        if frame.type == EthernetFrame.ARP:
            self.dump_arp_frame(frame.data)
        elif frame.type == EthernetFrame.IPV4:
            self.dump_ipv4_frame(frame.data)

        frame_end_border_title = '| --- End Ethernet frame ---'
        print(frame_end_border_title + (ETHERNET_FRAME_BORDER_LEN - len(frame_end_border_title) - 1) * ' ' + '|')
        print('+' + ('-' * (ETHERNET_FRAME_BORDER_LEN - 2)) + '+')

    def dump_arp_frame(self, arp):
        header = "Request"
        target_mac = arp.target_hardware_addr if arp.target_hardware_addr else '00:00:00:00:00:00'
        if arp.type == ARP.REPLY:
            header = "Reply"

        ARP_FRAME_BORDER_LEN = 80
        arp_frame = '|        +' + ('-' * (ARP_FRAME_BORDER_LEN - 2)) + '+'
        arp_frame += ((100 - len(arp_frame) - 1) * ' ') + '|'
        messages = [
            f'|        | --- ARP ({header}) ---',
            f'|        |        Hardware type: Ethernet (1)',
            f'|        |        Protocol type: IPv4 (0x0800)',
            f'|        |        Hardware size: 6',
            f'|        |        Protocol size: 4',
            f'|        |        Sender MAC address: {arp.sender_hardware_addr}',
            f'|        |        Sender IP address: {arp.sender_protocol_addr}',
            f'|        |        Target MAC address: {target_mac}',
            f'|        |        Target IP address: {arp.target_protocol_addr}',
            f'|        |        Who has {arp.target_protocol_addr}? Tell {arp.sender_protocol_addr}',
            f'|        | --- End ARP ---',
        ]

        print(arp_frame)
        for message in messages:
            act_out_msg = message + (ARP_FRAME_BORDER_LEN - len(message) + 8) * ' ' + '|'
            length = len(act_out_msg)
            print(act_out_msg, (100 - length - 2) * ' ' + '|')
        print(arp_frame)
        

    def dump_ipv4_frame(self, ippacket: ipv4.IPv4Packet):
        IP_BORDER_LEN = 80
        ipv4_frame = '|        +' + ('-' * (IP_BORDER_LEN - 2)) + '+'
        ipv4_frame += ((100 - len(ipv4_frame) - 1) * ' ') + '|'
        messages = [
            f'|        | --- IPv4 ---',
            f'|        |        Source address: {ippacket.src_ip}',
            f'|        |        Destination address: {ippacket.dest_ip}',
            f'|        |        Total Length: {ippacket.datagram_length}',
            f'|        |        Identification: {hex(ippacket.identifier)} ({ippacket.identifier})',
            f'|        |        Flags: {hex(ippacket.flags)}',
            f'|        |        ... Reserved bit: Not set',
            f'|        |        ... Don\'t Fragment: {"Set" if ippacket.flags & 0b10 else "Not set"}',
            f'|        |        ... More Fragments: {"Set" if ippacket.flags & 0b1 else "Not set"}',
            f'|        |        Fragment Offset: {hex(ippacket.fragment_offset)}',
            f'|        |        Time to Live: {ippacket.ttl}',
            f'|        |        Header Checksum: {hex(ippacket.header_checksum)}',
            f'|        |        Protocol: {ipv4.IPv4Packet.UpperLayerProtocol(ippacket.upper_layer_protocol).name} ({ippacket.upper_layer_protocol.value})',
            f'|        | --- End IPv4 ---'
        ]

        print(ipv4_frame)
        for message in messages:
            act_out_msg = message + (IP_BORDER_LEN - len(message) + 8) * ' ' + '|'
            length = len(act_out_msg)
            print(act_out_msg, (100 - length - 2) * ' ' + '|')
        print(ipv4_frame)

    def dump_udp_frame(self, frame):
        pass

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

        if frame.type == EthernetFrame.ARP:
            arp: ARP = frame.data
            src_ip = arp.sender_protocol_addr
            self.arp_table[src_ip] = arp.sender_hardware_addr

            if arp.type == ARP.REQUEST:
                if arp.target_protocol_addr != self.ip_addr:
                    return False
                
                self.dump_ethernet_frame(frame)
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
                    self.dump_ethernet_frame(frame)
            else: return False
        elif frame.type == EthernetFrame.IPV4:
            ippacket: ipv4.IPv4Packet = frame.data
            if ippacket.dest_ip != self.ip_addr: return False

            self.dump_ethernet_frame(frame)
            if ippacket.upper_layer_protocol == ipv4.IPv4Packet.UpperLayerProtocol.ICMP:
                icmpp:ICMP = ippacket.data
                if icmpp.type == ICMP.REQUEST:
                    icmpp_reply = ICMP(ICMP.REPLY, 0, None, b'')
                    net_pack = self.create_network_packet(self.ip_addr, ippacket.src_ip, ipv4.IPv4Packet.UpperLayerProtocol.ICMP, icmpp_reply)
                    fram = EthernetFrame(self.mac_addr, frame.src_mac, net_pack, EthernetFrame.IPV4)
                    self.send(fram)
        return True

if __name__ == "__main__":
    switch = Switch(4)

    host_a = Host(mac_addr = "fa:ce:de:ad:be:ef", ip_addr = "192.168.1.4")
    host_a.connect(switch)
    switch.connect_on_port(1, host_a)

    host_b = Host(mac_addr = "aa:aa:bb:bb:cc:dd", ip_addr = "192.168.1.5")
    host_b.connect(switch)
    switch.connect_on_port(2, host_b)

    host_a.send_data("192.168.1.5", 80, ipv4.IPv4Packet.UpperLayerProtocol.UDP, b'A' * 1600)