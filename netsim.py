#!/usr/bin/env python3

import sys
import pprint
from enum import Enum

class EthernetFrame:
    IPV4 = 0x0800
    ARP  = 0x0806

    def __init__(self, src_mac: str, dest_mac: str, data, typ=None):
        self.src_mac = src_mac
        self.dest_mac = dest_mac
        self.data = data
        self.type = typ
        self.preamble = 0
        self.crc = 0


class TransportLayerPacket:
    UDP = 1
    TCP = 2

    def __init__(self, src_port, dest_port, data: bytes):
        self.src_port = src_port
        self.dest_port = dest_port
        self.data = data


class TCPPacket(TransportLayerPacket):
    def __init__(self, src_port, dest_port, data: bytes):
        super().__init__(src_port, dest_port, data)


class UDPPacket(TransportLayerPacket):
    def __init__(self, src_port, dest_port, data: bytes):
        super().__init__(src_port, dest_port, data)
        self.length = len(self)
        self.checksum = 0b11111111

    def __len__(self):
        return 16 + len(self.data) # sizeof(source_port) + sizeof(dest_port) + sizeof(sizeofgth) + sizeof(checksum) + sizeof(data)


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


class ARP:
    REQUEST = 1
    REPLY = 2

    def __init__(self, sha, spa, tha, tpa, typ):
        self.sender_hardware_addr = sha
        self.sender_protocol_addr = spa
        self.target_hardware_addr = tha
        self.target_protocol_addr = tpa
        self.type = typ


class Node:
    def connect(self, port, device):
        pass

    def send(self, dest_ip: str, frame: EthernetFrame):
        pass

    def receive(self, src_ip: str, frame: EthernetFrame):
        pass


class Switch(Node):
    def __init__(self, port_count: int):
        self.port_count = port_count
        self.mac_table = dict()
        self.hosts = dict()

    def connect(self, port_number: int, host) -> None:
        if port_number in self.mac_table.keys():
            return

        if port_number < 1 or port_number > self.port_count:
            return

        self.mac_table[host.mac_addr] = port_number
        self.hosts[port_number] = host

    def send(self, dest_ip: str, frame: EthernetFrame):
        dest_mac = frame.dest_mac
        if dest_mac in self.mac_table.keys():
            port = self.mac_table.get(dest_mac)
            self.send_through_port(port, frame)
        else:
            self.flood(frame)

    def send_through_port(self, port_number: int, frame: EthernetFrame):
        if frame.type == EthernetFrame.ARP:
            src_ip = frame.data.sender_protocol_addr
        elif frame.type == EthernetFrame.IPV4:
            src_ip = frame.data.src_ip
        self.hosts.get(port_number).receive(src_ip, frame)

    def receive(self, src_ip: str, frame: EthernetFrame):
        pass

    def flood(self, frame: EthernetFrame):
        for receiver in self.hosts.values():
            arp = frame.data
            if arp.sender_protocol_addr != receiver.ip_addr:
                receiver.receive(arp.sender_protocol_addr, frame)


class Router(Node):
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


class Host(Node):
    def __init__(self, ip_addr: str, mac_addr: str):
        self.mac_addr = mac_addr
        self.ip_addr = ip_addr
        self.ether_connection = None
        self.arp_table = dict()
        self.default_gateway = "192.168.1.255"
        self.subnet_mask = "255.255.255.0"

    def connect(self, port_number: int, device) -> None:
        self.ether_connection = device
        device.connect(port_number, self)

    def dump_arp_request_frame(self, frame):
        arp = frame.data
        print("\n*** ARP Request ***")
        print(f'{arp.sender_protocol_addr} ==> {arp.target_protocol_addr}')
        print(f'Data: Who is {arp.target_protocol_addr}?')

    def dump_arp_response_frame(self, frame):
        arp = frame.data
        print("\n*** ARP Response ***")
        print(f'{arp.sender_protocol_addr} ==> {arp.target_protocol_addr}')
        print(f'Data: {arp.sender_hardware_addr} is {arp.sender_protocol_addr}')

    def dump_ipv4_frame(self, frame):
        ipv4 = frame.data
        upper_layer_protocol = ipv4.upper_layer_protocol

        if upper_layer_protocol == IPv4Packet.UpperLayerProtocol.UDP:
            print("\n*** UDP ***")
            print(f'{ipv4.src_ip} ==> {ipv4.dest_ip}')
            print(f'Data: {ipv4.data.data}')

    def make_arp_request(self, ip_addr: str) -> str:
        arp = ARP(self.mac_addr, self.ip_addr, None, ip_addr, ARP.REQUEST)
        frame = EthernetFrame(self.mac_addr, "ffff:ffff:ffff:ffff", arp, typ=EthernetFrame.ARP)
        self.dump_arp_request_frame(frame)
        self.ether_connection.send(ip_addr, frame)

    def do_subnet_mask(self, ip_addr):
        ip = list(map(int, ip_addr.split('.')))
        subnet = list(map(int, self.subnet_mask.split(".")))
        results = list(map(int, [x[0] & x[1] for x in zip(ip, subnet)]))
        return set(ip[:3]) == set(results[:3])

    def create_transport_packet(self, src_port: int, dest_port: int, protocol, data: bytes):
        if protocol == TransportLayerPacket.UDP:
            return UDPPacket(src_port, dest_port, data)
        else: return None

    def create_network_packet(self, src_ip, dest_ip, tpacket):
        return IPv4Packet(src_ip, dest_ip, IPv4Packet.UpperLayerProtocol.UDP, tpacket)

    def create_ethernet_frame(self, src_mac, dest_mac, data, typ):
        return EthernetFrame(src_mac, dest_mac, data, typ)

    def send(self, dest_ip: str, frame: EthernetFrame):
        dest_mac = self.arp_table.get(dest_ip)
        if not dest_mac:
            is_lan = self.do_subnet_mask(dest_ip)
            if is_lan:
                frame.dest_mac = self.make_arp_request(dest_ip)
            else:
                frame.dest_mac = self.make_arp_request(self.default_gateway)

        self.ether_connection.send(dest_ip, frame)

    def send_data(self, dest_ip: str, dest_port: int, data: bytes):
        ether_data = self.create_network_packet(
                    self.ip_addr, 
                    dest_ip, 
                    self.create_transport_packet(1000, dest_port, TransportLayerPacket.UDP, data)
                )
        frame = self.create_ethernet_frame(self.mac_addr, None, ether_data, EthernetFrame.IPV4)
        self.send(dest_ip, frame)

    def receive(self, src_ip: str, frame: EthernetFrame):
        if frame.type == EthernetFrame.ARP:
            arp = frame.data
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
                    self.send(src_ip, fram)
            elif arp.type == ARP.REPLY:
                arpp = frame.data
                self.dump_arp_response_frame(frame)
        elif frame.type == EthernetFrame.IPV4:
            self.dump_ipv4_frame(frame)


host_a = Host(mac_addr = "aaaa.bbbb.cccc.dddd", ip_addr = "192.168.1.1")
host_b = Host(mac_addr = "aaaa.bbbb.cccc.eeee", ip_addr = "192.168.1.2")
switch = Switch(4)

host_a.connect(1, switch)
host_b.connect(2, switch)

host_a.send_data("192.168.1.2", 80, b'\xca\xfe\xba\xbe')
