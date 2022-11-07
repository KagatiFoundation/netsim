#!/usr/bin/env python3

from ethernet import *
from transport_layer import *
from network_layer import *
from datalink_layer import *
from node import Node

class ARP:
    REQUEST = 1
    REPLY = 2

    def __init__(self, sha, spa, tha, tpa, typ):
        self.sender_hardware_addr = sha
        self.sender_protocol_addr = spa
        self.target_hardware_addr = tha
        self.target_protocol_addr = tpa
        self.type = typ
        self.length = len(self)

    def __len__(self):
        return 45


class Host(Node):
    def __init__(self, ip_addr: str, mac_addr: str):
        self.mac_addr = mac_addr
        self.ip_addr = ip_addr
        self.ether_connection = None
        self.arp_table = dict()
        self.default_gateway = "192.168.1.255"
        self.subnet_mask = "255.255.255.0"
        self.ethernet_port = EthernetPort()

    def connect(self, device) -> None:
        self.ether_connection = device
        self.ethernet_port.connect(device)

    def dump_ethernet_frame(self, frame: EthernetFrame):
        print()
        print('-' * 50)
        print('| --- Start Ethernet frame ---')
        length = frame.length
        print(f'| \tFrame length: {length} bytes ({length * 8} bits)') # dummy data
        print('| --- End Ethernet frame ---')
        print('-' * 50)

    def dump_arp_request_frame(self, frame):
        arp = frame.data
        self.dump_ethernet_frame(frame)
        print("| --- Start ARP Request ---")
        print(f'| \t{arp.sender_protocol_addr} ==> {arp.target_protocol_addr}')
        print(f'| \tData: Who is {arp.target_protocol_addr}?')
        print("| --- End ARP request ---")
        print('-' * 50)

    def dump_arp_response_frame(self, frame):
        arp = frame.data
        self.dump_ethernet_frame(frame)
        print("| --- Start ARP Response ---")
        print(f'| \t{arp.sender_protocol_addr} ==> {arp.target_protocol_addr}')
        print(f'| \tData: {arp.sender_hardware_addr} is {arp.sender_protocol_addr}')
        print("| --- End ARP response ---")
        print('-' * 50)

    def dump_ipv4_frame(self, frame):
        ipv4 = frame.data
        self.dump_ethernet_frame(frame)
        print("| --- Start IPv4 packet ---")
        print(f'| \t{ipv4.src_ip} ==> {ipv4.dest_ip}')
        print("| --- End IPv4 packet ---")
        print('-' * 50)

    def dump_udp_frame(self, frame):
        udp = frame.data.data
        self.dump_ipv4_frame(frame)
        print('| --- Start UDP frame ---')
        print(f'| \tUDP Data: {udp.data}')
        print('| --- End UDP frame ---')
        print('-' * 50)

    def make_arp_request(self, ip_addr: str) -> str:
        arp = ARP(self.mac_addr, self.ip_addr, None, ip_addr, ARP.REQUEST)
        frame = EthernetFrame(self.mac_addr, "ffff:ffff:ffff:ffff", arp, typ=EthernetFrame.ARP)
        result = self.ethernet_port.connected_device.receive(frame)
        if not result:
            print("\n*** ARP request timeout ***")
            print("\tHost unreachable")
            return False
        return True

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

    def send(self, frame: EthernetFrame):
        device = self.ethernet_port.connected_device
        device.receive(frame)
        return True

    def send_data(self, dest_ip: str, dest_port: int, data: bytes):
        ether_data = self.create_network_packet(
                    self.ip_addr, 
                    dest_ip, 
                    self.create_transport_packet(1000, dest_port, TransportLayerPacket.UDP, data)
                )
        frame = self.create_ethernet_frame(
            self.mac_addr, 
            None, 
            ether_data, 
            EthernetFrame.IPV4
        )
        dest_mac = self.arp_table.get(dest_ip)
        arp_result = True
        if not dest_mac:
            is_lan = self.do_subnet_mask(dest_ip)
            if is_lan:
                arp_result = self.make_arp_request(dest_ip)
            else:
                arp_result = self.make_arp_request(self.default_gateway)

        if arp_result:
            frame.dest_mac = self.arp_table.get(dest_ip)
            return self.send(frame)

    def receive(self, frame: EthernetFrame):
        if frame.type == EthernetFrame.ARP:
            arp = frame.data
            src_ip = arp.sender_protocol_addr
            self.arp_table[src_ip] = arp.sender_hardware_addr
            if arp.type == ARP.REQUEST:
                self.dump_arp_request_frame(frame)
                if arp.target_protocol_addr == self.ip_addr:
                    arpp = ARP(
                            self.mac_addr, 
                            self.ip_addr, 
                            arp.sender_hardware_addr, 
                            arp.sender_protocol_addr, 
                            typ=ARP.REPLY
                        )
                    fram = EthernetFrame(self.mac_addr, frame.src_mac, arpp, EthernetFrame.ARP)
                    self.send(fram)
                else: return False
            elif arp.type == ARP.REPLY:
                self.dump_arp_response_frame(frame)
            else: return False
        elif frame.type == EthernetFrame.IPV4:
            ipv4 = frame.data
            if ipv4.upper_layer_protocol == IPv4Packet.UpperLayerProtocol.UDP:
                self.dump_udp_frame(frame)
        return True


if __name__ == "__main__":
    host_a = Host(mac_addr = "aaaa.bbbb.cccc.dddd", ip_addr = "192.168.1.1")
    host_b = Host(mac_addr = "aaaa.bbbb.cccc.eeee", ip_addr = "192.168.1.3")
    switch = Switch(4)

    host_a.connect(switch)
    switch.connect_on_port(1, host_a)

    host_b.connect(switch)
    switch.connect_on_port(2, host_b)

    host_a.send_data("192.168.1.3", 80, b'\xca\xfe')
    host_a.send_data("192.168.1.3", 80, b'\xba\xbe\xfe')