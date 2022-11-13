#!/usr/bin/env python3

from ethernet import *
from transport_layer import *
from network_layer import *
from datalink_layer import *
from node import Node
from protocols import ipv4
from protocols.arp import ARP

class Host(Node):
    def __init__(self, ip_addr: str, mac_addr: str):
        self.mac_addr = mac_addr
        self.ip_addr = ip_addr
        self.ether_connection = None
        self.arp_table = {"localhost": self.mac_addr, "127.0.0.1": self.mac_addr}
        self.default_gateway = "192.168.1.254"
        self.subnet_mask = "255.255.255.0"
        self.ethernet_port = EthernetPort()

    def connect(self, device) -> None:
        self.ether_connection = device
        self.ethernet_port.connect(device)

    def dump_ethernet_frame(self, frame: EthernetFrame):
        print()

        ETHERNET_FRAME_BORDER_LEN = 100
        print('+' + ('-' * (ETHERNET_FRAME_BORDER_LEN - 2)) + '+')
        length = frame.length
        messages = [
            f'|        Frame length: {length} bytes ({length * 8} bits)',
        ]

        frame_start_border_title = '| --- Ethernet frame ---'
        print(frame_start_border_title+ (ETHERNET_FRAME_BORDER_LEN - len(frame_start_border_title) - 1) * ' ' + '|')
        for message in messages:
            print(message + (ETHERNET_FRAME_BORDER_LEN - len(message) - 1) * ' ' + '|')

        if frame.type == EthernetFrame.ARP:
            self.dump_arp_frame(frame.data)

        frame_end_border_title = '| --- End Ethernet frame ---'
        print(frame_end_border_title + (ETHERNET_FRAME_BORDER_LEN - len(frame_end_border_title) - 1) * ' ' + '|')
        print('+' + ('-' * (ETHERNET_FRAME_BORDER_LEN - 2)) + '+')

    def dump_arp_frame(self, arp):
        header = "Request"
        target_mac = arp.target_hardware_addr
        if arp.type == ARP.REPLY:
            header = "Reply"
            target_mac = "00:00:00:00:00:00"

        ARP_FRAME_BORDER_LEN = 80
        arp_frame = '|        +' + ('-' * (ARP_FRAME_BORDER_LEN - 2)) + '+'
        arp_frame += ((100 - len(arp_frame) - 1) * ' ') + '|'
        messages = [
            f'|        | --- ARP ({header}) ---',
            f'|        |        Hardware type: Ethernet (1)',
            f'|        |        Protocol type: IPv4 (0x0800',
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
        return ipv4.IPv4Packet(src_ip, dest_ip, ipv4.IPv4Packet.UpperLayerProtocol.UDP, tpacket)

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
            is_lan = ipv4.IPv4.is_private_ip(dest_ip)
            if is_lan:
                arp_result = self.make_arp_request(dest_ip)
            else:
                arp_result = self.make_arp_request(self.default_gateway)

        if arp_result:
            frame.dest_mac = self.arp_table.get(dest_ip)
            return self.send(frame)

    def receive(self, frame: EthernetFrame):
        if not frame: return False 
        self.dump_ethernet_frame(frame)

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
                    self.send(fram)
                else: return False
            elif arp.type == ARP.REPLY:
                pass
            else: return False
        elif frame.type == EthernetFrame.IPV4:
            pass
        return True

if __name__ == "__main__":
    host_a = Host(mac_addr = "fa:ce:de:ad:be:ef", ip_addr = "192.168.1.4")
    switch = Switch(4)

    host_a.connect(switch)
    switch.connect_on_port(1, host_a)

    host_b = Host(mac_addr = "aa:aa:bb:bb:cc:dd", ip_addr = "192.168.1.5")
    host_b.connect(switch)
    switch.connect_on_port(2, host_b)

    host_a.send_data("192.168.1.5", 80, b'\xca\xfe')