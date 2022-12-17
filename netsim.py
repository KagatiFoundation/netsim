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
        elif protocol == TransportLayerPacket.TCP:
            seq_num = random.randint(0x00, 0xFFFFFFFF)
            self._tcp_socket = {"ack_num": 0, "seq_num": seq_num}
            return TCPPacket(src_port, dest_port, 0, seq_num = seq_num, data = data, flags = 0b000000010)
        return None

    '''
    This method returns fragmented IP packets given the data.
    If the data size is greater than MTU, then this fragments data to fit into 
    the MTU size.
    '''
    def create_network_packet(self, src_ip, dest_ip, upper_layer_protocol: ipv4.IPv4Packet.UpperLayerProtocol, tpacket):
        raw_bytes = pickle.dumps(tpacket)
        data_length = len(raw_bytes)
        identifier = rand.randint(0xFFFF, 0xFFFFFFFF)
        return ipv4.IPv4Packet(src_ip, dest_ip, upper_layer_protocol, tpacket, identifier=identifier)
        '''
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
        '''

    def create_ethernet_frame(self, src_mac, dest_mac, data, typ):
        return EthernetFrame(src_mac, dest_mac, data, typ)

    def send(self, frame: EthernetFrame):
        device = self.ethernet_port.connected_device
        return device.receive(frame)

    def send_data(self, dest_ip: str, dest_port: int, packet_type, data: bytes):
        if packet_type == ipv4.IPv4Packet.UpperLayerProtocol.ICMP:
            data = ICMP(8, 0, None, b'')
        elif packet_type == ipv4.IPv4Packet.UpperLayerProtocol.TCP:
            data = self.create_transport_packet(1000, dest_port, TransportLayerPacket.TCP, data)
        elif packet_type == ipv4.IPv4Packet.UpperLayerProtocol.UDP:
            data = self.create_transport_packet(1000, dest_port, TransportLayerPacket.UDP, data)
        else: return False
        
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
                    packet_type,
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
            frame.data = ether_data
            frame_dumper.dump_ethernet_frame(frame)
            if not self.send(frame): return False
        return True

    def receive(self, frame: EthernetFrame):
        if not frame: return False 

        if frame.type == EthernetFrame.ARP:
            arp: ARP = frame.data
            src_ip = arp.sender_protocol_addr
            self.arp_table[src_ip] = arp.sender_hardware_addr

            if arp.type == ARP.REQUEST:
                if arp.target_protocol_addr != self.ip_addr:
                    return False
                
                arpp = ARP(
                        self.mac_addr, 
                        self.ip_addr, 
                        arp.sender_hardware_addr, 
                        arp.sender_protocol_addr, 
                        typ=ARP.REPLY
                    )
                fram = EthernetFrame(self.mac_addr, frame.src_mac, arpp, EthernetFrame.ARP)
                return self.send(fram)
            elif arp.type == ARP.REPLY:
                if arp.target_protocol_addr == self.ip_addr:
                    frame_dumper.dump_ethernet_frame(frame)
                    return True
            else: return False
        elif frame.type == EthernetFrame.IPV4:
            ippacket: ipv4.IPv4Packet = frame.data
            if ippacket.dest_ip != self.ip_addr: return False

            if ippacket.upper_layer_protocol == ipv4.IPv4Packet.UpperLayerProtocol.ICMP:
                icmpp:ICMP = ippacket.data
                if icmpp.type == ICMP.REQUEST:
                    icmpp_reply = ICMP(ICMP.REPLY, 0, None, b'')
                    net_pack = self.create_network_packet(self.ip_addr, ippacket.src_ip, ipv4.IPv4Packet.UpperLayerProtocol.ICMP, icmpp_reply)
                    fram = EthernetFrame(self.mac_addr, frame.src_mac, net_pack, EthernetFrame.IPV4)
                    return self.send(fram)
            elif ippacket.upper_layer_protocol == ipv4.IPv4Packet.UpperLayerProtocol.TCP:
                tcp: TCPPacket = ippacket.data
                if not hasattr(self, '_tcp_socket'): self._tcp_socket = dict() # handling only 1 TCP connection at a time

                _syn_bit = (tcp.flags >> 0x1) & 0x1
                _ack_bit = (tcp.flags >> 0x4) & 0x1
                if _syn_bit == 0x1:
                    if _ack_bit == 0x1:
                        reply_flags = 0b000010000
                        ack_num = tcp.seq_num + 1
                        seq_num = self._tcp_socket.get('seq_num') + 1
                        self._tcp_socket['seq_num'] = seq_num
                        self._tcp_socket['ack_num'] = ack_num
                    else:
                        reply_flags = 0b000010010
                        seq_num = random.randint(0x00, 0xFFFFFFFF)
                        self._tcp_socket['seq_num'] = seq_num
                        self._tcp_socket['ack_num'] = tcp.seq_num + 1
                elif _ack_bit == 0x1:
                    print("TCP connection established")
                    sys.exit(0)
                tcp_reply = TCPPacket(1000, tcp.src_port, self._tcp_socket.get("ack_num"), self._tcp_socket.get("seq_num"), b'', 5, reply_flags)
                net_pack = self.create_network_packet(self.ip_addr, ippacket.src_ip, ipv4.IPv4Packet.UpperLayerProtocol.TCP, tcp_reply)
                fram = EthernetFrame(self.mac_addr, frame.src_mac, net_pack, EthernetFrame.IPV4)
            frame_dumper.dump_ethernet_frame(fram)
            return self.send(fram)
        return False

if __name__ == "__main__":
    host1 = Host("192.168.1.1", "aa:bb:aa:bb:aa:bb")
    host2 = Host("192.168.1.2", "aa:bb:aa:bb:aa:cc")
    sw = Switch(4)
    host1.connect(sw)
    host2.connect(sw)
    sw.connect_on_port(1, host1)
    sw.connect_on_port(2, host2)
    host1.send_data("192.168.1.2", 100, ipv4.IPv4Packet.UpperLayerProtocol.TCP, b'Hello')