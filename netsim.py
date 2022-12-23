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
import random
import typing

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
        self.__ip_data_packs = dict()

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
            return TCPPacket(src_port, dest_port, self._tcp_socket.get('ack_num'), seq_num = self._tcp_socket.get('seq_num'), data = data)
        return None

    '''
    This method returns fragmented IP packets given the data.
    If the data size is greater than MTU, then this fragments data to fit into 
    the MTU size.
    '''
    def create_network_packet(self, src_ip, dest_ip, upper_layer_protocol: ipv4.IPv4Packet.UpperLayerProtocol, tpacket):
        raw_bytes = pickle.dumps(tpacket)
        data_length = len(raw_bytes)
        identifier = random.randint(0xFFFF, 0xFFFFFFFF)
        if data_length <= self.mtu:
            # Return 'tpacket' object with IP data without fragmenting.
            yield ipv4.IPv4Packet(src_ip, dest_ip, upper_layer_protocol, tpacket, identifier=identifier)
        else:
            # Return 'tpacket' object with IP data by fragmenting into multiple
            # packets.
            buffer_pointer = 0
            frag_off = 1
            while True:
                yield ipv4.IPv4Packet(src_ip, dest_ip, upper_layer_protocol, raw_bytes[buffer_pointer:buffer_pointer + self.mtu], identifier=identifier, flags=0b001, offset = frag_off)
                buffer_pointer += self.mtu
                left_data = raw_bytes[buffer_pointer:]
                if len(left_data) > self.mtu:
                    frag_off += 1
                    continue
                else:
                    yield ipv4.IPv4Packet(src_ip, dest_ip, upper_layer_protocol, left_data, identifier=identifier, offset = frag_off)
                    break

    def create_ethernet_frame(self, src_mac, dest_mac, data, typ):
        return EthernetFrame(src_mac, dest_mac, data, typ)

    def send(self, frame: EthernetFrame):
        device = self.ethernet_port.connected_device
        return device.receive(frame)

    def __do_arp(self, dest_ip: str) -> bool:
        arp_res = True
        same_subnet = self.on_same_subnetwork(dest_ip)
        if same_subnet:
            arp_res = self.make_arp_request(dest_ip)
        else:
            arp_res = self.make_arp_request(self.default_gateway)
        return arp_res

    # init -> initiate
    def __init_3_way_handshake(self, dest_ip: str, dest_port: int) -> bool:
        dest_mac = self.arp_table.get(dest_ip)
        arp_result = True
        if not dest_mac:
            arp_result = self.__do_arp(dest_ip)
        
        if arp_result:
            # Following two lines of code is to maintain a status of TCP connection
            # in a host. When a host initiates the 3 way handshake, new TCP 
            # connection is established. Only one connection can exist at a time(
            # in this simulator).
            # 'status' set to value 'SYN' indicates that this host is sending its 
            # first TCP packet -- SYN packet.
            seq_num = random.randint(0x0, 0xFFFFFFFF)

            # Vanilla dictionary to maintain TCP session information.
            self._tcp_socket = {"ack_num": 0, "seq_num": seq_num, "status": "SYN"}

            # 'net_pack' is SYN packet.
            # Look at the flags argument -- SYN bit is set.
            # SYN bit is second bit(LSB) in flags field of TCP packet.
            net_pack = self.create_network_packet(
                self.ip_addr, 
                dest_ip,
                ipv4.IPv4Packet.UpperLayerProtocol.TCP, 
                TCPPacket(random.randint(0, 65535), dest_port, 0, data = b'', off = 0, flags = 0b10)
            )
            for np in net_pack:
                frame = EthernetFrame(self.mac_addr, dest_mac, np, EthernetFrame.IPV4)
                frame_dumper.dump_ethernet_frame(frame)
                if not self.send(frame): return False
            return True
        return False

    def send_data(self, dest_ip: str, dest_port: int, packet_type, data: bytes):
        if packet_type == ipv4.IPv4Packet.UpperLayerProtocol.ICMP:
            data = ICMP(8, 0, None, b'')
        elif packet_type == ipv4.IPv4Packet.UpperLayerProtocol.TCP:
            if not self.__init_3_way_handshake(dest_ip, dest_port):
                print("Failed to complete 3 way handshake")
                return False
            data = self.create_transport_packet(1000, dest_port, TransportLayerPacket.TCP, data)
        elif packet_type == ipv4.IPv4Packet.UpperLayerProtocol.UDP:
            data = self.create_transport_packet(1000, dest_port, TransportLayerPacket.UDP, data)
        else: return False
        
        dest_mac = self.arp_table.get(dest_ip)
        arp_result = True
        if not dest_mac:
            arp_result = self.__do_arp(dest_ip)

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
            for packet in ether_data:
                frame.data = packet
                # frame_dumper.dump_ethernet_frame(frame)
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
                    self.arp_table[src_ip] = arp.sender_hardware_addr
                    frame_dumper.dump_ethernet_frame(frame)
                return True
            else: return False
        elif frame.type == EthernetFrame.IPV4:
            ippacket: ipv4.IPv4Packet = frame.data
            if ippacket.dest_ip != self.ip_addr: return False

            more_frags = (ippacket.flags & 0x1) == 0x1
            ident = ippacket.identifier
            if more_frags:
                pack: typing.List = self.__ip_data_packs.get(ident)
                if not pack:
                    pack: typing.List = []
                    self.__ip_data_packs[ident] = pack
                pack.append(ippacket.data)
                return True
            else:
                if ippacket.fragment_offset != 0x0:
                    self.__ip_data_packs.get(ident).append(ippacket.data)
                    assembled_data = self.__assemble_ip_data(identifier = ident, pack_type = ippacket.upper_layer_protocol, frame = frame)
                    ippacket.data = assembled_data
                else:
                    if isinstance(ippacket.data, bytes):
                        ippacket.data = pickle.loads(ippacket.data)

            if ippacket.upper_layer_protocol == ipv4.IPv4Packet.UpperLayerProtocol.ICMP:
                icmpp:ICMP = ippacket.data
                if icmpp.type == ICMP.REQUEST:
                    icmpp_reply = ICMP(ICMP.REPLY, 0, None, b'')
                    net_pack = self.create_network_packet(self.ip_addr, ippacket.src_ip, ipv4.IPv4Packet.UpperLayerProtocol.ICMP, icmpp_reply)
                    fram = EthernetFrame(self.mac_addr, frame.src_mac, net_pack, EthernetFrame.IPV4)
                    return self.send(fram)
            elif ippacket.upper_layer_protocol == ipv4.IPv4Packet.UpperLayerProtocol.TCP:
                tcp: TCPPacket = ippacket.data
                _syn_bit = (tcp.flags >> 0x1) & 0x1
                _ack_bit = (tcp.flags >> 0x4) & 0x1
                if _syn_bit == 0x1:
                    if _ack_bit == 0x1:
                        # If SYN and ACK both bits are set.
                        # In this(^^^) case, this host received a TCP SYN ACK 
                        # response to its previously sent TCP SYN request.
                        return self.__handle_tcp_syn_ack_pack(tcp, ippacket.src_ip)
                    else:
                        # If host receives packet with only SYN bit set.
                        # In this(^^^) case, this host is being sent a new 
                        # TCP connection request.
                        
                        # Vanilla dictionary to maintain TCP session information.
                        self._tcp_socket = dict()
                        return self.__handle_tcp_syn_pack(tcp, ippacket.src_ip)
                elif _ack_bit == 0x1:
                    self._tcp_socket['status'] = 'connected' # receiver side
                    print("TCP connection established")
                    return True
            else: return False # Protocol not supported
        return False

    def __send_ip_pack(self, dest_ip: str, data: typing.Any):
        dest_mac = self.arp_table.get(dest_ip)
        net_pack = self.create_network_packet(self.ip_addr, dest_ip, ipv4.IPv4Packet.UpperLayerProtocol.TCP, data)
        for np in net_pack:
            frame = EthernetFrame(self.mac_addr, dest_mac, np, EthernetFrame.IPV4)
            frame_dumper.dump_ethernet_frame(frame)
            if not self.send(frame): return False
        return True

    def __handle_tcp_syn_pack(self, syn_pack: TCPPacket, sender_ip: str):
        seq_num = random.randint(0x00, 0xFFFFFFFF)
        self._tcp_socket['seq_num'] = seq_num
        self._tcp_socket['ack_num'] = syn_pack.seq_num + 1

        # Replying with SYN ACK packet.
        # Last one is flags argument. SYN and ACK bits are set.
        syn_ack_reply = TCPPacket(1000, syn_pack.src_port, self._tcp_socket.get("ack_num"), seq_num, b'', 1, 0b000010010)
        return self.__send_ip_pack(sender_ip, syn_ack_reply)

    def __handle_tcp_syn_ack_pack(self, syn_ack_pack: TCPPacket, sender_ip: str):
        ack_num = syn_ack_pack.seq_num + 1
        seq_num = self._tcp_socket.get('seq_num') + 1
        self._tcp_socket['seq_num'] = seq_num
        self._tcp_socket['ack_num'] = ack_num

        # Replying with ACK packet.
        # Last one is flags argument. ACK bit is set.
        ack_reply = TCPPacket(1000, syn_ack_pack.src_port, self._tcp_socket.get("ack_num"), self._tcp_socket.get("seq_num"), b'', 2, 0b10000)
        result = self.__send_ip_pack(sender_ip, ack_reply)

        # Connection status is set to 'connected' after SYN ACK response 
        # is received and ACK reply is sent. 
        if result: self._tcp_socket['status'] = 'connected'
        return result

    def __assemble_ip_data(self, identifier, pack_type, frame):
        if not identifier or not pack_type: return
        chunks = self.__ip_data_packs.get(identifier)
        concated_chunk = b'' 
        for chunk in chunks:
            concated_chunk += chunk
        
        frame.data.data = pickle.loads(concated_chunk)
        frame_dumper.dump_ethernet_frame(frame)
        sys.exit(1)


if __name__ == "__main__":
    host1 = Host("192.168.1.1", "aa:bb:aa:bb:aa:bb")
    host2 = Host("192.168.1.2", "aa:bb:aa:bb:aa:cc")
    host3 = Host("192.168.1.3", "aa:bb:aa:bb:aa:ff")
    sw = Switch(4)
    host1.connect(sw)
    host2.connect(sw)
    host3.connect(sw)
    sw.connect_on_port(1, host1)
    sw.connect_on_port(2, host2)
    sw.connect_on_port(3, host3)
    host1.send_data("192.168.1.2", 100, ipv4.IPv4Packet.UpperLayerProtocol.TCP, b'A' * 1600)

    # TODO: Maintain port numbers in TCP session