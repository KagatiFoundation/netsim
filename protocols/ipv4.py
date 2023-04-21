#!/usr/bin/env python3

from enum import Enum
from protocols.udp import UDP
from protocols.tcp import TCP

class IPv4:
    @staticmethod
    def is_valid_ipv4(ip: str):
        octets = ip.split('.')
        for octet in octets:
            octet_i = int(octet)
            if octet_i < 0 or octet_i > 255:
                return False
        return True

    @staticmethod
    def is_class_a_ip(ip: str):
        octets = list(map(int, ip.split('.')))
        if octets[0] != 10:
            return False
        return all(map(lambda x: x >= 0 and x <= 255, [octets[1], octets[2], octets[3]]))

    @staticmethod
    def is_class_b_ip(ip: str):
        octets = list(map(int, ip.split('.')))
        if octets[0] != 172:
            return False

        o1 = octets[1]
        o2 = octets[2]
        o3 = octets[3]
        return all([(o1 >= 16 and o1 <= 31), (o2 >= 0 and o2 <= 255), (o3 >= 0 and o3 <= 255)])

    @staticmethod
    def is_class_c_ip(ip: str):
        octets = list(map(int, ip.split('.')))
        if (octets[0] != 192) and (octets[2] != 168):
            return False
        return all(list(map(lambda x: x >= 0 and x <= 255, [octets[2], octets[3]])))

    @staticmethod
    def is_private_ip(ip: str):
        if not IPv4.is_valid_ipv4(ip): return False
        return any([IPv4.is_class_a_ip(ip), IPv4.is_class_b_ip(ip), IPv4.is_class_c_ip(ip)])

    @staticmethod
    def ipv4_to_binary(ip: str):
        if not IPv4.is_valid_ipv4(ip): return ""
        octets = ip.split('.')
        output = ""
        for octet in octets:
            output += bin(int(octet))[2:].rjust(8, '0')
        return output


class IPv4Packet:
    NO_FRAG = 0b10
    MORE_FRAG = 0b1

    class UpperLayerProtocol(Enum):
        ICMP = 1
        TCP = 6
        UDP = 17

    def __init__(self, src_ip, dest_ip, upper_layer_protocol, data, identifier: int = 0x0, offset: int = 0x0, flags: int = 0x0, options = None):
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.data = data
        self.upper_layer_protocol = upper_layer_protocol
        self.header_length = 20 # 20 bytes if there aren't any extra options
        self.datagram_length =  len(self)
        self.identifier = identifier
        self.type_of_service = 0
        self.ttl = 128
        self.header_checksum = 1111
        self.fragment_offset = offset
        self.flags = flags
        self.options = options

    def __len__(self):
        return self.header_length + len(self.data)
