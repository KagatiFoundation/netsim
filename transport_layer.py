#!/usr/bin/env python3

import random

class TransportLayerPacket:
    UDP = 1
    TCP = 2

    def __init__(self, src_port, dest_port, data: bytes):
        self.src_port = src_port
        self.dest_port = dest_port
        self.data = data


class TCPPacket(TransportLayerPacket):
    def __init__(self, src_port: int, dest_port: int, ack_num: int, seq_num: int = random.randint(0x00, 0xFFFFFFFF), data: bytes = b'', off: int = 0b000000000, flags: int = 0, window = 0, checksum = 0, urgent_p = 0, options = ''):
        super().__init__(src_port, dest_port, data)
        self.seq_num = seq_num # 32 bits
        self.ack_num = ack_num # 32 bits
        self.data_offset = off # 16 bits
        self.reserved = 0b000 # 3 bits
        self.flags = flags # 9 bits
        self.window = window # 16 bits
        self.checksum = checksum # 16 bits
        self.urgent_pointer = urgent_p # 16 bits
        self.options = options # 0 - 320 bits

    def __len__(self):
        return 160 + len(self.data)


class UDPPacket(TransportLayerPacket):
    def __init__(self, src_port, dest_port, data: bytes):
        super().__init__(src_port, dest_port, data)
        self.length = len(self)
        self.checksum = 0b11111111

    def __len__(self):
        return 16 + len(self.data) # sizeof(source_port) + sizeof(dest_port) + sizeof(sizeofgth) + sizeof(checksum) + sizeof(data)
