#!/usr/bin/env python3

import random

class TCP:
    FIN = 0b1
    SYN = 0b10
    RST = 0b100
    PSH = 0b1000
    ACK = 0b10000
    URG = 0b100000
    ECE = 0b1000000
    CWR = 0b10000000

    def __init__(self, src_port: int, dest_port: int, ack_num: int, seq_num: int = random.randint(0x00, 0xFFFFFFFF), data: bytes = b'', off: int = 0b000000000, flags: int = 0, window = 0, checksum = 0, urgent_p = 0, options = ''):
        self.src_port = src_port
        self.dest_port = dest_port
        self.data = data
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

