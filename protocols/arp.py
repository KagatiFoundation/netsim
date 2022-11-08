#!/usr/bin/env python3

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