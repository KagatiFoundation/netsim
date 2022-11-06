#!/usr/bin/env python3

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
