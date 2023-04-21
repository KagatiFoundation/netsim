#!/usr/bin/env python3

class UDP:
    def __init__(self, src_port, dest_port, data: bytes):
        super().__init__(src_port, dest_port, data)
        self.src_port = src_port
        self.dest_port = dest_port
        self.data = data
        self.length = len(self)
        self.checksum = 0b11111111

    def __len__(self):
        return 16 + len(self.data) # sizeof(source_port) + sizeof(dest_port) + sizeof(sizeofgth) + sizeof(checksum) + sizeof(data)
