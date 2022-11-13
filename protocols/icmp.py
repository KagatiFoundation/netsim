class ICMP:
    REQUEST = 8
    REPLY = 0

    def __init__(self, typ: int, code: int, cksum, data: bytes = b''):
        self.type = typ
        self.code = code
        self.cksum = cksum
        self.data = data

    def __len__(self):
        return 8 + len(self.data)