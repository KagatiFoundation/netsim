class ICMP:
    def __init__(self, typ: int, code: int, cksum, data: bytes = None):
        self.type = typ
        self.code = code
        self.cksum = cksum
        self.data = data

    def __len__(self):
        return 8