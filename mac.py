import typing 
import errors.mac_error as mac_error
import re

MAC_ADDR_REGEX = re.compile(r'^([a-fA-F0-9]{1,2}:){5}([a-fA-F0-9]{1,2})$')

class MACAddr:
    def __init__(self, octets: typing.List[int]):
        if len(octets) != 6:
            raise mac_error.MACAddrError(f"MAC address should be 6 bytes long. Given length: '{len(octets)}'.")

        for byte in octets:
            if byte < 0 or byte > 255:
                raise mac_error.MACAddrError(f"'{byte}' is not a valid value for MAC address octet.")
        self.__octets = octets

    @classmethod
    def from_string(cls, mac: str):
        matches = re.match(MAC_ADDR_REGEX, mac)
        if not matches:
            raise mac_error.MACAddrError(f"Invalid MAC address: '{mac}'.")
        octets = list(map(lambda x: int(f'0x{x}', 16), mac.split(":")))
        return cls(octets)

    def __getitem__(self, key):
        self.__check_key_validity(key)
        return self.__octets[key]

    def __setitem__(self, key, value):
        self.__check_key_validity(key)
        self.__octets[key] = value

    def __check_key_validity(self, key):
        if not isinstance(key, int):
            raise KeyError(f"Type {type(key)} is not valid type of key for MACAddr indexing. Try using int.")
        if int(key) < 0 or int(key) > 5:
            raise KeyError(f"Valid index range for MACAddr indexing: 0 - 5.")

    def __str__(self):
        return ":".join([f"{hex(byte)[2:].rjust(2, '0')}" for byte in self.__octets])

if __name__ == "__main__":
    mac = MACAddr.from_string("ff:ff:f:3:54:34")
    print(mac[0])