import unittest
import os 
import sys

parent = os.path.abspath(".")
sys.path.insert(1, parent)

import mac
import errors.mac_error as mac_error

class TestMACAddr(unittest.TestCase):
    def test_from_string_returns_MACAddr_object_on_valid_hex_string(self):
        m = mac.MACAddr.from_string("ca:db:06:ae:3f:fb")
        self.assertTrue(m is not None)
    
    def test_from_string_returns_MACAddr_object_on_one_letter_hex_octet(self):
        m = mac.MACAddr.from_string("c:b:6:ae:3f:fb")
        self.assertTrue(m is not None)

    def test_from_string_raises_MACAddrError_on_invalid_hex_value(self):
        with self.assertRaises(mac_error.MACAddrError):
            m = mac.MACAddr.from_string("fg:45:09:bj:00:af")
            print(m)
    
    def test_from_string_raises_MACAddrError_on_less_than_or_more_than_6_octet_count(self):
        with self.assertRaises(mac_error.MACAddrError):
            m = mac.MACAddr.from_string("ff:09:b:00:af")
            print(m)
    
    def test_from_string_raises_MACAddrError_on_less_than_or_more_than_6_octet_count2(self):
        with self.assertRaises(mac_error.MACAddrError):
            m = mac.MACAddr.from_string("ff:09::00:af:45:be")
            print(m)
    
    def test_from_string_raises_MACAddrError_on_hex_string_without_colon(self):
        with self.assertRaises(mac_error.MACAddrError):
            m = mac.MACAddr.from_string("ff0900af45be")
            print(m)

if __name__ == "__main__":
    unittest.main()