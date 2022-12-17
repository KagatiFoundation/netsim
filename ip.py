#!/usr/bin/env python3

from protocols import ipv4
from ethernet import EthernetPort
from protocols.arp import ARP
from ethernet import EthernetFrame

def on_same_subnetwork(dest_ip, ip_addr, subnet_mask):
    src = int(f'0b{ipv4.IPv4.ipv4_to_binary(ip_addr)}', 2)
    sub = int(f'0b{ipv4.IPv4.ipv4_to_binary(subnet_mask)}', 2)
    dest = int(f'0b{ipv4.IPv4.ipv4_to_binary(dest_ip)}', 2)
    my_network = src & sub
    return my_network == (sub & dest)

class Router:
    def __init__(self, mac_addr, ip_addr):
        self.mac_addr = mac_addr
        self.ip_addr = ip_addr
        self.routing_table = None
        self.interfaces = None

    def connect_on_interface(self, interf, device):
        if interf not in self.interfaces.keys():
            print("Invalid interface")
            return
        self.interfaces.get(interf).connect(device)

    def configure(self, **configs):
        routing_table = configs.get("routing_table")
        if routing_table:
            self.routing_table = routing_table

        interfaces = configs.get("interfaces")
        if interfaces:
            self.interfaces = interfaces

    def route(self, dest_ip: str, data):
        if not self.routing_table: return False
        for entry in self.routing_table:
            if on_same_subnetwork(dest_ip, entry.get("destination"), entry.get("netmask")):
                interf = entry.get("interface")
                self.interfaces.get(interf).connected_device.receive(data)
                return True
        return False

    def receive(self, frame):
        if frame.type == EthernetFrame.ARP:
            arp: ARP = frame.data
            if arp.target_protocol_addr != self.ip_addr:
                return False
            arpp = ARP(self.mac_addr, self.ip_addr, frame.src_mac, arp.sender_protocol_addr, ARP.REPLY)
            self.route(arp.sender_protocol_addr, EthernetFrame(self.mac_addr, frame.src_mac, arpp, EthernetFrame.ARP))
            return True

    def send(self, frame):
        print("Sending")
        return True

    def show_ip_route(self):
        print(f'+{"-":-^98}+')
        print(f'|{"*** Routing Table ***":<98}|')
        print(f"|{'Codes: DC - Directly Connected, S - Static, D - Dynamic':<98}|")
        if not self.routing_table: return
        for entry in self.routing_table:
            typ = entry.get("type")
            if typ == "DC":
                msg = "is directly connected"
            subnet = entry.get("netmask")
            dest = entry.get("destination")
            interf = entry.get("interface")
            subbin = ipv4.IPv4.ipv4_to_binary(subnet)
            info_msg = f'{entry.get("type")}\t{dest}/{subbin.count("1")} {msg}, {interf}'
            print(f"|{info_msg:<94}|")
        print(f'+{"-":-^98}+')

if __name__ == "__main__":
    import netsim

    router = Router(ip_addr = "192.168.1.1", mac_addr = "bb:bb:bb:bb:bb:bb")
    router.configure(
        routing_table = [
                    {
                        "type": "DC",
                        "destination": "192.168.1.0", 
                        "netmask": "255.255.255.0",
                        "next-hop": "0.0.0.0",
                        "interface": "lan"
                    },
                    {
                        "type": "DC",
                        "destination": "0.0.0.0", 
                        "netmask": "0.0.0.0",
                        "next-hop": "27.34.22.129",
                        "interface": "FastEthernet"
                    },
                ],
        interfaces = {
                "lan": EthernetPort(),
                "FastEthernet": EthernetPort()
            })

    router2 = Router(ip_addr = "192.168.2.1", mac_addr = "bb:ab:bb:bb:bb:bb")
    router2.configure(
        routing_table = [
                    {
                        "type": "DC",
                        "destination": "192.168.2.0", 
                        "netmask": "255.255.255.0",
                        "next-hop": "0.0.0.0",
                        "interface": "lan"
                    },
                    {
                        "type": "DC",
                        "destination": "0.0.0.0", 
                        "netmask": "0.0.0.0",
                        "next-hop": "27.34.22.129",
                        "interface": "FastEthernet"
                    },
                ],
        interfaces = {
                "lan": EthernetPort(),
                "FastEthernet": EthernetPort()
            })

    host1 = netsim.Host(ip_addr = "192.168.1.3", mac_addr = "ab:ab:ab:ab:ab:ab")
    host1.default_gateway = "192.168.1.1"
    host1.connect(router)
    router.connect_on_interface("lan", host1)

    host2 = netsim.Host(ip_addr = "192.168.2.3", mac_addr = "ab:ab:ab:ab:eb:ab")
    host2.default_gateway = "192.168.2.1"
    host2.connect(router)
    router2.connect_on_interface("lan", host2)

    router2.connect_on_interface("FastEthernet", router)
    router.connect_on_interface("FastEthernet", router2)

    host1.send_data("192.168.2.3", 80, ipv4.IPv4Packet.UpperLayerProtocol.UDP, b"Hello")
    router.show_ip_route()