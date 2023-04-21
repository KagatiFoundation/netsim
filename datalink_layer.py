#!/usr/bin/env python3

from ethernet import *
from node import Node

import sys
import threading
import time

class Switch(Node):
    def __init__(self, port_count: int = 4):
        self.port_count = port_count
        self.mac_table = dict()
        self.hosts = dict()
        self.ports = {port_number + 1: EthernetPort() for port_number in range(port_count)}
        self.vlans = {1: VLAN(1, ports = self.ports.copy())}
        self.__mac_table_manager_thread = threading.Thread(target = self.__manage_mac_table)
        self.__mac_table_manager_thread.start()

    def __manage_mac_table(self):
        while True:
            time.sleep(2)
            self.mac_table.clear()

    def connect(self, node = None) -> None:
        print("Use method 'connect_on_port': this method is not supported")
        sys.exit(1)

    def connect_on_port(self, port_number: int, device) -> None:
        if port_number in self.mac_table.keys():
            return
        if port_number < 1 or port_number > self.port_count:
            return
        self.ports.get(port_number).connect(device)
        self.mac_table[device.mac_addr] = port_number

    def send(self, frame: EthernetFrame):
        dest_mac = frame.dest_mac
        port = self.mac_table.get(dest_mac)
        if not port:
            return self.flood(frame)
        else:
            src_mac = frame.src_mac
            src_port = self.mac_table.get(src_mac)
            src_vlan_id = self.find_vlan(port_number = src_port)
            dest_vlan_id = self.find_vlan(port_number = port)
            if(src_vlan_id != dest_vlan_id):
                print("Ports are not on same VLAN")
                return False

        return self.send_through_port(port, frame)

    def send_through_port(self, port_number: int, frame: EthernetFrame):
        return self.ports.get(port_number).connected_device.receive(frame)

    def receive(self, frame: EthernetFrame):
        if frame.dest_mac == "ffff:ffff:ffff:ffff": return self.flood(frame)
        else: return self.send(frame)

    def flood(self, frame: EthernetFrame):
        sender_mac = frame.src_mac
        for port in self.ports.values():
            receiver = port.connected_device
            if receiver:
                if sender_mac != receiver.mac_addr:
                    if receiver.receive(frame): return True
        return False

    def create_vlan(self, id, name):
        if self.__vlan_exists(id = id):
            print(f"ERROR: Cannot add VLAN with ID '{id}'. VLAN with ID '{id}' already exists.")
            return
        elif self.__vlan_exists(name = name):
            print(f"ERROR: Cannot add VLAN with name '{name}'. VLAN named '{name}' already exists.")
            return

        self.vlans[id] = VLAN(id, name)

    # change mode to access or trunk port
    # def change_mode(self, port_number: int):

    # Get ID of vlan where a given port might exist
    def find_vlan(self, port_number: int):
        if port_number < 1 or port_number > self.port_count:
            print(f"ERROR: Port '{port_number}' doesn't exist.")
            return False

        for vlan in self.vlans.values():
            if port_number in vlan.ports.keys():
                return vlan.id
        return False

    def __vlan_exists(self, id = None, name = None):
        if id:
            for vlan_id in self.vlans.keys():
                if vlan_id == id: return True
        elif name:
            for vlan in self.vlans.values():
                if vlan.name == name: return True
        return False

    def access_vlan(self, port_number: int, vlan_id: int):
        if not self.__vlan_exists(vlan_id):
            print(f"ERROR: VLAN with ID {vlan_id} doesn't exist.")
            return False

        if port_number < 1 or port_number > self.port_count:
            print(f"ERROR: Port '{port_number}' doesn't exist.")
            return False

        current_vlan_id = 1
        for vlan in self.vlans.values():
            if port_number in vlan.ports.keys():
                current_vlan_id = vlan.id
                break

        self.vlans.get(current_vlan_id).ports.pop(port_number)
        vlan = self.vlans.get(vlan_id) 
        vlan.ports[port_number] = self.ports.get(port_number)
        

    def display_mac_table(self):
        print(f'{"MAC Address Table":^50}')
        print(f"{'':-^50}")
        print("MAC Address\t\t\tPort")
        print("----------\t\t\t-------")
        for port, mac in enumerate(self.mac_table):
            print(mac + "\t\t" + str(port))

    def display_vlan_table(self):
        print(f"{'VLAN Table':^80}")
        print(f"{'':-^80}")
        print("VLAN\t\t\tName\t\t\tStatus\t\t\tPorts")
        print("----\t\t\t-----\t\t\t------\t\t\t-----")
        for vlan in self.vlans.values():
            print(f'{vlan.id}\t\t\t{vlan.name}\t\t\t{"Active" if vlan.status == VLAN.ACTIVE else "Inactive"}\t\t\t{list(vlan.ports.keys())}')


class VLAN:
    ACTIVE = 0x1
    INACTIVE = 0x2

    def __init__(self, id: int, name = "default", ports = dict()):
        self.id = id
        self.status = VLAN.ACTIVE
        self.name = name
        self.ports = ports