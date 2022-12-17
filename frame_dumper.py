from ethernet import EthernetFrame
from protocols.arp import ARP
from protocols import ipv4

def dump_ethernet_frame(frame: EthernetFrame):
    print()

    if frame.type == EthernetFrame.ARP:
        typp = f'ARP ({hex(EthernetFrame.ARP)})'
    elif frame.type == EthernetFrame.IPV4:
        typp = f'IPv4 ({hex(EthernetFrame.IPV4)})'

    ETHERNET_FRAME_BORDER_LEN = 100
    print('+' + ('-' * (ETHERNET_FRAME_BORDER_LEN - 2)) + '+')
    length = frame.length
    messages = [
        f'|        Frame length: {length} bytes ({length * 8} bits)',
        f'|        Destination: {frame.dest_mac}',
        f'|        Source: {frame.src_mac}',
        f'|        Type: {typp}'
    ]

    frame_start_border_title = '| --- Ethernet frame ---'
    print(frame_start_border_title+ (ETHERNET_FRAME_BORDER_LEN - len(frame_start_border_title) - 1) * ' ' + '|')
    for message in messages:
        print(message + (ETHERNET_FRAME_BORDER_LEN - len(message) - 1) * ' ' + '|')

    if frame.type == EthernetFrame.ARP:
        dump_arp_frame(frame.data)
    elif frame.type == EthernetFrame.IPV4:
        dump_ipv4_frame(frame.data)

    frame_end_border_title = '| --- End Ethernet frame ---'
    print(frame_end_border_title + (ETHERNET_FRAME_BORDER_LEN - len(frame_end_border_title) - 1) * ' ' + '|')
    print('+' + ('-' * (ETHERNET_FRAME_BORDER_LEN - 2)) + '+')


def dump_arp_frame(arp):
    header = "Request"
    target_mac = arp.target_hardware_addr if arp.target_hardware_addr else '00:00:00:00:00:00'
    data_msg = f'Who has {arp.target_protocol_addr}? Tell {arp.sender_protocol_addr}',
    if arp.type == ARP.REPLY:
        header = "Reply"
        data_msg = f"{arp.sender_protocol_addr} is at {arp.sender_hardware_addr}"

    ARP_FRAME_BORDER_LEN = 80
    arp_frame = '|        +' + ('-' * (ARP_FRAME_BORDER_LEN - 2)) + '+'
    arp_frame += ((100 - len(arp_frame) - 1) * ' ') + '|'
    messages = [
        f'|        | --- ARP ({header}) ---',
        f'|        |        Hardware type: Ethernet (1)',
        f'|        |        Protocol type: IPv4 (0x0800)',
        f'|        |        Hardware size: 6',
        f'|        |        Protocol size: 4',
        f'|        |        Sender MAC address: {arp.sender_hardware_addr}',
        f'|        |        Sender IP address: {arp.sender_protocol_addr}',
        f'|        |        Target MAC address: {target_mac}',
        f'|        |        Target IP address: {arp.target_protocol_addr}',
        f'|        |        \033[92m{data_msg}\033[0m',
        f'|        | --- End ARP ---',
    ]

    print(arp_frame)
    for message in messages:
        act_out_msg = message + (ARP_FRAME_BORDER_LEN - len(message) + 8) * ' ' + '|'
        length = len(act_out_msg)
        print(act_out_msg, (100 - length - 2) * ' ' + '|')
    print(arp_frame)
    

def dump_ipv4_frame(ippacket: ipv4.IPv4Packet):
    IP_BORDER_LEN = 80
    ipv4_frame = '|        +' + ('-' * (IP_BORDER_LEN - 2)) + '+'
    ipv4_frame += ((100 - len(ipv4_frame) - 1) * ' ') + '|'
    messages = [
        f'|        | --- IPv4 ---',
        f'|        |        Source address: {ippacket.src_ip}',
        f'|        |        Destination address: {ippacket.dest_ip}',
        f'|        |        Total Length: {ippacket.datagram_length}',
        f'|        |        Identification: {hex(ippacket.identifier)} ({ippacket.identifier})',
        f'|        |        Flags: {hex(ippacket.flags)}',
        f'|        |        ... Reserved bit: Not set',
        f'|        |        ... Don\'t Fragment: {"Set" if ippacket.flags & 0b10 else "Not set"}',
        f'|        |        ... More Fragments: {"Set" if ippacket.flags & 0b1 else "Not set"}',
        f'|        |        Fragment Offset: {hex(ippacket.fragment_offset)}',
        f'|        |        Time to Live: {ippacket.ttl}',
        f'|        |        Header Checksum: {hex(ippacket.header_checksum)}',
        f'|        |        Protocol: {ipv4.IPv4Packet.UpperLayerProtocol(ippacket.upper_layer_protocol).name} ({ippacket.upper_layer_protocol.value})',
        f'|        | --- End IPv4 ---'
    ]

    print(ipv4_frame)
    for message in messages:
        act_out_msg = message + (IP_BORDER_LEN - len(message) + 8) * ' ' + '|'
        length = len(act_out_msg)
        print(act_out_msg, (100 - length - 2) * ' ' + '|')
    print(ipv4_frame)


def dump_udp_frame(frame):
    pass