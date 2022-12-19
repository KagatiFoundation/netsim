from ethernet import EthernetFrame
from protocols.arp import ARP
from protocols import ipv4
import transport_layer

def dump_ethernet_frame(frame: EthernetFrame):
    print()

    if frame.type == EthernetFrame.ARP:
        typp = f'ARP ({hex(EthernetFrame.ARP)})'
    elif frame.type == EthernetFrame.IPV4:
        typp = f'IPv4 ({hex(EthernetFrame.IPV4)})'

    ETHERNET_FRAME_BORDER_LEN = 120
    ethernet_border = '+' + f"{'':-^{(ETHERNET_FRAME_BORDER_LEN - 2)}}" + '+'
    print(ethernet_border)
    length = frame.length
    messages = [
        f'Frame length: {length} bytes ({length * 8} bits)',
        f'Destination: {frame.dest_mac}',
        f'Source: {frame.src_mac}',
        f'Type: {typp}'
    ]

    frame_start_border_title = '| --- Ethernet frame ---'
    border_msg_len = ETHERNET_FRAME_BORDER_LEN - len(frame_start_border_title)
    print(frame_start_border_title + f"{'|':>{border_msg_len}}")
    for message in messages:
        msg = f'|        {message}'
        msg += f'{"|":>{(ETHERNET_FRAME_BORDER_LEN - len(msg))}}'
        print(msg)

    if frame.type == EthernetFrame.ARP:
        dump_arp_frame(frame.data)
    elif frame.type == EthernetFrame.IPV4:
        dump_ipv4_frame(frame.data)

    frame_end_border_title = '| --- End Ethernet frame ---'
    border_msg_len = ETHERNET_FRAME_BORDER_LEN - len(frame_end_border_title)
    print(frame_end_border_title + f"{'|':>{border_msg_len}}")
    print(ethernet_border)


def dump_arp_frame(arp):
    header = "Request"
    target_mac = arp.target_hardware_addr if arp.target_hardware_addr else '00:00:00:00:00:00'
    data_msg = f'Who has {arp.target_protocol_addr}? Tell {arp.sender_protocol_addr}',
    if arp.type == ARP.REPLY:
        header = "Reply"
        data_msg = f"{arp.sender_protocol_addr} is at {arp.sender_hardware_addr}"

    PARENT_FRAME_LEN = 120
    ARP_FRAME_BORDER_LEN = 100
    arp_frame = '|        +' + f"{'-':-^{(ARP_FRAME_BORDER_LEN - 2)}}" + '+'
    arp_frame += f"{'|':>{PARENT_FRAME_LEN - len(arp_frame)}}"
    messages = [
        f'| --- ARP ({header}) ---',
        f'|        Hardware type: Ethernet (1)',
        f'|        Protocol type: IPv4 (0x0800)',
        f'|        Hardware size: 6',
        f'|        Protocol size: 4',
        f'|        Sender MAC address: {arp.sender_hardware_addr}',
        f'|        Sender IP address: {arp.sender_protocol_addr}',
        f'|        Target MAC address: {target_mac}',
        f'|        Target IP address: {arp.target_protocol_addr}',
        f'|        DATA: {data_msg}',
        f'| --- End ARP ---',
    ]

    print(arp_frame)
    for message in messages:
        msg = f'|        {message}'
        msg += f'{"|":>{(ARP_FRAME_BORDER_LEN - len(msg) + 9)}}'
        msg += f'{"|":>{(PARENT_FRAME_LEN - len(msg))}}'
        print(msg)
    print(arp_frame)
    

def dump_ipv4_frame(ippacket: ipv4.IPv4Packet):
    PARENT_FRAME_LEN = 120
    IP_BORDER_LEN = 100
    ipv4_frame = '|        +' + f"{'-':-^{IP_BORDER_LEN - 2}}" + '+'
    ipv4_frame += f"{'|':>{PARENT_FRAME_LEN - len(ipv4_frame)}}"
    messages = [
        f'|        Source address: {ippacket.src_ip}',
        f'|        Destination address: {ippacket.dest_ip}',
        f'|        Total Length: {ippacket.datagram_length}',
        f'|        Identification: {hex(ippacket.identifier)} ({ippacket.identifier})',
        f'|        Flags: {hex(ippacket.flags)}',
        f'|        ... Reserved bit: Not set',
        f'|        ... Don\'t Fragment: {"Set" if ippacket.flags & 0b10 else "Not set"}',
        f'|        ... More Fragments: {"Set" if ippacket.flags & 0b1 else "Not set"}',
        f'|        Fragment Offset: {hex(ippacket.fragment_offset)}',
        f'|        Time to Live: {ippacket.ttl}',
        f'|        Header Checksum: {hex(ippacket.header_checksum)}',
        f'|        Protocol: {ipv4.IPv4Packet.UpperLayerProtocol(ippacket.upper_layer_protocol).name} ({ippacket.upper_layer_protocol.value})',
    ]

    print(ipv4_frame)
    frame_start_border_title = "|        | --- IPv4 ---"
    border_msg_len = IP_BORDER_LEN - len(frame_start_border_title)
    frame_start_border_title += f"{'|':>{border_msg_len + 9}}"
    border_msg_len = PARENT_FRAME_LEN - len(frame_start_border_title)
    frame_start_border_title += f"{'|':>{border_msg_len}}"
    print(frame_start_border_title)

    for message in messages:
        msg = f'|        {message}'
        msg += f'{"|":>{(IP_BORDER_LEN - len(msg) + 9)}}'
        msg += f'{"|":>{(PARENT_FRAME_LEN - len(msg))}}'
        print(msg)

    if ippacket.upper_layer_protocol == ipv4.IPv4Packet.UpperLayerProtocol.TCP:
        dump_tcp_frame(ippacket.data)

    frame_end_border_title = "|        | --- End IPv4 ---"
    border_msg_len = IP_BORDER_LEN - len(frame_end_border_title)
    frame_end_border_title += f"{'|':>{border_msg_len + 9}}"
    border_msg_len = PARENT_FRAME_LEN - len(frame_end_border_title)
    frame_end_border_title += f"{'|':>{border_msg_len}}"
    print(frame_end_border_title)
    print(ipv4_frame)


def dump_tcp_frame(frame: transport_layer.TCPPacket):
    PARENT_FRAME_LEN = 100
    SUPER_PARENT_FRAME_LEN = 120
    TCP_BORDER_LEN = 80
    tcp_frame = '|        |        +' + f"{'-':-^{TCP_BORDER_LEN - 2}}" + '+'
    tcp_frame += f"{'|':>{PARENT_FRAME_LEN - len(tcp_frame) + 9}}"
    tcp_frame += f"{'|':>{SUPER_PARENT_FRAME_LEN - len(tcp_frame)}}"

    flags_set = []
    flags = frame.flags
    if flags & 0b10 == 0b10: flags_set.append("(SYN)")
    if (flags >> 4) & 0b1 == 0b1: flags_set.append("(ACK)")
    if flags & 0b1 == 0b1: flags_set.append("(FIN)")

    messages = [
        f'|        | --- TCP ---',
        f'|        |        Source Port: {frame.src_port}',
        f'|        |        Destination Port: {frame.dest_port}',
        f'|        |        Sequence Number: {frame.seq_num}',
        f'|        |        Acknowledgement Number: {frame.ack_num}',
        f'|        |        Flags: {hex(frame.flags)} {", ".join(flags_set)}',
        f'|        |        Window: {frame.window}',
        f'|        |        Checksum: {frame.checksum}',
        f'|        |        Urgent Pointer: {frame.urgent_pointer}',
        f'|        | --- End TCP ---'
    ]

    print(tcp_frame)
    for message in messages:
        msg = f'|        {message}'
        msg += f'{"|":>{TCP_BORDER_LEN - len(msg) + 18}}'
        msg += f'{"|":>{PARENT_FRAME_LEN - len(msg) + 9}}'
        msg += f'{"|":>{SUPER_PARENT_FRAME_LEN - len(msg)}}'
        print(msg)
    print(tcp_frame)