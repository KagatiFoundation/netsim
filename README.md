# netsim

````python
    switch = Switch(4)

    host_a = Host(mac_addr = "fa:ce:de:ad:be:ef", ip_addr = "192.168.1.4")
    host_a.connect(switch)
    switch.connect_on_port(1, host_a)

    host_b = Host(mac_addr = "aa:aa:bb:bb:cc:dd", ip_addr = "192.168.1.5")
    host_b.connect(switch)
    switch.connect_on_port(2, host_b)

    host_a.send_data("192.168.1.5", 80, ipv4.IPv4Packet.UpperLayerProtocol.UDP, b'A' * 1600)
```

Example Output:
```
+--------------------------------------------------------------------------------------------------+
| --- Ethernet frame ---                                                                           |
|        Frame length: 71 bytes (568 bits)                                                         |
|        Destination: ffff:ffff:ffff:ffff                                                          |
|        Source: fa:ce:de:ad:be:ef                                                                 |
|        Type: ARP (0x806)                                                                         |
|        +------------------------------------------------------------------------------+          |
|        | --- ARP (Request) ---                                                        |          |
|        |        Hardware type: Ethernet (1)                                           |          |
|        |        Protocol type: IPv4 (0x0800)                                          |          |
|        |        Hardware size: 6                                                      |          |
|        |        Protocol size: 4                                                      |          |
|        |        Sender MAC address: fa:ce:de:ad:be:ef                                 |          |
|        |        Sender IP address: 192.168.1.4                                        |          |
|        |        Target MAC address: 00:00:00:00:00:00                                 |          |
|        |        Target IP address: 192.168.1.5                                        |          |
|        |        Who has 192.168.1.5? Tell 192.168.1.4                                 |          |
|        | --- End ARP ---                                                              |          |
|        +------------------------------------------------------------------------------+          |
| --- End Ethernet frame ---                                                                       |
+--------------------------------------------------------------------------------------------------+

+--------------------------------------------------------------------------------------------------+
| --- Ethernet frame ---                                                                           |
|        Frame length: 71 bytes (568 bits)                                                         |
|        Destination: fa:ce:de:ad:be:ef                                                            |
|        Source: aa:aa:bb:bb:cc:dd                                                                 |
|        Type: ARP (0x806)                                                                         |
|        +------------------------------------------------------------------------------+          |
|        | --- ARP (Reply) ---                                                          |          |
|        |        Hardware type: Ethernet (1)                                           |          |
|        |        Protocol type: IPv4 (0x0800)                                          |          |
|        |        Hardware size: 6                                                      |          |
|        |        Protocol size: 4                                                      |          |
|        |        Sender MAC address: aa:aa:bb:bb:cc:dd                                 |          |
|        |        Sender IP address: 192.168.1.5                                        |          |
|        |        Target MAC address: fa:ce:de:ad:be:ef                                 |          |
|        |        Target IP address: 192.168.1.4                                        |          |
|        |        Who has 192.168.1.4? Tell 192.168.1.5                                 |          |
|        | --- End ARP ---                                                              |          |
|        +------------------------------------------------------------------------------+          |
| --- End Ethernet frame ---                                                                       |
+--------------------------------------------------------------------------------------------------+

+--------------------------------------------------------------------------------------------------+
| --- Ethernet frame ---                                                                           |
|        Frame length: 1546 bytes (12368 bits)                                                     |
|        Destination: aa:aa:bb:bb:cc:dd                                                            |
|        Source: fa:ce:de:ad:be:ef                                                                 |
|        Type: IPv4 (0x800)                                                                        |
|        +------------------------------------------------------------------------------+          |
|        | --- IPv4 ---                                                                 |          |
|        |        Source address: 192.168.1.4                                           |          |
|        |        Destination address: 192.168.1.5                                      |          |
|        |        Total Length: 1520                                                    |          |
|        |        Identification: 0x5145e4d8 (1363535064)                               |          |
|        |        Flags: 0x1                                                            |          |
|        |        ... Reserved bit: Not set                                             |          |
|        |        ... Don't Fragment: Not set                                           |          |
|        |        ... More Fragments: Set                                               |          |
|        |        Fragment Offset: 0x0                                                  |          |
|        |        Time to Live: 128                                                     |          |
|        |        Header Checksum: 0x457                                                |          |
|        |        Protocol: UDP (17)                                                    |          |
|        | --- End IPv4 ---                                                             |          |
|        +------------------------------------------------------------------------------+          |
| --- End Ethernet frame ---                                                                       |
+--------------------------------------------------------------------------------------------------+

+--------------------------------------------------------------------------------------------------+
| --- Ethernet frame ---                                                                           |
|        Frame length: 264 bytes (2112 bits)                                                       |
|        Destination: aa:aa:bb:bb:cc:dd                                                            |
|        Source: fa:ce:de:ad:be:ef                                                                 |
|        Type: IPv4 (0x800)                                                                        |
|        +------------------------------------------------------------------------------+          |
|        | --- IPv4 ---                                                                 |          |
|        |        Source address: 192.168.1.4                                           |          |
|        |        Destination address: 192.168.1.5                                      |          |
|        |        Total Length: 238                                                     |          |
|        |        Identification: 0x5145e4d8 (1363535064)                               |          |
|        |        Flags: 0x0                                                            |          |
|        |        ... Reserved bit: Not set                                             |          |
|        |        ... Don't Fragment: Not set                                           |          |
|        |        ... More Fragments: Not set                                           |          |
|        |        Fragment Offset: 0x0                                                  |          |
|        |        Time to Live: 128                                                     |          |
|        |        Header Checksum: 0x457                                                |          |
|        |        Protocol: UDP (17)                                                    |          |
|        | --- End IPv4 ---                                                             |          |
|        +------------------------------------------------------------------------------+          |
| --- End Ethernet frame ---                                                                       |
+--------------------------------------------------------------------------------------------------+
```