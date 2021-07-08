#!/usr/bin/python3

import socket
import struct
import textwrap
from helper import Helper
from networkProtocols.ethernet import Ethernet
from networkProtocols.ipv4 import IPv4
from networkProtocols.icmp import ICMP
from networkProtocols.tcp import TCP
from networkProtocols.udp import UDP
from networkProtocols.http import HTTP
from networkProtocols.pcap import Pcap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

def main():

    pcap = Pcap('capture.pcap')
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(35536)
        pcap.write(raw_data)
        ethernet_frame = Ethernet(raw_data)
        print('\nEthernet Frame:')
        print(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(ethernet_frame.dest_mac, ethernet_frame.source_mac, ethernet_frame.protocol))

        # protocol for IPV4 in ethernet frame is 8.
        if ethernet_frame.protocol == 8:
            ipv4_packet = IPv4(ethernet_frame.data)
            print(TAB_1 + 'IPV4 Packet:')
            print(TAB_2 + 'Version: {}, header_length: {}, TTL: {}'.format(ipv4_packet.version, ipv4_packet.header_length, ipv4_packet.time_to_live))
            print(TAB_2 + 'Protocol: {}, Source IP: {}, Destination IP: {}'.format(ipv4_packet.protocol, ipv4_packet.src_ip, ipv4_packet.target_ip))

            #ICMP
            if ipv4_packet.protocol == 1:
                icmp_segment = ICMP(ipv4_packet.data)
                print(TAB_1 + 'ICMP Segment:')
                print(TAB_2 + 'Type: {}, Code: {}, Check Sum: {}'.format(icmp_segment.type, icmp_segment.code, icmp_segment.checksum))
                print(TAB_2 + 'DATA:')
                print(Helper.format_multiline_data(DATA_TAB_3, icmp_segment.data))
            #TCP
            elif ipv4_packet.protocol == 6:
                tcp_segment = TCP(ipv4_packet.data)
                print(TAB_1 + 'TCP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(tcp_segment.src_port, tcp_segment.dest_port))
                print(TAB_2 + 'Sequence: {}, Acknowledgement: {}'.format(tcp_segment.sequence, tcp_segment.acknowledgement))
                print(TAB_2 + 'Flags:')
                print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp_segment.flag_urg, tcp_segment.flag_ack, tcp_segment.flag_psh))
                print(TAB_3 + 'RST: {}, SYN: {}, FIN: {}'.format(tcp_segment.flag_rst, tcp_segment.flag_syn, tcp_segment.flag_fin))
                
                if len(tcp_segment.data) > 0:
                    #HTTP
                    if tcp_segment.src_port == 80 or tcp_segment.dest_port == 80:
                        print(TAB_2 + 'HTTP DATA:')
                        try:
                            http = HTTP(tcp_segment.data)
                            http_info = str(http.data).split('\n')
                            for line in http_info:
                                print(DATA_TAB_3 + str(line))
                        except:
                            print(Helper.format_multiline_data(DATA_TAB_3, tcp_segment.data))
                    else:
                        print(TAB_2 + 'TCP Data:')
                        print(Helper.format_multiline_data(DATA_TAB_3, tcp_segment.data))
            #UDP
            elif ipv4_packet.protocol == 17:
                udp_segment = UDP(ipv4_packet.data)
                print(TAB_1 + 'UDP Segment:')
                print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp_segment.src_port, udp_segment.dest_port, udp_segment.size))
            #Other
            else:
                print(TAB_1 + 'Other Protocols:')
                print(TAB_2 + 'DATA:')
                print(Helper.format_multiline_data(DATA_TAB_2, ipv4_packet.data))
        else:
            print(TAB_2 + 'DATA:')
            print(Helper.format_multiline_data(DATA_TAB_3, ethernet_frame.data))
    pcap.close()



main()