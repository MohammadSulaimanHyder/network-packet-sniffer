#!/usr/bin/python3

import struct
from helper import Helper

class IPv4:

    def __init__(self, raw_data):
        version_header_length = raw_data[0]
        self.time_to_live, self.protocol, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
        self.version = version_header_length >> 4
        self.header_length = (version_header_length & 15) * 4
        self.src_ip = Helper.format_IPV4_addr(src)
        self.target_ip = Helper.format_IPV4_addr(target)
        self.data = raw_data[self.header_length:]
