#!/usr/bin/python3

import socket
import struct
from helper import Helper

class Ethernet:

    def __init__(self, raw_data):
        dest, source, proto = struct.unpack('! 6s 6s H', raw_data[:14])

        self.dest_mac = Helper.format_mac_addr(dest)
        self.source_mac = Helper.format_mac_addr(source)
        self.protocol = socket.htons(proto)
        self.data = raw_data[14:]

        


    
