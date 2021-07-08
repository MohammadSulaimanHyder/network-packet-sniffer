#!/usr/bin/python3

import textwrap

class Helper:

    #function is responsible for taking bytes and converting them to human readable MAC address.
    def format_mac_addr(bytes_addr):
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()
    
    def format_IPV4_addr(bytes_addr):
        return '.'.join(map(str, bytes_addr))

    def format_multiline_data(prefix, string, size=80):
        size -= len(prefix)
        if isinstance(string, bytes):
            string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
            if size % 2:
                size -= 1
        return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
