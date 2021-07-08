#!/usr/bin/python3

class HTTP:
    
    def __init__(self, raw_data):
        try:
            self.data = raw_data.decode('UTF8')
        except:
            self.data = raw_data

