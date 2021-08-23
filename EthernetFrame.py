import struct
import socket

class EthernetFrame:
    def __init__(self, data):
        self.__data = data
        self.destination_addr = ''
        self.source_addr = ''
        self.protocol = 0
        self.data = data[14:]
        self.Packet = None

        self.__extract()

    def __extract(self):
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', self.__data[:14])

        self.destination_addr = self.__get_mac_addr( dest_mac )
        self.source_addr = self.__get_mac_addr( src_mac )
        self.protocol = socket.htons(proto)

    def __get_mac_addr(self, byte_addr):
        byte_addr =  map('{:02x}'.format, byte_addr)
        return ':'.join(byte_addr).upper()

    
    def __str__(self):
        result = "----------------------------[PACKET]------------------------\n"
        result += "\t+-------------------------------------------+\n"
        result += "\t|              Ethernet Frame               |\n"
        result += "\t+-------------------------------------------+\n"
        result += "\t| Source Packet :         {addr} |\n".format(addr = self.source_addr)
        result += "\t| Destination Packet :    {addr} |\n".format(addr = self.destination_addr)
        result += "\t| Protocol Packet : {proto:23d} |\n".format(proto = self.protocol)
        result += "\t+-------------------------------------------+\n"
        return result
