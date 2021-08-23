import struct

class IPPacket:
    def __init__(self, data):
        self.__data = data
        self.version = ''
        self.header_length = ''
        self.ttl = ''
        self.source = ''
        self.target = ''
        self.protocol = ''
        self.type = 'IP_PACKET'
        self.data = None
        self.Segment = None

        self.__extract()

    def __extract(self):
        self.version = self.__data[0] >> 4
        self.header_length = (self.__data[0] & 15) * 4
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', self.__data[:20])
        self.ttl = ttl 
        self.source = self.__get_ip_addr( src )
        self.target = self.__get_ip_addr( target )
        self.protocol = proto
        self.data = self.__data[self.header_length:]


    def __get_ip_addr(self, ip_addr):
        return '.'.join(map(str, ip_addr))

    
    def __str__(self):
        result = "\t+-------------------------------------------+\n"
        result += "\t|                 IP Packet                 |\n"
        result += "\t+-------------------------------------------+\n"
        result += "\t| Source IP :              {addr:>16} |\n".format(addr = self.source)
        result += "\t| Target IP :              {addr:>16} |\n".format(addr = self.target)
        result += "\t| Packet Protocol : {proto:23d} |\n".format(proto = self.protocol)
        result += "\t+-------------------------------------------+\n"
        result += "\t| Version : {version:2d}                   TTL :  {ttl:3d} |\n".format(version = self.version, ttl = self.ttl)
        result += "\t+-------------------------------------------+\n"
        return result




