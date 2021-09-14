import struct
from textwrap import TextWrapper
import base64
import zlib
import gzip

try:
    from http_parser.parser import HttpParser
except ImportError:
    from http_parser.pyparser import HttpParser

class TCPSegment:
    def __init__(self, data, httpData, netSniffer):
        self.httpData = httpData
        self.__data = data
        self.source_port = 0
        self.destination_port = 0 
        self.seq = 0
        self.ack = None
        self.offest = 0
        self.flags = {}
        self.data = None
        self.type = 'TCP_SEGMENT'
        self.netSniffer = netSniffer

        self.__extract()

    def __extract(self):
        self.source_port, self.destination_port, self.seq, self.ack, offest_reserved_flags = struct.unpack('! H H L L H', self.__data[:14])
        self.offest = ( offest_reserved_flags >> 12 ) * 4
        self.flags = {
            "urg" : ( offest_reserved_flags & 32 ) * 5,
            "ack" : ( offest_reserved_flags & 16 ) * 4,
            "psh" : ( offest_reserved_flags & 8 ) * 3,
            "rst" : ( offest_reserved_flags & 4 ) * 2,
            "syn" : ( offest_reserved_flags & 2 ) * 1,
            "fin" : ( offest_reserved_flags & 1 ),
        }
        self.data = self.__data[self.offest:]


    def __str__(self):
        text_wrap = TextWrapper(width=43, subsequent_indent='\t ')
        
        result = "\t+-------------------------------------------+\n"
        result += "\t|                 TCP Packet                |\n"
        result += "\t+-------------------------------------------+\n"
        result += "\t| Source PORT: {src:6d}   Target PORT: {dest:6d} |\n".format(src = self.source_port, dest = self.destination_port)
        result += "\t| Seq: {seq:12d}        ACK: {ack:12d}|\n".format(seq = self.seq, ack = self.ack)
        result += "\t+-------------------------------------------+\n"
        result += "\t| URG : {urg:2d}     | ACK : {ack:2d}    | PSH : {psh:2d}     |\n".format(urg = self.flags['urg'], ack = self.flags['ack'], psh = self.flags['psh'])
        result += "\t| RST : {rst:2d}     | SYN : {syn:2d}    | FIN : {fin:2d}     |\n".format(rst = self.flags['rst'], syn = self.flags['syn'], fin = self.flags['fin'])
        result += "\t+-------------------------------------------+\n"
        result += "\t                   PAYLOAD               \n"

        if self.source_port == 80 or self.destination_port == 80:
            result = "\t+-------------------------------------------+\n"
            result += "\t|                HTTP DATA                  |\n"
            result += "\t+-------------------------------------------+\n"

            try:
                result += "\t" +  text_wrap.fill(text = self.data.decode('utf-8') ) + "\n"
            except:
                self.netSniffer.getParser().execute(self.data, len(self.data))
                if self.netSniffer.getParser().is_headers_complete():
                    result += "\t" +  text_wrap.fill(text = str( self.netSniffer.getParser().get_headers() ) )+ "\n"
                    
                if self.netSniffer.getParser().is_partial_body():
                    self.httpData.append( self.netSniffer.getParser().recv_body() )

                if self.netSniffer.getParser().is_message_complete():
                    try:
                        decodedText = gzip.decompress( b''.join(self.httpData) )
                        result += "\t" + text_wrap.fill(text =  str( decodedText, 'utf-8' ) ) + "\n"
                        self.httpData.clear()
                    except:
                        pass
        else:
            result += "\t " + text_wrap.fill(text = str(self.data)) + "\n"
        
        result += "\t+-------------------------------------------+\n"
        return result

    def parseHTTP(self, data):
        data = self.data.decode('utf-8')


class UDPSegment:
    def __init__(self, data):
        self.__data = data
        self.source_port = 0
        self.destination_port = 0 
        self.size = 0
        self.type = 'UDP_SEGMENT'
        self.data = None

        self.__extract()

    def __extract(self):
        self.source_port, self.destination_port, self.size = struct.unpack('! H H 2x H', self.__data[:8])
        self.data = self.__data[8:]

    
    def __str__(self):
        text_wrap = TextWrapper(width=43, subsequent_indent='\t ')
        result = "\t+-------------------------------------------+\n"
        result += "\t|                 UDP Packet                |\n"
        result += "\t+-------------------------------------------+\n"
        result += "\t| Source PORT : {src:4d}    Target PORT : {dest:4d} |\n".format(src = self.source_port, dest = self.destination_port)
        result += "\t+-------------------------------------------+\n"
        result += "\t| URG : {urg:35d} |\n".format(urg = self.size)
        result += "\t+-------------------------------------------+\n"
        result += "\t                   PAYLOAD               \n"
        result += "\t " + text_wrap.fill(text = str(self.data)) + "\n"
        result += "\t+-------------------------------------------+\n"
        return result


class ICMPPacket:
    def __init__(self, data):
        self.__data = data
        self.icmp_type = ''
        self.code = ''
        self.checksum = ''
        self.type = 'ICMP_PACKET'
        self.data = None

        self.__extract()

    def __extract(self):
        self.icmp_type, self.code, self.checksum = struct.unpack('! B B H', self.__data[:4])
        self.data = self.__data[4:]
    
    def __str__(self):
        text_wrap = TextWrapper(width=43, subsequent_indent='\t ')

        result = "\t+-------------------------------------------+\n"
        result += "\t|               ICMP Packet                 |\n"
        result += "\t+-------------------------------------------+\n"
        result += "\t| ICMP TYPE :                            {icmp_type:2d} |\n".format(icmp_type = self.icmp_type)
        result += "\t| Code :                                 {code:2d} |\n".format(code = self.code)
        result += "\t| Checksum :                         {checksum:6d} |\n".format(checksum = self.checksum)
        result += "\t+-------------------------------------------+\n"
        result += "\t                   PAYLOAD               \n"
        result += "\t " + text_wrap.fill(text = str(self.data)) + "\n"
        result += "\t+-------------------------------------------+\n"
        return result