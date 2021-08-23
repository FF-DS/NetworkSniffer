import socket
import struct
import textwrap

from threading import Thread
from EthernetFrame import *
from NetworkPacket import *
from TransportSegment import *
from Filter import *


class NetworkSniffer:
    def __init__(self, filterValues):
        self.filter = Filter( filterValues )

    def startCapturing(Self):
        thread = Thread(self.capturePackets, self)
        thread.start()
        thread.join()


    def capturePackets(self):
        conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

        while True:
            raw_data, addr = conn.recvfrom(65536)
            ethernet = EthernetFrame(raw_data)

            if ethernet.protocol == 8:
                ethernet.Packet = IPPacket( ethernet.data )
                if ethernet.Packet.protocol == 6:
                    ethernet.Packet.Segment = TCPSegment( ethernet.Packet.data )
                elif ethernet.Packet.protocol == 1:   
                    ethernet.Packet.Segment = ICMPPacket( ethernet.Packet.data )
                elif ethernet.Packet.protocol == 17: 
                    ethernet.Packet.Segment = UDPSegment( ethernet.Packet.data )
            
            
            display = self.filter.filterPackets( ethernet ) 
            if display:
                print(ethernet)
                if ethernet.Packet:
                    print(ethernet.Packet)
                    print(ethernet.Packet.Segment)


    
    




