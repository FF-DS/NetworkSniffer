from collections import defaultdict

class Filter:
    def __init__(self, filterValues):
        self.ether = filterValues['ether'] 
        self.ip = filterValues['ip'] 
        self.icmp = filterValues['icmp']  
        self.tcp = filterValues['tcp'] 
        self.udp = filterValues['udp'] 
        self.packetType = filterValues['packet_type'] 

    def packetTypes(self, packet):
        if not self.packetType:
            return True
        return not (packet.Packet == None or packet.Packet.Segment == None or self.packetType.count( packet.Packet.Segment.type ) == 0 ) 


    def ethernetFilter(self, packet):
        return ((packet.destination_addr == self.ether['dest'] or self.ether['dest'] == None) and (packet.source_addr ==  self.ether['src'] or self.ether['src'] == None) and (packet.protocol == self.ether['proto'] or self.ether['proto'] == None))
    

    def networkIPFilter(self, packet):
        return (packet.Packet == None or packet.Packet.type != 'IP_PACKET') or  ((packet.Packet.source == self.ip['src'] or self.ip['src'] == None) and (packet.Packet.target == self.ip['dest'] or self.ip['dest'] == None) and (packet.Packet.protocol == self.ip['proto'] or self.ip['proto'] == None) and (packet.Packet.version == self.ip['version'] or self.ip['version'] == None))


    def transportICMPFilter(self, packet):
        return (packet.Packet == None or packet.Packet.Segment == None or packet.Packet.Segment.type != 'ICMP_PACKET') or ((packet.Packet.Segment.icmp_type == self.icmp['icmp_type'] or self.icmp['icmp_type'] == None) and (packet.Packet.Segment.code == self.icmp['code'] or self.icmp['code'] == None))


    def transportTCPFilter(self, packet):
        return (packet.Packet == None or packet.Packet.Segment == None or packet.Packet.Segment.type != 'TCP_SEGMENT') or  ((packet.Packet.Segment.destination_port == self.tcp['dest'] or self.tcp['dest'] == None) and (packet.Packet.Segment.source_port == self.tcp['src'] or self.tcp['src'] == None) and (self.tcp['flag'] == None or packet.Packet.Segment.flags[flag]))
    

    def transportUDPFilter(self, packet):
        return (packet.Packet == None or packet.Packet.Segment == None or packet.Packet.Segment.type != 'UDP_SEGMENT') or  ((packet.Packet.Segment.destination_port == self.udp['dest'] or self.udp['dest'] == None) and (packet.Packet.Segment.source_port == self.udp['src'] or self.udp['src'] == None))


    def filterPackets(self, packet):
        return ( self.packetTypes(packet) and self.ethernetFilter(packet) and self.networkIPFilter(packet) and self.transportICMPFilter(packet) and self.transportTCPFilter(packet) and self.transportUDPFilter(packet) )





class ConsoleFilter:
    def __init__(self):
        self.MainFilters = {
            'ether': defaultdict(lambda: None),
            'ip': defaultdict(lambda: None),
            'icmp': defaultdict(lambda: None),
            'tcp': defaultdict(lambda: None),
            'udp': defaultdict(lambda: None),
            'packet_type' : []
        }

    def EthFilter(self):
        filters = self.MainFilters['ether']
        print('                      Ethernet Filter')
        print('Destination Address:', end="")
        filters['dest'] = input() or None
        print('Source Address:', end="")
        filters['src'] = input() or None
        print('Protocol:', end="")
        filters['proto'] = self.__parseInt(input()) or None

        return filters


    def IPFilter(self):
        filters = self.MainFilters['ip']
        print('                      IP Filter')
        print('Destination Address:', end="")
        filters['dest'] = input() or None
        print('Source Address:', end="")
        filters['src'] = input() or None
        print('Protocol:', end="")
        filters['proto'] = self.__parseInt(input()) or None
        print('Version:', end="")
        filters['version'] = input() or None

        return filters


    def ICMPFilter(self):
        filters = self.MainFilters['icmp']
        print('                      ICMP Filter')
        print('ICMP Type:', end="")
        filters['icmp_type'] = input() or None
        print('Code:', end="")
        filters['code'] = input() or None

        self.MainFilters['packet_type'].append('ICMP_PACKET')
        return filters


    def TCPFilter(self):
        filters = self.MainFilters['tcp']
        print('                      TCP Filter')
        print('Destination Port:', end="")
        filters['dest'] = self.__parseInt(input()) or None
        print('Source Port:', end="")
        filters['src'] = self.__parseInt(input()) or None
        print('On flag name:', end="")
        filters['flag'] = self.__parseInt(input()) or None

        self.MainFilters['packet_type'].append('TCP_SEGMENT')
        return filters


    def UDPFilter(self):
        filters = self.MainFilters['udp']
        print('                      UDP Filter')
        print('Destination Port:', end="")
        filters['dest'] = self.__parseInt(input()) or None
        print('Source Port:', end="")
        filters['src'] = self.__parseInt(input()) or None

        self.MainFilters['packet_type'].append('UDP_SEGMENT')
        return filters

    def __parseInt(self, val):
        try:
            return int(val)
        except:
            return None