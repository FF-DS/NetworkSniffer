from collections import defaultdict
from NetworkSniffer import *
from Filter import *
import sys
import time

logo = ''' 
                            +-----------------------------+
                            |                             |
                            |    |||||||| ******* ***     |
                            |    ||       ******  ***     |
                            |    ||       *****   ***     |
                            |    |||||||  ****    ***     |  Packet Sniffer 
                            |    ||       ***   *****     |  ==============
                            |    ||       **    *****     |  Made By FF-DS
                            |    ||       ******  ***     |
                            |    ||       ******  ***     |
                            |    ||       ***********     |
                            |                             |
                            *******************************
'''
print(logo)



def main():
    consoleFilter = ConsoleFilter()

    for i in range(1, len(sys.argv)):
        if sys.argv[i] == 'ip':
            consoleFilter.IPFilter()
        elif sys.argv[i] == 'eth':
            consoleFilter.EthFilter()
        elif sys.argv[i] == 'udp':
            consoleFilter.UDPFilter()
        elif sys.argv[i] == 'icmp':
            consoleFilter.ICMPFilter()
        elif sys.argv[i] == 'tcp':
            consoleFilter.TCPFilter()

    print("[Network Sniffer]:+ Started...")
    time.sleep(2)
    networkSniffer = NetworkSniffer( consoleFilter.MainFilters )
    networkSniffer.capturePackets()


main()





