from collections import defaultdict
from NetworkSniffer import *
from Filter import *
import sys
import time
import threading
# from pynput import keyboard

logo = ''' 
        ______          _            _   _      _  _           
       |  ____|        | |          | | (_)    | || |          
       | |__ __ _ _ __ | |_ __ _ ___| |_ _  ___| || |_         
       |  __/ _` | '_ \| __/ _` / __| __| |/ __|__   _|        
       | | | (_| | | | | || (_| \__ \ |_| | (__   | |             Packet Sniffer 
  _____|_|  \__,_|_| |_|\__\__,_|___/\__|_|\___|_ |_|             ==============
 |  __ \         | |      | |  / ____|     (_)/ _|/ _|            Made By FF-DS
 | |__) |_ _  ___| | _____| |_| (___  _ __  _| |_| |_ ___ _ __ 
 |  ___/ _` |/ __| |/ / _ \ __|\___ \| '_ \| |  _|  _/ _ \ '__|
 | |  | (_| | (__|   <  __/ |_ ____) | | | | | | | ||  __/ |   
 |_|   \__,_|\___|_|\_\___|\__|_____/|_| |_|_|_| |_| \___|_|   
                                                             
'''
print(logo)


def threadFunc(key):
    try:
        k = key.char
        if k == "q":
            quit()
    except:
        k = key.name 



def main():
    consoleFilter = ConsoleFilter()

    # listener = keyboard.Listener(on_press=threadFunc)
    # listener.start()

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
    time.sleep(1)
    networkSniffer = NetworkSniffer( consoleFilter.MainFilters )
    networkSniffer.capturePackets()

    # listener.join()


main()





