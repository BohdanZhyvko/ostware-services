#!/usr/bin/python

import netinfo
from scapy.all import *


## Create a Packet Count var
packetCount = 0
## Define our Custom Action function
def customAction(packet):
    global packetCount
    packetCount += 1
    return "Packet #%s: %s ==> %s" % (packetCount, packet[0][1].src, packet[0][1].dst)

def sniffer(toListen):
    #netinfo get default destination(0.0.0.0) interface
    default_gateway = [route for route in netinfo.get_routes() if route['dest'] == '0.0.0.0'][0]
    print "default destination(0.0.0.0) interface: " + default_gateway['dev']
    
    sniff(iface=default_gateway['dev'], filter=toListen, prn=customAction, timeout=30)

    print "Find pacets: "
    print packetCount
    return packetCount
