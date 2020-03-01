import sys
from scapy.all import *

pcap_file = rdpcap('/home/atul/Downloads/wiredradiusfiltered.pcap')


def write(pkt):
    wrpcap('Filteres.pcap', pkt, append=True)


def writea(pkt):
    wrpcap('Filteresas.pcap', pkt, append=True)


def packet_capture(pcap_file):
    ab = []
    for pkt in pcap_file:
        if 'RADIUS' in pkt:
            ab.append(pkt)
        else:
            pass
    return ab


def session(filtered):
    state = ''
    for pkt in filtered:
        if pkt['RADIUS'].code == 1:
            writea(pkt)
        else:
            state = pkt['RADIUS']
            for i in pkt['RADIUS']:
                print(i,'*'*10)
            # print(dir(pkt['RADIUS']))
            wrpcap('challenge.pcap', pkt, append=True)
    return state


filtered = rdpcap('challenge.pcap')
result = session(filtered)
#print(result)
