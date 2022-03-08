import socket
import dpkt

flows = []

class FlowInterpretor:
    def __init__(self, ipPack, ts):
        self.ipSrc = socket.inet_ntop(socket.AF_INET,ipPack.src)
        self.ipDst = socket.inet_ntop(socket.AF_INET, ipPack.dst)
        self.srcPort = ipPack.data.sport
        self.dstPort = ipPack.data.dport
        self.flags = ipPack.data.flags
        self.timestamp = ts
def main():
    f = open("assignment2.pcap", 'rb')
    pcap = dpkt.pcap.Reader(f)
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        print("Source Port:", tcp.sport, "Source IP:", socket.inet_ntop(socket.AF_INET,ip.src), "-> Destination Port:", tcp.dport, " Destination IP:", socket.inet_ntop(socket.AF_INET, ip.dst), tcp.flags)

if __name__ == "__main__":
    main()