from glob import glob
from operator import truediv
import socket
from sys import flags
import dpkt

flows = []
newFlowCheck = False
class FlowInterpretor:
    def __init__(self, ipPack, ts):
        self.ipSrc = socket.inet_ntop(socket.AF_INET,ipPack.src)
        self.ipDst = socket.inet_ntop(socket.AF_INET, ipPack.dst)
        self.srcPort = ipPack.data.sport
        self.dstPort = ipPack.data.dport
        self.flags = ipPack.data.flags
        self.timestamp = ts
        self.printed = 0
        self.recievedCount = 0
        self.synAckCheck = False
        self.throughput = 0
        self.firstts = 0
        self.lastts = 0
        self.seqackwinList = []
        self.recievedList = []
    
    def checkUniquePorts(self, port1, port2):
        check1Switch = False
        #for flow in flows:
        if (self.srcPort == port1):
            if (self.dstPort == port2):
                check1Switch = True        
        if (self.dstPort == port1):
            if (self.srcPort == port2):
                check1Switch = True
                    
        if (check1Switch):
            return True
        return False
    
    def checkUniqueIp(self, ip1, ip2):
        check1Switch = False
        if (self.ipSrc == ip1):
            if (self.ipDst == ip2):
                check1Switch = True
        if (self.ipDst == ip1):
            if (self.ipSrc == ip2):
                check1Switch = True
                
        if (check1Switch):
            return True
        return False

    def __eq__(self, other):
        return (FlowInterpretor.checkUniqueIp(self, other.ipSrc, other.ipDst) and FlowInterpretor.checkUniquePorts(self, other.srcPort, other.dstPort)) 
    

def appendToFlows(flow):
    if len(flows) == 1:
        flows.append(flow)
        return True
    else:
        for eachFlow in flows:
            if not flow.eq(eachFlow):
                flows.append(flow)
                return True
    return False
def main():
    f = open("assignment2.pcap", 'rb')
    pcap = dpkt.pcap.Reader(f)
    global flows
    global newFlowCheck
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        newFlow = FlowInterpretor(ip, ts)
        if len(flows) == 0:
            print("Source Port:", tcp.sport, "Source IP:", socket.inet_ntop(socket.AF_INET,ip.src), "-> Destination Port:", tcp.dport, " Destination IP:", socket.inet_ntop(socket.AF_INET, ip.dst), "\n")
            flows.append(newFlow)
        else:
            for eachFlow in flows:
                if (newFlow.__eq__(eachFlow)):
                    newFlowCheck = False
                    if ((tcp.flags & 0x12) == 0x12):
                        eachFlow.synAckCheck = True
                    elif ((tcp.flags & 0x10) == 0x10 and eachFlow.synAckCheck):
                        eachFlow.firstts = ts
                        eachFlow.synAckCheck = False
                    elif (eachFlow.printed < 2 and not eachFlow.synAckCheck and eachFlow.srcPort == tcp.sport and eachFlow.dstPort == tcp.dport):
                        eachFlow.lastts = ts
                        strAdd = "Source Port: " + str(tcp.sport) + " Destination Port: " + str(tcp.dport) + " Sequence Number: " + str(tcp.seq) + " Ack Number: " + str(tcp.ack) + " Recieve Window Size: " + str(tcp.win)
                        eachFlow.seqackwinList.append(strAdd)
                        eachFlow.printed+=1
                        eachFlow.throughput+=tcp.__len__()
                    elif (eachFlow.recievedCount < 2 and not eachFlow.synAckCheck and eachFlow.srcPort == tcp.dport and eachFlow.dstPort == tcp.sport):
                        strAdd = "Source Port: " + str(tcp.sport) + " Destination Port: " + str(tcp.dport) + " Sequence Number: " + str(tcp.seq) + " Ack Number: " + str(tcp.ack) + " Recieve Window Size: " + str(tcp.win)
                        eachFlow.recievedList.append(strAdd)
                        eachFlow.recievedCount+=1
                        if (tcp.flags & 0x1) != 0x1:
                            eachFlow.lastts = ts
                            eachFlow.throughput+=tcp.__len__()
                    else:
                        if (tcp.flags & 0x1) != 0x1:
                            eachFlow.lastts = ts
                            eachFlow.throughput+=tcp.__len__()
                    break
                else:
                    newFlowCheck = True
            if newFlowCheck:
                print("Source Port:", tcp.sport, "Source IP:", socket.inet_ntop(socket.AF_INET,ip.src), "-> Destination Port:", tcp.dport, " Destination IP:", socket.inet_ntop(socket.AF_INET, ip.dst), "\n")
                flows.append(newFlow)
    for eachFlow in flows:
        i = 0
        while i < 2:
            print("Sender:", eachFlow.seqackwinList[i])
            print("Receiver:", eachFlow.recievedList[i])
            i+=1
        print("Source Port:", eachFlow.srcPort, "Destination Port:", eachFlow.dstPort, "Total bytes:", eachFlow.throughput, "Bytes Throughput:", eachFlow.throughput / (eachFlow.lastts - eachFlow.firstts), "Bytes per Second\n")
    f.close()



if __name__ == "__main__":
    main()