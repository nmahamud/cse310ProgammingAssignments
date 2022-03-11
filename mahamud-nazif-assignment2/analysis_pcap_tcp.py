from glob import glob
from operator import truediv
import socket
from sys import flags
import dpkt

flows = [] #global list for checks
newFlowCheck = False #global bool used for checking if flows neds a new variable
class FlowInterpretor: #class object used for organizing everything
    def __init__(self, ipPack, ts): #takes in an IP packet and timestamp
        self.ipSrc = socket.inet_ntop(socket.AF_INET,ipPack.src) #source IP
        self.ipDst = socket.inet_ntop(socket.AF_INET, ipPack.dst) #destination IP
        self.srcPort = ipPack.data.sport #source Port
        self.dstPort = ipPack.data.dport #destination Port
        self.flags = ipPack.data.flags #Flags such as ACK and FIN
        self.timestamp = ts #the timestamp
        self.printed = 0 #check how many times printed for sender, only used for flows
        self.recievedCount = 0 #check how many times printed for receivers 
        self.synAckCheck = False #check if first SynAck has appeared
        self.throughput = 0 #throughput required for flows
        self.firstts = 0 #tracking the first timestamp
        self.lastts = 0 #tracking the final timestamp
        self.seqackwinList = [] #list to hold sender requests
        self.recievedList = [] #list to hold receive requests
        self.firsttsFlag = False #flag for setting firsttsx
        self.RTT = 0 #used for storing RTT
        self.packetTime = 0 #get the packtime
        self.packetCount = 0 #get the amount of packets sent within RTT
        self.congestionWindow = [] #the window of Congestions\
        self.prevTS = 0
    
    def checkUniquePorts(self, port1, port2): #used to check if the ports are the same regardless of order
        check1Switch = False #switch
        if (self.srcPort == port1): #if 1 port is good
            if (self.dstPort == port2): #checks the other
                check1Switch = True        
        if (self.dstPort == port1): #else check it in flipped order
            if (self.srcPort == port2): #check the other
                check1Switch = True         
        if (check1Switch): #if switch has been flipped, that means equal port
            return True
        return False
    
    def checkUniqueIp(self, ip1, ip2):  #like checkUniquePorts but for IPs, same implementation
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
        return (FlowInterpretor.checkUniqueIp(self, other.ipSrc, other.ipDst) and FlowInterpretor.checkUniquePorts(self, other.srcPort, other.dstPort)) #return if both ports and IPs appear in the other, regardless of order
    
def main():
    file = input("Please give filename from current directory: ") #gets file name
    f = open(file, 'rb') #inserts that file into f
    pcap = dpkt.pcap.Reader(f) #use the pcap reader to allow python to read the data
    global flows
    global newFlowCheck #set the variables as global
    for ts, buf in pcap: #for each timestamp and buffer
        eth = dpkt.ethernet.Ethernet(buf) #make a ethernet object
        ip = eth.data #get an IP Packet from the ethernet packet
        tcp = ip.data #get a TCP object from IP packet
        newFlow = FlowInterpretor(ip, ts) #creates a new FlowInterpretor object for comparisions
        if len(flows) == 0: #when empty, always new flow
            print("Source Port:", tcp.sport, "Source IP:", socket.inet_ntop(socket.AF_INET,ip.src), "-> Destination Port:", tcp.dport, " Destination IP:", socket.inet_ntop(socket.AF_INET, ip.dst), "\n")
            flows.append(newFlow)
        else: #whennot empty, do the next funny comparisons 
            for eachFlow in flows: #goes through each flow in flows to see if any match
                if (newFlow.__eq__(eachFlow)): #checks if IP and Ports are the same
                    newFlowCheck = False #if so set newFlowCheck to false to make sure it's not printed
                    if ((tcp.flags & 0x12) == 0x12): #check if it's a SYN/ACK
                        eachFlow.synAckCheck = True #sets the SYN/ACK flag in the flow from 
                        eachFlow.RTT = ts - eachFlow.timestamp #get RTT for flow from SYN/ACK - SYN
                    elif ((tcp.flags & 0x10) == 0x10 and eachFlow.synAckCheck): #check if ACK and SYN?ACK flag is raised
                        eachFlow.firsttsFlag = True #this is now the first ts flag set 
                        eachFlow.synAckCheck = False #turn off synAckCheck
                        eachFlow.prevTS = ts
                    elif (eachFlow.printed < 2 and not eachFlow.synAckCheck and eachFlow.srcPort == tcp.sport and eachFlow.dstPort == tcp.dport):
                        if eachFlow.firsttsFlag: 
                            eachFlow.firstts = ts #set first ts to firstts
                            eachFlow.firsttsFlag = False #turning off flag so no more change
                        strAdd = "Source Port: " + str(tcp.sport) + " Destination Port: " + str(tcp.dport) + " Sequence Number: " + str(tcp.seq) + " Ack Number: " + str(tcp.ack) + " Recieve Window Size: " + str(tcp.win)
                        eachFlow.seqackwinList.append(strAdd) #add String for printing to sender list
                        eachFlow.printed+=1 #add counter
                        if eachFlow.packetTime < eachFlow.RTT and len(eachFlow.congestionWindow) < 3:
                            eachFlow.packetTime+=(ts-eachFlow.prevTS)
                            eachFlow.packetCount+=1
                            eachFlow.prevTS = ts
                        elif len(eachFlow.congestionWindow) < 3:
                            eachFlow.congestionWindow.append(eachFlow.packetCount)
                            eachFlow.packetTime = 0
                            eachFlow.packetCount = 0
                        if (tcp.flags & 0x1) != 0x1: #if not last, add lastts ad throughput
                            eachFlow.lastts = ts
                            eachFlow.throughput+=tcp.__len__()
                    elif (eachFlow.recievedCount < 2 and not eachFlow.synAckCheck and eachFlow.srcPort == tcp.dport and eachFlow.dstPort == tcp.sport): #same thing just flipped and for receive
                        if eachFlow.firsttsFlag:
                            eachFlow.firstts = ts
                            eachFlow.firsttsFlag = False
                        if eachFlow.packetTime < eachFlow.RTT and len(eachFlow.congestionWindow) < 3:
                            eachFlow.packetTime+=(ts-eachFlow.prevTS)
                            eachFlow.packetCount+=1
                            eachFlow.prevTS = ts
                        elif len(eachFlow.congestionWindow) < 3:
                            eachFlow.congestionWindow.append(eachFlow.packetCount)
                            eachFlow.packetTime = 0
                            eachFlow.packetCount = 0
                        strAdd = "Source Port: " + str(tcp.sport) + " Destination Port: " + str(tcp.dport) + " Sequence Number: " + str(tcp.seq) + " Ack Number: " + str(tcp.ack) + " Recieve Window Size: " + str(tcp.win)
                        eachFlow.recievedList.append(strAdd)
                        eachFlow.recievedCount+=1
                        if (tcp.flags & 0x1) != 0x1:
                            eachFlow.lastts = ts
                            eachFlow.throughput+=tcp.__len__()
                    else: #if none of these, just do this, set for last
                        if eachFlow.packetTime < eachFlow.RTT and len(eachFlow.congestionWindow) < 3:
                            eachFlow.packetTime+=(ts-eachFlow.prevTS)
                            eachFlow.packetCount+=1
                            eachFlow.prevTS = ts
                        elif len(eachFlow.congestionWindow) < 3:
                            eachFlow.congestionWindow.append(eachFlow.packetCount)
                            eachFlow.packetTime = 0
                            eachFlow.packetCount = 0
                        if (tcp.flags & 0x1) != 0x1:
                            eachFlow.lastts = ts
                            eachFlow.throughput+=tcp.__len__()
                    break
                else:
                    newFlowCheck = True #if not equal, then new flow
            if newFlowCheck:
                print("Source Port:", tcp.sport, "Source IP:", socket.inet_ntop(socket.AF_INET,ip.src), "-> Destination Port:", tcp.dport, " Destination IP:", socket.inet_ntop(socket.AF_INET, ip.dst), "\n")
                flows.append(newFlow) #add new flow to flows
    for eachFlow in flows:
        i = 0
        while i < 2:
            print("Sender:", eachFlow.seqackwinList[i]) #get the sender flow
            print("Receiver:", eachFlow.recievedList[i]) #get the receiver flow
            i+=1
        print("Source Port:", eachFlow.srcPort, "Destination Port:", eachFlow.dstPort, "Total bytes:", eachFlow.throughput, "Bytes Throughput:", eachFlow.throughput / (eachFlow.lastts - eachFlow.firstts), "Bytes per Second") #output for memory
        print("Congestion Window Size estimates:", end=" ")#, eachFlow.congestionWindow[0], eachFlow.congestionWindow[1], eachFlow.congestionWindow[2], "\n")
        for eachWin in eachFlow.congestionWindow:
            print(eachWin, end=" ")
        print("\n")
    f.close() #close the file



if __name__ == "__main__":
    main() #calls main