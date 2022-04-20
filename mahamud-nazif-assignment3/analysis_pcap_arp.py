import dpkt.pcap

def isARP(packet):
    type = packet[12:14].hex()
    if type == "0806":
        return True
    return False

def isARPRequest(packet):
    opcode = packet[20:22].hex()
    addy = packet[0:6].hex()
    if addy == "ffffffffffff":
        return False
    return opcode == "0001"

def isARPReply(packet):
    opcode = packet[20:22].hex()
    return opcode == "0002"

def isReplyOfRequest(request, reply):
    reqSendIP = request[28:32].hex() #request's sender IP
    reqTarIP = request[38:42].hex() #request's target IP
    repSendIP = reply[28:32].hex() #reply's sender IP
    repTarIP = reply[38:42].hex() #reply's target IP
    return reqSendIP == repTarIP and reqTarIP == repSendIP #checks if the IPs are the same

if __name__ == '__main__':
    file = input("Please give filename from current directory: ") #gets file name
    f = open(file, 'rb') #inserts that file into f
    pcap = dpkt.pcap.Reader(f) #use the pcap reader to allow python to read the data
    ARPPackets = [] #make a list to store the packets
    for ts, buf in pcap: #for each timestamp and buffer
        if (isARP(buf)): #check if ARP
            if len(ARPPackets) == 0:
                if isARPRequest(buf): #if it's a request add it. Request first because you don'tknow if a reply was asked for before
                    ARPPackets.append(buf) 
            else:
                if len(ARPPackets) == 1:
                    if isARPReply(buf): #do if it's a reply
                        if isReplyOfRequest(ARPPackets[0],buf): #make sure it's a reply for the request
                            ARPPackets.append(buf)
                            break;
    req = ARPPackets[0]
    reply = ARPPackets[1]
    # This very long section is just for printing
    print("ARP Request:")
    print("\tHardware Type: {}".format(req[14:16].hex()))
    print("\tProtocol Type: {}".format(req[16:18].hex()))
    print("\tHardware Size: {}".format(req[18:19].hex()))
    print("\tProtocol Size: {}".format(req[19:20].hex()))
    print("\tOpcode: request {}".format(req[20:22].hex()))
    print("\tSender MAC address: {}:{}:{}:{}:{}:{}".format(req[22:23].hex(),req[23:24].hex(),req[24:25].hex(),req[25:26].hex(),req[26:27].hex(),req[27:28].hex()))
    ip1 = req[28:29].hex()
    ip2 = req[29:30].hex()
    ip3 = req[30:31].hex()
    ip4 = req[31:32].hex()
    print("\tSender IP address: {}.{}.{}.{}".format(int(ip1,16),int(ip2,16),int(ip3,16),int(ip4,16)))
    print("\tTarget MAC address: {}:{}:{}:{}:{}:{}".format(req[32:33].hex(),req[33:34].hex(),req[34:35].hex(),req[35:36].hex(),req[36:37].hex(),req[37:38].hex()))
    ip1 = req[38:39].hex()
    ip2 = req[39:40].hex()
    ip3 = req[40:41].hex()
    ip4 = req[41:42].hex()
    print("\tTarget IP address: {}.{}.{}.{}".format(int(ip1,16),int(ip2,16),int(ip3,16),int(ip4,16)))
    print("ARP Reply:")
    print("\tHardware Type: {}".format(reply[14:16].hex()))
    print("\tProtocol Type: {}".format(reply[16:18].hex()))
    print("\tHardware Size: {}".format(reply[18:19].hex()))
    print("\tProtocol Size: {}".format(reply[19:20].hex()))
    print("\tOpcode: reply {}".format(reply[20:22].hex()))
    print("\tSender MAC address: {}:{}:{}:{}:{}:{}".format(reply[22:23].hex(),reply[23:24].hex(),reply[24:25].hex(),reply[25:26].hex(),reply[26:27].hex(),reply[27:28].hex()))
    ip1 = reply[28:29].hex()
    ip2 = reply[29:30].hex()
    ip3 = reply[30:31].hex()
    ip4 = reply[31:32].hex()
    print("\tSender IP address: {}.{}.{}.{}".format(int(ip1,16),int(ip2,16),int(ip3,16),int(ip4,16)))
    print("\tTarget MAC address: {}:{}:{}:{}:{}:{}".format(reply[32:33].hex(),reply[33:34].hex(),reply[34:35].hex(),reply[35:36].hex(),reply[36:37].hex(),reply[37:38].hex()))
    ip1 = reply[38:39].hex()
    ip2 = reply[39:40].hex()
    ip3 = reply[40:41].hex()
    ip4 = reply[41:42].hex()
    print("\tTarget IP address: {}.{}.{}.{}".format(int(ip1,16),int(ip2,16),int(ip3,16),int(ip4,16)))
