import datetime
# import imp
# from ipaddress import IPv4Address
# from posixpath import split
import dns.message
import dns.query
import dns.exception
import dns.rcode
import dns.rdtypes
import time
# from urllib3 import Retry

ROOT_SERVERS = [ 
    "198.41.0.4",
    "199.9.14.201",
    "193.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "192.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "199.7.83.42",
    "202.12.27.33"
] #array of all the root servers
originalResponseig = "" #string needed for CNAME resolving

#function to resolve URLs
def resolver(url, ogurl, server):
        try:
            queryMessage = dns.query.udp(dns.message.make_query(url, "A"), server, 10) #makes query
        except dns.exception.Timeout:
            raise dns.exception.Timeout("DNS search timed out") #catches the timeout
        except dns.exception.FormError:
            raise dns.exception.FormError("Bad URL")
        if (queryMessage.rcode() == 3):
            return "Non"
        answerMessage = "Non" #Base case if nothing happens
        returnSpliterTemp = "" #delcaring variable that is used in string manip
        if(queryMessage.answer != []):
            if "CNAME" in str(queryMessage.answer[0]): #check if the answer is a CNAME
                queryMessageAnswerCNAMEConvert = str(queryMessage.answer[0][0]) #converts it into a usuable IP
                for rootServer in ROOT_SERVERS:
                    returnSpliterTemp = resolver(queryMessageAnswerCNAMEConvert[:-1], ogurl, rootServer) #gets the IP of the CNAME in each root server
                    if(returnSpliterTemp != "Non"):
                        answerMessage = returnSpliterTemp
                        global originalResponseig
                        originalResponseig = str(queryMessage.answer[0]) #set the original answer query to a global variable
                        return answerMessage #return the new IP that was set in returnSpliterTemp
            else:               
                answerMessage = str(queryMessage.answer[0]) #if the answer isn't a CNAME then return the answer IP
                return answerMessage
        else:
            if(len(queryMessage.additional) > 0): #if there is an additional
                for addIP1 in queryMessage.additional:
                    for addIP2 in addIP1: #for each IP in the additional. It needs a double for loop to get the IP itself
                        if ":" not in str(addIP2): #making sure it's not IPv6
                            returnSpliterTemp = resolver(url, ogurl, addIP2.to_text()) #try to resolve the IP using the new additional IP
                            if(returnSpliterTemp != "Non"): #If there is an answer return it, if not check the next additional
                                answerMessage = returnSpliterTemp
                                return answerMessage 
            
            if(len(queryMessage.authority) > 0): #if there are authorites with the additionals either not present or not giving an answer
                for auth1 in queryMessage.authority:
                    for auth2 in auth1: #get the ns for the authority. Double for required to get the ns
                            splitArrayTemp = auth2.to_text().split(" ") #split via space to get the ns from the string
                            for rootServer in ROOT_SERVERS:
                                tempTemp = resolver(splitArrayTemp[0][:-1], ogurl, rootServer) #look for the IP of the NS from the root servers
                                if(tempTemp != "Non"): #if the server has an IP
                                    returnSpliterTemp = resolver(url, ogurl, tempTemp.split(" ")[4]) #take that IP and ask it for the url
                                    if(returnSpliterTemp != "Non"): #if there is an IP, return it
                                        answerMessage = returnSpliterTemp
                                        return answerMessage
        return answerMessage #base case if there is no answer
def main():
    url = input("Enter a URL: ") #gets the url the user wants
    oldTime = time.time()*1000 #gets the time the query starts at
    for server in ROOT_SERVERS: #loops through each root server
        answerStringCheck = resolver(url, url, server) #first call to resolver
        if(answerStringCheck != "Non"): #if answer exists, break the loop
            break
    if(answerStringCheck == "Non"):
        print("Bad URL")
        return
    newTime = time.time() * 1000 #get the final time
    stringArray = answerStringCheck.split(" ") #split the final array with sapces for printing
    totalQueryTime = newTime - oldTime #get total time
    if(originalResponseig != ""): #if CNAME exists, gets the original url wanted with it's TTL
        ogResponse = originalResponseig.split(" ")
        stringArray[0] = ogResponse[0]
        stringArray[1] = ogResponse[1]
    newAnswerString = ""
    for answerString in stringArray: #used to mke the new string that's printed
        newAnswerString += answerString + " "
    print("QUESTION SECTION:" + "\n" + url + ". IN A" + "\n" + "ANSWER SECTION:" + "\n" + newAnswerString + "\n" + "Query time: " + str(totalQueryTime) + "ms" + "\n" + "WHEN: " + str(datetime.datetime.now())) 
    #final print that gives you the output

if __name__ == "__main__":
    main() #calls the main function