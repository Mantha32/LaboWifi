#!/usr/bin/env python
#This previous line ensures that this script run under python context
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
# file: sniffingMacSta.py
# Purpose: Find the client MAC address in your area
# Description: Thanks to scapy to propose an API to deal with this issue. The mobile station sends
#			   probe request to discover 802.11 network within its proximity. The probe request contains 
#			   this MAC address and the destination layer-2 address (broadcast or well-kown AP).
#		       We use probe request frame sending by the client device to find if this particular station is
#			   near by us. 
			   	
# Authors: Yosra Harbaoui, Iando Rafidimalala

#import the system function and signal handler
import sys, os, signal
#import the scapy function
from scapy.all import *
#import the Process function 
from multiprocessing import Process


macAdress = '' # MAC address target
interface = "wlx00c0ca3fb74a"  #monitor interface

#Search the device according his MAC adress
#This function sniff Probe response and Probe Request sending by the device
#The packet that was sniffed is passed as the function argument
def searchSTA(p):
	checker = False;
	stamgmtstypes = (0, 2, 4)
	# Check to make sure we got an 802.11 packet
	if p.haslayer(Dot11):
		
		
		# Check to see if it's a device probing for networks and his response
		if p.type == 0 and p.subtype in stamgmtstypes:
			checker = p.addr2 == macAdress
			print p.addr2
	
	#Print that the device is found and end up the script	
	if checker:
		print "The station using this MAC \" %s \" is found!" %(macAdress)
		sys.exit(0)
		
#A function handler the interuption from user 	
def signal_handler(signal, frame):
	p.terminate()
	p.join()
	sys.exit(0)


# A function to hop among channels
def channel_hopper():
    while True:
        try:
            channel = random.randrange(1,15)
            os.system("iw dev %s set channel %d" % (interface, channel))
            time.sleep(1)
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
	#Ensure that we have make the client MAC adress as argument of this script
	if len(sys.argv) != 2:
		print "Need Mac Address pass through argument on this script "
		sys.exit(1)
	
	#check the length of the MAC address to avoid error
	#If the MAC length is correct,we assume that the MAC address syntax is well-defined and correct	
	if len(sys.argv[1]) != 17:
		print "wrong MAC address syntax"
		sys.exit(1)

	macAdress = sys.argv[1]

	# Start the channel hopper
	p = Process(target = channel_hopper)
	p.start()
    
	print "start sniffing the station using this MAC: %s " %(macAdress)
	print "-==-==-==-==-==-==-==-==-==-"
	print "MAC_STA"
	# Capture CTRL-C to interrupt the script
	signal.signal(signal.SIGINT, signal_handler)

	# Start the sniffer
	#Invoke the scapy function sniff(), pointing to the monitor mode interface,
	#and telling scapy to call searchSTA() for each packet received
	sniff(iface=interface,prn=searchSTA)
