#!/usr/bin/env python
#This previous line ensures that this script run under python context
# sniffingAPbasedOnSTA.py - find AP based on the device 
# Author: Yosra Harbaoui, Iando Rafidimalala

#import the system function and signal handler
import sys, os, signal
#import the scapy function
from scapy.all import *
#import the Process function 
from multiprocessing import Process

interface = "wlx00c0ca3fb74a"  #monitor interface, change it with your monitor

# This dictionnary keeps track of unique MAC device adresse pairing with his well-known BSS
# Unique Mac client is associate with SPA list. The Mac client is used as key
dictSTA_APS = dict() 

#Keep track of the pair (MAC client, SSID)
#Check to make if this device MAC address exist, and add on his SSID list is the SSID is not yet record
#otherwise add the pair (clientMac,SSID) like a new entry
def recordPair(clientMac, SSID):
	#Check if the device MAC address have recorded before
	if clientMac in dictSTA_APS.keys():
		# Check to see if we have seen the AP MAC address before, if not, record it
		if SSID not in dictSTA_APS[clientMac]:
			dictSTA_APS[clientMac].append(SSID)
	else:
		#Keep track of the new pair
		dictSTA_APS[clientMac] = list().append(SSID)
	
	
		
#Search the device based on his MAC and each AP associate on it
# This function sniff the probe request sending by the client
#The packet that was sniffed is passed as the function argument
def packetAnalyzer(pkt):
	
	# Check to make sure we got an 802.11 packet
	if pkt.haslayer(Dot11):
		# The device try to seek any well-known BSS.
		## Check to see if it's the device probing for networks
		if (pkt.type == 0 and pkt.subtype == 4):	#p.haslayer(Dot11ProbeReq)
			SSID = pkt.info
			BSSID = pkt.addr2
			STA_MAC = pkt.addr3
			# Check to see if we have seen the STA MAC address before, if not, keep track on it
			# And make sure SSID is not blank
			if pkt.info !="":
				recordPair(STA_MAC, SSID)
				
				# Display Device MAC and his discovered AP (BSSID.SSID)
				print " %s  %s %s" % (STA_MAC, BSSID, SSID) 			
			
		
#A function handler the interuption from user 	
def signal_handler(signal, frame):
	print "Goodbye!"
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

	# Start the channel hopper
	p = Process(target = channel_hopper)
	p.start()
    
	print "start sniffing the station!"

	# Capture CTRL-C to interrupt the script
	signal.signal(signal.SIGINT, signal_handler)


	# Start the sniffer
	#Invoke the scapy function sniff(), pointing to the monitor mode interface,
	#and telling scapy to call packetAnalyzer() for each packet received
	sniff(iface=interface,prn=packetAnalyzer)
	
