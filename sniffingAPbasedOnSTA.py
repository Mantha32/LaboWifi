#!/usr/bin/env python
#This previous line ensures that this script run under python context
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
# file: sniffingAPbasedOnSTA.py
# Purpose: Find AP based on the device
# Description: 	Based on the sniffingMacSta.py script, the different network names annonced to 
#		the clinets are captured. 
# PS: You can change your 'wlan0' with your interface name if needed
# Authors: Yosra Harbaoui, Iando Rafidimalala
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

#import the system function and signal handler
import sys, os, signal
#import the scapy function
from scapy.all import *
#import the Process function 
from multiprocessing import Process
import threading

try:
    # For Python 3.0 and later
    from urllib.request import urlopen
except ImportError:
    from urllib2 import urlopen
    
import json

#monitor interface, you can change it with your monitor's name
interface = "wlan0"  

#macvendors provides API to retrieve the MAC vendor informations
url = "http://macvendors.co/api/" 

# This dictionnary keeps track of unique MAC device adresse pairing with his well-known BSS
# Unique Mac client is associate with SPA list. The Mac client is used as key
dictSTA_APS = dict()

stamgmtstypes = (0, 2, 4)

#Keep track of the pair (MAC client, SSID)
#Check to make if this device MAC address exist, and add on his SSID list is the SSID is not yet record
#otherwise add the pair (clientMac,SSID) like a new entry
def recordPair(clientMac, SSID):
	ssidList = []
	#Check if the device MAC address have not recorded before
	if clientMac not in dictSTA_APS.keys():
		dictSTA_APS[clientMac] = ssidList
		dictSTA_APS[clientMac].append(SSID)		
	# Check to see if we have seen the AP MAC address before and not his SSID, record it
	if SSID not in dictSTA_APS[clientMac]:
		dictSTA_APS[clientMac].append(SSID)

	
	
		
#Search the device based on his MAC and each AP associate on it
# This function sniff the probe request sending by the client
#The packet that was sniffed is passed as the function argument
def packetAnalyzer(pkt):	
	# Check to make sure we got an 802.11 packet
	if pkt.haslayer(Dot11):
		# The device try to seek any well-known BSS.
		## Check to see if it's the device probing for networks
		#if pkt.haslayer(Dot11ProbeReq):
		if (pkt.type == 0 and pkt.subtype in stamgmtstypes):	
			# Check to see if we have seen the STA MAC address before, if not, keep track on it
			# And make sure SSID is not blank
			if pkt.info !="":
				recordPair(pkt.addr2, pkt.info)
				display()	#display when we meet a client		
			


#Retrieve the company using the macvendor API	
def getVendorName(mac):
	try:
		response = urlopen(url + mac)
		data = response.read().decode("utf-8")
		json_data = json.loads(data)
		result = "no result"
		if(json_data['result']['company'])
			result = json_data['result']['company']
		
	except KeyError:
		print "Err.. %s company not found" %(mac)
	return  result

#Diplay the result 
def display():
	for key, ssidList in dictSTA_APS.items():
		ssidToString = ""
		company = getVendorName(key)
		for ssid in ssidList:
			ssidToString += ssid + ", "
		
		print ("%s ( %s ) - %s") %(key, company, ssidToString)
	print('----------------------------------------------------')
	
	

     		
#A function handler the interuption from user 	
def signal_handler(signal, frame):
	display()
	print "Goodbye!"
	sys.exit(0)


if __name__ == "__main__":
    
	print "start sniffing the station!"
	# Print the program header
	print "-=-=-=-=-=-=-=-=-=-= AP base on STA =-=-=-=-=-=-=-=-"
	print "MAC_STA 		COMPANY             SSID"
    
	# Capture CTRL-C to interrupt the script
	signal.signal(signal.SIGINT, signal_handler)
	
	# Start the sniffer
	#Invoke the scapy function sniff(), pointing to the monitor mode interface,
	#and telling scapy to call packetAnalyzer() for each packet received
	sniff(iface=interface,prn=packetAnalyzer)
	
