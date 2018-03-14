#!/usr/bin/env python
#This previous line ensures that this script run under python context
# sniffingMacSta.py - find MAC adress based on scapy
# Author: Yosra Harbaoui, Iando Rafidimalala

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
	# Check to make sure we got an 802.11 packet
	if p.haslayer(Dot11):
		# Check to see if it's a device probing for networks and his response
		if p.haslayer(Dot11ProbeReq) :
			checker = p[Dot11].addr2 == macAdress
		elif p.haslayer(Dot11ProbeResp) :
			checker = p[Dot11].addr1 == macAdress
			
	#Print that the device is found and end up the script	
	if checker:
		print "The station using this MAC \" %s \" is found!" %(macAdress)
		sys.exit(1)
		
#A function handler the interuption from user 	
def signal_handler(signal, frame):
	print "Goodbye!"
	p.terminate()
	p.join()
	sys.exit(0)

def monitor_on(macAdress):
    iface = macSTA
    status = False
    
    if 'wlan' in iface:
		print('\n[' +G+ '+' +W+ '] Interface found!\nTurning on monitoring mode...')
		os.system('ifconfig ' + iface + ' down')
		os.system('iwconfig ' + iface + ' mode monitor')
		os.system('ifconfig ' + iface + ' up')
		print('[' +G+ '+' +W+ '] Turned on monitoring mode on: ' + iface)
		status = True

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
	
	#check the length the MAC address to avoid error
	#we assume that the MAC address syntax is correct	
	if len(sys.argv[1]) != 17:
		print "wrong MAC address syntax"
		sys.exit(1)

	macAdress = sys.argv[1]

	# Start the channel hopper
	p = Process(target = channel_hopper)
	p.start()
    
	print "start sniffing the station using this MAC: %s " %(macAdress)

	# Capture CTRL-C to interrupt the script
	signal.signal(signal.SIGINT, signal_handler)


	# Start the sniffer
	#Invoke the scapy function sniff(), pointing to the monitor mode interface,
	#and telling scapy to call searchSTA() for each packet received
	sniff(iface=interface,prn=searchSTA)
	
