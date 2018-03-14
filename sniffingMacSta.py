#!/usr/bin/env python



import sys, os, signal
from scapy.all import *
from multiprocessing import Process
import sys

macAdress = '' # MAC address target
interface = "wlx00c0ca3fb74a"  #monitor interface

#Process sniffed Proberesponse , ProbeRequest , traffic between the specific station and the AP

def searchSTA(p):
	checker = False;
	if p.haslayer(Dot11):
		checker = ((p.haslayer(Dot11ProbeReq) and p[Dot11].addr2 == macAdress))
		
	if checker:
		print "The station using this MAC \" %s \" is found" %(macAdress)
		sys.exit(1)
		
			
def signal_handler(signal, frame):
	print "goodbye!"
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

# Channel hopper
def channel_hopper():
    while True:
        try:
            channel = random.randrange(1,15)
            os.system("iw dev %s set channel %d" % (interface, channel))
            time.sleep(1)
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
	if len(sys.argv) != 2:
		print "Need Mac Address pass through argument on this script "
		sys.exit(1)
		
	if len(sys.argv[1]) != 17:
		print "wrong MAC address syntax"
		sys.exit(1)

	macAdress = sys.argv[1]

	# Start the channel hopper
	p = Process(target = channel_hopper)
	p.start()
    
	print "start sniffing the station using this MAC: %s " %(macAdress)

	# Capture CTRL-C
	signal.signal(signal.SIGINT, signal_handler)


	# Start the sniffer	
	sniff(iface=interface,prn=searchSTA)
	
