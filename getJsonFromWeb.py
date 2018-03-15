#!/usr/bin/env python
#This previous line ensures that this script run under python context
# getJsonFromWeb.py - get jason object frome website , take MAC as argument
# Author: Yosra Harbaoui, Iando Rafidimalala

#import the system function
import sys

try:
    # For Python 3.0 and later
    from urllib.request import urlopen
except ImportError:
    # Fall back to Python 2's urllib2
    from urllib2 import urlopen
    
import json


macAddress = '' # MAC address target
url = "http://macvendors.co/api/"
	

def getVendorName(url):
	response = urlopen(url)
	data = response.read().decode("utf-8")
	json_data = json.loads(data)
	
	return json_data['result']['company']
	
	
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

	macAddress = sys.argv[1]
	url += macAddress
	vendor = getVendorName(url)
	
	print "The vendor of this MAC :%s is %s" %(macAddress, vendor)	
	
