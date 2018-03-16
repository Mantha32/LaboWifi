#!/bin/bash
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
# file: monitorOn.sh
# Purpose: This script put the interface on and on monitor mode.
# Ps : You can replace 'wlan0' with the name of your interface if needed  
# Authors: Yosra Harbaoui, Iando Rafidimalala
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

sudo ip link set wlan0 down
sudo iwconfig wlan0  mode monitor
sudo ip link set wlan0 up
