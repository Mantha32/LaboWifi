#!/bin/bash
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==
# file: monitorOn.sh
# Purpose: This script put the interface on and on monitor mode.
#Ps : You can replace 'wlx00c0ca3fb74a' with the name of your interface  
# Authors: Yosra Harbaoui, Iando Rafidimalala
#-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==

sudo ip link set wlx00c0ca3fb74a down
sudo iwconfig wlx00c0ca3fb74a  mode monitor
sudo ip link set wlx00c0ca3fb74a up
