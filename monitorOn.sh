#!/bin/bash

sudo ip link set wlx00c0ca3fb74a down
sudo iwconfig wlx00c0ca3fb74a  mode monitor
sudo ip link set wlx00c0ca3fb74a up
