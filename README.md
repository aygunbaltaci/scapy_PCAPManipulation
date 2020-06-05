# Manipulate PCAP Traces with Scapy

This code can manipulate the PCAP data traces for various purposes. It takes a PCAP data trace as input file and manipulates the data packets according to the user-defined features as given below: 

**Features**:

1. It adds IP & UDP layers to the captured packets. So, the original PCAP traces can be injected into IP networks by providing source & end IP addresses and port numbers. 
2. Maximum transmission unit (MTU) can be set to limit the maximum packet size. 
3. For packet scheduling purposes, it can regenerate only the odd or even numbered packets from the original PCAP trace. It can also divide original packets into two chunks (for load balancing purposes).   

## Prerequisites
**Python 3**
> sudo apt update

> sudo apt install python3.6 (or any other python3 version) 

**Scapy library**
> pip3 install scapy

## Input File
The program takes input file: 
*inputfiles/input_pcapdata.csv*

## Usage
> python3 scapy_manipulatepackets.py

Modify the variables as you need: *srcIP, dstIP, srcPort, dstPort, maxMTU*, etc.

## Result
The result is saved in the directory below with the corresponding date (YYYYMMDD_HHMMSS):

*outputfiles/*

## Copyright
This code is licensed under GNU General Public License v3.0. For further information, please refer to [LICENSE](LICENSE)
