#!/usr/bin/env python

from decimal import *
import gc
import math
from scapy.all import *
from scapy.utils import rdpcap
import time

gc.collect() # garbage collector to release unreference memory

# ======== variables - modify them as you wish
inputDir = 'inputfiles'
inputFileName = 'input_pcapdata.pcap'
outputDir = 'outputfiles'
outputFileName = 'output_pcapdata.pcap'
srcIP = "129.187.211.123" # !!! UPDATE !!! UPDATE THIS LINE EVERYTIME CLIENT HAS NEW IP !!! OTHERWISE, PACKETS MAY NOT REACH TO SERVER SIDE.
dstIP = "129.187.205.6" # !!! UPDATE !!! IP addr of server
printStatInt = 10000 # how often the processing stat to be displayed on the terminal. Once per given # of loops
srcPort = 47811 # UDP port at client
dstPort = 47813 # UDP port at server

# variables for MTU limitation. leftOver bytes: remaining bytes from packets due to MTU limitation.
maxMTU = 1500
artifDelay = 0.002000 # artificial delay for extra packets generated, 2 msec
addLeftOverBytes = True # !!! NOTE: STORING LEFTOVER BYTES CAN SLOW DOWN THE PROCESS !!! whether to add leftover bytes to end of already-existing packets where len(pkt) > maxMTU
leftOverBytes_genNewPkts = True # whether to generate new packets out of leftover bytes

# load balancing variables
loadBal = False # load balancing feature. Only half of the data will be generated. Select odd or even below
loadBalPat_even = False # packets with even packet numbers will be written. Valid only if loadBal is True

# packet splitting variables
pSplit = False # Turn on/off packet splitting
ps_send2ndHalf = False # send only the 2nd half of packets for packet splitting method. Otherwise, 1st half to be sent

# ======== shape packet lengths
def resize_packet(pkt, maxMTU, clonedPkt, macIPUDPOverhead_sqnNum, leftoverData):
	clonedPkt = str(pkt) # convert pkt into string

	# MTU limitation
	if len(clonedPkt) > maxMTU: # dissect the packet if it exceeds the max MTU size		
		leftoverData = leftoverData + clonedPkt[maxMTU:] # collect extra bytes
		clonedPkt = clonedPkt[:maxMTU] # shrink the size of packet to maxMTU and reduce extra bytes to allocate IP & UDP layers later$
	
	# Packet splitting
	if pSplit == True:
		if ps_send2ndHalf == True:
			if addLeftOverBytes == True: leftoverData = leftoverData + clonedPkt[:len(clonedPkt)/2] # collect extra bytes
			clonedPkt = clonedPkt[len(clonedPkt)/2:] # shrink the size of packet to maxMTU and reduce extra bytes to allocate IP & UDP layers later on
		else:
			if addLeftOverBytes == True: leftoverData = leftoverData + clonedPkt[len(clonedPkt)/2:] # collect extra bytes
			clonedPkt = clonedPkt[:len(clonedPkt)/2] # shrink the size of packet to maxMTU and reduce extra bytes to allocate IP & UDP layers later on
	
	# MTU limitation
	if len(clonedPkt) > maxMTU: # dissect the packet if it exceeds the max MTU size
		leftoverData = leftoverData + clonedPkt[maxMTU:] # collect extra bytes
		clonedPkt = clonedPkt[:maxMTU] # shrink the size of packet to maxMTU and reduce extra bytes to allocate IP & UDP layers later on
	
	# Add leftover bytes to end of already-existing packets
	if addLeftOverBytes == True and len(clonedPkt) < maxMTU:  # send leftover bytes if enabled && packet len < maxMTU
		emptySize = maxMTU - len(clonedPkt) # find out number of leftover bytes that can be allocated to packet
		if emptySize < len(leftoverData): # leftover bytes exceeding available space in pkt
			clonedPkt_origLen = len(clonedPkt) # store original length of pkt before extending its size, original length needed to determine what portion of leftover data to keep
			clonedPkt = clonedPkt + leftoverData[:maxMTU - clonedPkt_origLen] # place portion of leftover bytes to pkt
			leftoverData = leftoverData[maxMTU - clonedPkt_origLen:] # delete allocated bytes from leftover str
		else: # all leftover bytes can be allocated in packet
			clonedPkt = clonedPkt + leftoverData # add leftover bytes to packet, reduce the size to allocate IP & UDP layers later on
			leftoverData = ''
	
	# Remove bytes from packets for extra bytes from IP&UDP layers, to keep packet length same
        #leftOverData = leftOverData + clonedPkt[len(clonedPkt) - macIPUDPOverhead_sqnNum:] # enable this line if you want to send all bytes from original packets. It is disabled now to keep total bitrate same
	clonedPkt = clonedPkt[:len(clonedPkt) - macIPUDPOverhead_sqnNum]
	
	return clonedPkt, leftoverData

# renegerate manipulated packets
def renegerate_packet(pkts, pkt_list, clonedPkt, counter, timestamp, leftOverBytes_timestamp):
	clonedPkt = str(counter + 1).zfill(len(str(len(pkts)))) + clonedPkt # add sqn number to the beginning of packet, zfill to add leading zeroes to sqn
	clonedPkt = UDP()/clonedPkt
	clonedPkt = IP()/clonedPkt # 13082019
	clonedPkt[IP].src = srcIP
	clonedPkt[IP].dst = dstIP
	clonedPkt[UDP].sport = srcPort # Add a src port #
	clonedPkt[UDP].dport = dstPort # Add a dest port #
	if leftOverBytes_timestamp == False:
		timestamp = pkts[counter].time
	clonedPkt.time = timestamp # Keep original timestamps on packets
	pkt_list.append(clonedPkt)
	return timestamp

# ======== MAIN
def main():
	pkts = rdpcap(inputDir + os.sep + inputFileName)
	macIPUDPOverhead_sqnNum = 28 # # num of extra bytes from IP & UDP layers and sqn number additions. 28 from IP&UDP layers
	macIPUDPOverhead_sqnNum += len(str(len(pkts))) # Add the byte size of pkt sqn number to the overhead
	counter = 0
	pkt_list = []
	leftoverData = ''
	clonedPkt = ''
	elapsedTime = []
	timestamp = 0
	print("Packet manipulation has begun. It will take a while...")
	t1 = time.time()
	for pkt in pkts:
		if loadBal == True:
			if loadBalPat_even == True and counter % 2 != 0:
				clonedPkt, leftoverData = resize_packet(pkt, maxMTU, clonedPkt, macIPUDPOverhead_sqnNum, leftoverData)
				timestamp = renegerate_packet(pkts, pkt_list, clonedPkt, counter, timestamp, False)
			elif loadBalPat_even == False and counter % 2 == 0:
				clonedPkt, leftoverData = resize_packet(pkt, maxMTU, clonedPkt, macIPUDPOverhead_sqnNum, leftoverData)
				timestamp = renegerate_packet(pkts, pkt_list, clonedPkt, counter, timestamp, False)
		else: # no load balancing
			clonedPkt, leftoverData = resize_packet(pkt, maxMTU, clonedPkt, macIPUDPOverhead_sqnNum, leftoverData)
			timestamp = renegerate_packet(pkts, pkt_list, clonedPkt, counter, timestamp, False)
		counter += 1
		if counter % 1000 == 0:
			print("Processed loop: {} ({}%)".format(counter, 100*counter//len(pkts)))
			t2 = time.time()
			elapsedTime.append(t2 - t1)
			elapsedTime = elapsedTime[len(elapsedTime) - 20:] # limit the size of array to 20, to avoid array size overgrowth
			elapsedTimeAvg = sum(elapsedTime) / (len(elapsedTime) * 1.0) # 1.0 to make division result in float num
			leftoverTime = elapsedTimeAvg * (len(pkts) - counter) / (1000 * 1.0)
			t1 = t2
			print("Estimated Leftover Time: %.2f s\n\n\n" %(leftoverTime))
	print("Leftover bytes: %d\n\n\n" %len(leftoverData))
	leftoverPktNum = int(math.ceil(float(len(leftoverData)) / (maxMTU))) # find out how many extra packets to be generated from leftover bytes
	lastPktLen = len(leftoverData) % (maxMTU)
	startByte = 0
	if leftOverBytes_genNewPkts == True:
		print("Number of leftover packets = %d \n" %leftoverPktNum)
		print("Last packet len=%d" %lastPktLen)
		print("Adding leftover packets to pcap...")
		for i in range(leftoverPktNum):
			if i == leftoverPktNum - 1:
				clonedPkt = leftoverData[startByte:startByte + lastPktLen - macIPUDPOverhead_sqnNum]
			else:
				clonedPkt = leftoverData[startByte:startByte + maxMTU - macIPUDPOverhead_sqnNum]
				startByte += maxMTU
			timestamp += Decimal(artifDelay)
			timestamp = renegerate_packet(pkts, pkt_list, clonedPkt, counter, timestamp, True)
	wrpcap(outputDir + os.sep + outputFileName, pkt_list)
	print("Packet manipulation is completed!")

main()
