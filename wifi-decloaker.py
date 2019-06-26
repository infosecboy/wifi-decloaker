#!/usr/bin/python

from scapy.all import *
hidden = []
unhidden=[]
def HiddenSSIDFinder(pkt):
	if pkt.haslayer(Dot11ProbeResp):
		addr2 = pkt.getlayer(Dot11).addr2
		if (addr2 in hidden) and (addr2 not in unhidden):
			print ("[+] Decloaked Hidden SSID: " +" for MAC: " + addr2)
			unhidden.append(arr2)

	if pkt.haslayer(Dot11Beacon):
		if pkt.getlayer(Dot11).info ==' ':
			addr2 = pkt.getlayer(Dot11).addr2
			print ('[-] Detected Hidden SSID: ' + 'with MAC:' + addr2)
			hidden.append(addr2)


iface_input  = raw_input("Enter your monitor mode interface name")
conf.iface = iface_input
sniff(prn=HiddenSSIDFinder)

		
		

