#!/usr/bin/python3

import ipaddr

a = "10.1.20.240/24"
b = "11.104.24.165/27"
c = "11.104.24.163/27"

na = ipaddr.IPNetwork(a)
nb = ipaddr.IPNetwork(b)
nc = ipaddr.IPNetwork(c)

ip1 = ipaddr.IPNetwork("10.1.20.10")
ip2 = ipaddr.IPNetwork("10.1.10.10")
ip3 = ipaddr.IPNetwork("11.104.24.191")
ip4 = ipaddr.IPNetwork("11.104.24.159")


print(nb.overlaps(nc))
print(na.overlaps(nc))
print(na.overlaps(ip1))
print(na.overlaps(ip2))
print(nb.overlaps(ip3))
print(nb.overlaps(ip4))
print(nc.overlaps(ip3))
print(nc.overlaps(ip4))


#addr1 = ipaddress.ip_address('10.1.20.10')
#addr2 = ipaddress.ip_address('10.1.10.10')

#print(addr1 in ipaddress.ip_network(a))
#print(addr2 in ipaddress.ip_network(a))
