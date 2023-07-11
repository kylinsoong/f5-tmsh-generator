#!/usr/bin/python3

import ipaddress

def is_valid_ip_network(address):
    try:
        ipaddress.ip_network(address, False)
        return True
    except ValueError:
        return False

net_external = '192.168.20.251/24'
result = is_valid_ip_network(net_external)
network = ipaddress.ip_network(net_external, False)
ip_address_str = net_external[0:len(net_external) - 3]
ip_address = ipaddress.ip_address(ip_address_str) + 2
floatingip = str(ip_address) + net_external[len(net_external) - 3:]

print(net_external,floatingip, result)

print("--------------")

a = '10.1.20.240/24'
b = "11.104.24.165/27"
c = "11.104.24.163/27"
d = "11.104.24.160/27"

ip1 = '10.1.20.10'
ip2 = "10.1.10.10"
ip3 = "11.104.24.191"
ip4 = "11.104.24.159"

print(ipaddress.ip_address('192.168.0.1') in ipaddress.ip_network('192.168.0.0/24'))

print(ipaddress.ip_address(ip1))
print(ipaddress.ip_address(ip2))
print(ipaddress.ip_address(ip3))
print(ipaddress.ip_address(ip4))

print(ipaddress.ip_network(a, False))
print(ipaddress.ip_network(b, False))
print(ipaddress.ip_network(c, False))
print(ipaddress.ip_network(d))


print(ipaddress.ip_address(ip1) in ipaddress.ip_network(a, False))
print(ipaddress.ip_address(ip2) in ipaddress.ip_network(a, False))

print(ipaddress.ip_network(b, False).overlaps(ipaddress.ip_network(c, False)))
print(ipaddress.ip_network(b, False).overlaps(ipaddress.ip_network(d, False)))


result = ipaddress.ip_network(b, False)
print(type(result))
print(str(result))
