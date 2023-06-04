#!/usr/bin/python

ip = "22.200.64.67-90"

def find_last_index(str, substr):
    last_index = -1
    while True:
        index = str.find(substr, last_index + 1)
        if index == -1:
            return last_index
        last_index = index

def format_ip_addr(ip):
    list = []
    if("-" in ip) :
        ips = ip.split("-")
        list.insert(0, ips[0])
        lastdot = find_last_index(list[0], ".")
        prefix = list[0][:(lastdot + 1)]
        start = list[0][(lastdot + 1):]
        last = ips[1]
        for i in range(int(last) - int(start)):
            num = int(start) + i
            list.insert(i + 1, prefix + str(num))
    else:
        list.insert(0, ip)
    return list

print(format_ip_addr("1.1.1.1"))
print(format_ip_addr("1.1.1.1-2"))
print(format_ip_addr(ip))

