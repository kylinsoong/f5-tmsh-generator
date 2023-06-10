#!/usr/bin/python3

import sys
import ast

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


if not sys.argv[1:]:
    print("Usage: f5-tmsh-generator.py [file] [file]")
    sys.exit()

fileadd = sys.argv[1]

k_name = '系统名称'
k_vip = 'VS地址'
k_vport = 'VS端口'
k_snataddr = 'SNAT地址'
k_serverport = '服务器端口'
k_serveraddr = '真实服务器地址'
k_protocol = '协议类型'
k_internal = 'internal地址'
k_internalvlan = 'internalvlan'
k_external = 'external地址'
k_externalvlan = 'externalvlan'

with open(fileadd, "r") as file:
    for line in file:
        line = line.replace('[', '{').replace(']', '}')
        dict = ast.literal_eval(line)
        print(dict['系统名称'])
        config = {'name': dict[k_name], 'ip': dict[k_vip], 'port': dict[k_vport], 'protocol': dict[k_protocol]}
        config['serverlist'] = format_ip_addr(dict[k_serveraddr])
        config['serverport'] = dict[k_serverport]
        config['snatpoollist'] = format_ip_addr(dict[k_snataddr])
        config['internal'] = dict[k_internal]
        config['internalvlan'] = dict[k_internalvlan]
        config['external'] = dict[k_external]
        config['externalvlan'] = dict[k_externalvlan]
        print(config)
       # generateNewVirtualServer(config)
