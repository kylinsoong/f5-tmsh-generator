#!/usr/bin/python

import sys
import ast

from tmsh_generator_lib import format_ip_addr, generateNewVirtualServer

if not sys.argv[1:]:
    print("Usage: f5-tmsh-generator.py [file] [file]")
    sys.exit()

fileadd = sys.argv[1]

k_name = '\xe7\xb3\xbb\xe7\xbb\x9f\xe5\x90\x8d\xe7\xa7\xb0'
k_vip = 'VS\xe5\x9c\xb0\xe5\x9d\x80'
k_vport = 'VS\xe7\xab\xaf\xe5\x8f\xa3'
k_snataddr = 'SNAT\xe5\x9c\xb0\xe5\x9d\x80'
k_serverport = '\xe6\x9c\x8d\xe5\x8a\xa1\xe5\x99\xa8\xe7\xab\xaf\xe5\x8f\xa3'
k_serveraddr = '\xe7\x9c\x9f\xe5\xae\x9e\xe6\x9c\x8d\xe5\x8a\xa1\xe5\x99\xa8\xe5\x9c\xb0\xe5\x9d\x80'
k_protocol = '\xe5\x8d\x8f\xe8\xae\xae\xe7\xb1\xbb\xe5\x9e\x8b'

with open(fileadd, "r") as file:
    for line in file:
        line = line.replace('[', '{').replace(']', '}')
        dict = ast.literal_eval(line)
        #config = {'name': dict[k_name], 'ip': dict[k_vip], 'port': dict[k_vport], 'protocol': dict[k_protocol]}
        #config['serverlist'] = format_ip_addr(dict[k_serveraddr])
        #config['serverport'] = dict[k_serverport]
        #config['snatpoollist'] = format_ip_addr(dict[k_snataddr])
        #generateNewVirtualServer(config)

        #config = {'name': dict[k_name], 'ip': dict[k_vip], 'port': dict[k_vport], 'protocol': dict[k_protocol]}
        #generateNewVirtualServer(config)

        config = {'name': dict[k_name], 'ip': dict[k_vip], 'port': dict[k_vport], 'protocol': dict[k_protocol]}
        #config['snatpoollist'] = format_ip_addr(dict[k_snataddr])
        config['serverlist'] = format_ip_addr(dict[k_serveraddr])
        config['serverport'] = dict[k_serverport]
        generateNewVirtualServer(config)
