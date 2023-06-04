#!/usr/bin/python

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

def poolGenerator(name, serlist, serport):
    pool = "tmsh create ltm pool " + name + " members add {"
    for ip in serlist:
        member = " " + ip + ":" + str(serport) + " { address " + ip + " }"
        pool += member
    pool += " } monitor http"
    print(pool)

def snatGenerator(name, snatlist):
    snat = "tmsh create ltm snatpool " + name + " {"
    for ip in snatlist:
        member = " members add { " + ip + " }"
        snat += member
    snat += " }"
    print(snat)

def vsGenerator(vs_name, pool_name, snat_name, addr, port, protocol):
    vs = "tmsh create ltm virtual " + vs_name + " destination " + addr + ":" + str(port) + " pool " + pool_name + " ip-protocol " + protocol + " source-address-translation { type snat " + snat_name + " }"
    print(vs)  

def addNewVirtualServer(name, addr, port, serlist, serport, snatlist, protocol):
    prefix = "yw" + "_" + addr + "_" + str(port) + "_"
    vs_name = prefix + "vs"
    pool_name = prefix + "pool"
    snat_name = prefix + "snat"
    poolGenerator(pool_name, serlist, serport)
    snatGenerator(snat_name, snatlist)
    vsGenerator(vs_name, pool_name, snat_name, addr, port, protocol)

def tmshstrip(str, c):
    str = str.strip().lstrip(c).rstrip(c)
    return str

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
        addNewVirtualServer(dict[k_name], dict[k_vip], dict[k_vport], format_ip_addr(dict[k_serveraddr]), dict[k_serverport], format_ip_addr(dict[k_snataddr]), dict[k_protocol])
