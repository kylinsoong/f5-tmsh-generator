#!/usr/bin/python3

import sys
import ast
import re
import socket
import ipaddress

from pypinyin import pinyin, Style

def listToString(s):
    result = ""
    for l in s:
        result += l[0]
    return result

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
            num = int(start) + i + 1
            list.insert(i + 1, prefix + str(num))
    else:
        list.insert(0, ip)
    return list

def format_ip_addr_list(ip):
    list = []
    if("," in ip) :
        ips = ip.split(",")
        for i in ips:
            list.extend(format_ip_addr(i)) 
    else:
        list = format_ip_addr(ip)
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

def vsGeneratorSnatOnly(vs_name, snat_name, addr, port, protocol):
    vs = "tmsh create ltm virtual " + vs_name + " destination " + addr + ":" + str(port) + " ip-protocol " + protocol + " source-address-translation { type snat " + snat_name + " }"
    print(vs)

def vsGeneratorPoolOnly(vs_name, pool_name, addr, port, protocol):
    vs = "tmsh create ltm virtual " + vs_name + " destination " + addr + ":" + str(port) + " ip-protocol " + protocol + " pool " + pool_name
    print(vs)

def vsGeneratorVSOnly(vs_name, addr, port, protocol):
    vs = "tmsh create ltm virtual " + vs_name + " destination " + addr + ":" + str(port) + " ip-protocol " + protocol
    print(vs)


'''
Generate tmsh for create vs/pool/snat/profile/health/monitor via a dictionary

The dictionary should contains the following key:

  ip       - VS ip
  port     - VS port
  protocol - VS Protocol
  
The following keys are optional:

  serverlist   - The list of server ip address
  serverport   - server port
  snatpoollist - The list if snat pool ip address
'''
def generateNewVirtualServer(dict):
    first_later_list = pinyin(dict['name'], style=Style.FIRST_LETTER)
    prefix = listToString(first_later_list) + "_" + dict['ip'] + "_" + str(dict['port']) + "_"
    vs_name = prefix + "vs"
    pool_name = prefix + "pool"
    snat_name = prefix + "snat"

    isPoolCreated = False
    isSnatCreated = False

    if("serverlist" in dict and "serverport" in dict):
        poolGenerator(pool_name, dict['serverlist'], dict['serverport'])
        isPoolCreated = True

    if("snatpoollist" in dict):
        snatGenerator(snat_name, dict['snatpoollist'])
        isSnatCreated = True    

    if(isPoolCreated and isSnatCreated):
        vsGenerator(vs_name, pool_name, snat_name, dict['ip'], dict['port'], dict['protocol'])
    elif(isPoolCreated and ~isSnatCreated):
        vsGeneratorPoolOnly(vs_name, pool_name, dict['ip'], dict['port'], dict['protocol'])
    elif(~isPoolCreated and isSnatCreated):
        vsGeneratorSnatOnly(vs_name, snat_name, dict['ip'], dict['port'], dict['protocol'])
    else:
        vsGeneratorVSOnly(vs_name, dict['ip'], dict['port'], dict['protocol'])

def manually_mapping(input):
    if input == 'any':
        return '0'
    else:
        print(input)
        return '0'

def convert_servicename_to_port(input):
    result = "";
    if isinstance(input, str):
        if input.isdigit():
            return input
        try:
            result = socket.getservbyname(input)
        except OSError:
            return manually_mapping(input)
    else:
        result = input
    return str(result)

def convert_servicename_to_port_f5(input):
    all_dict = {}
    with open("f5-services") as myfile:
        for line in myfile:
            name, var = line.partition(" ")[::2]
            all_dict[name.strip()] = var.strip()

    if input in all_dict:
        return all_dict[input]
    else:
        return convert_servicename_to_port(input)

def data_collect(filepath):
    info_list = []
    vs_list = []
    net_list = []
    with open(filepath, 'r') as fo:
        data_all = fo.read()

    data_all = data_all.replace('[m','')
    data_all = data_all.replace('[K', '')
    error = re.findall(r'\[7m---\(less (\d+)',data_all)
    for i in error:
        error1 = '[7m---(less '+i
        data_all = data_all.replace(error1, '')
    fo.close()

    net_name_data = re.findall(r'net self\s+\S+',data_all, re.I)
    for i in net_name_data:
        net_self_data_start = re.search(i, data_all, re.I).start()
        net_self_data_end = re.search('address', data_all[net_self_data_start:]).start()
        net_self_data = data_all[net_self_data_start:][:net_self_data_end + 40]
        #net_self_address = re.search(r'address\s+(\d+\.\d+\.\d+\.\d+)', net_self_data, re.I)
        net_self_address_list = re.search(r'address\s+((\d){1,3}\.){3}\d{1,3}(\/(\d{1,2}))?', net_self_data, re.I)
        if net_self_address_list:
            net_self_address = net_self_address_list.group(0)
            net_self_address = net_self_address.lstrip('address').strip()
            net_addr = ipaddress.ip_network(net_self_address, False)
            net_list.append(str(net_addr))
    net_list = list(dict.fromkeys(net_list))
    #print(net_list)
    #print(len(net_list))

    vs_name_data = re.findall(r'ltm virtual\s+\S+',data_all, re.I)
    for i in vs_name_data:
        vs_list.append(i)

    for i,num  in zip(vs_name_data,range(len(vs_name_data))):
        if num < len(vs_list)-1:
            vs_data_start = re.search(i, data_all, re.I).start()
            vs_data_end = re.search(vs_list[num+1], data_all[vs_data_start:]).start()
            vs_data_detail = data_all[vs_data_start:][:vs_data_end]
        else:
            vs_data_start = re.search(i, data_all, re.I).start()
            vs_data_end = re.search(r'net interface', data_all[vs_data_start:]).start()
            vs_data_detail = data_all[vs_data_start:][:vs_data_end]

        vs_name_detail_list = re.search(r'ltm virtual\s+(\S+)', vs_data_detail,re.I)
        vs_name_detail = vs_name_detail_list.group(1)
        
        vs_ip_detail_list = re.search(r'destination\s+(\d+\.\d+\.\d+\.\d+)', vs_data_detail, re.I)
        vs_ip_detail = vs_ip_detail_list.group(1)

        vs_port_detail_list = re.search(r'destination\s+\d+\.\d+\.\d+\.\d+:(\S+)', vs_data_detail, re.I)
        vs_port_detail = vs_port_detail_list.group(1)
        vs_port_detail = convert_servicename_to_port_f5(vs_port_detail)

        vs_snatpool_name = ""
        snatpool_members_detail_list = []
        vs_pool_detail_list = re.search(r'pool\s+(\S+)', vs_data_detail, re.I)
        if vs_pool_detail_list:
            vs_pool_detail = vs_pool_detail_list.group(1)
            pool_data_start = re.search(r'ltm pool\s+'+vs_pool_detail, data_all, re.I).start()
            pool_data_end = re.search(r'}\s+}', data_all[pool_data_start:]).start()
            pool_data_detail = data_all[pool_data_start:][:pool_data_end]

            vs_snat_detail_list = re.search(r'source-address-translation\s+(\S+)', vs_data_detail, re.I)
            if vs_snat_detail_list:
                vs_snat_start = re.search(vs_snat_detail_list.group(), vs_data_detail, re.I).start()
                vs_snat_end = re.search("}", vs_data_detail[vs_snat_start:]).start()
                vs_snat_detail = vs_data_detail[vs_snat_start:][:vs_snat_end + 1]
                vs_snatpool_name_list = re.search(r'pool\s+(\S+)', vs_snat_detail, re.I)
                if vs_snatpool_name_list:
                    vs_snatpool_name = vs_snatpool_name_list.group(1)
                    vs_snatpool_data_start = re.search(r'ltm snatpool\s+'+vs_snatpool_name, data_all, re.I).start()
                    vs_snatpool_data_end = re.search(r'}\s+}', data_all[vs_snatpool_data_start:]).start()
                    vs_snatpool_data_detail = data_all[vs_snatpool_data_start:][:vs_snatpool_data_end + 1]
                    snatpool_members_detail_list = re.findall(r'(\d+\.\d+\.\d+\.\d+)', vs_snatpool_data_detail, re.I)

            pool_ip_port_detail_list = re.findall(r'(\d+\.\d+\.\d+\.\d+):(\S+)\s+{', pool_data_detail, re.I)
            if pool_ip_port_detail_list:
                members = []
                for i,j in pool_ip_port_detail_list:
                    member_dict = {
                        'ip': i,
                        'port': convert_servicename_to_port_f5(j)
                    }
                    members.append(member_dict)

                info_dict = {
                    'vsname': vs_name_detail,
                    'vsip': vs_ip_detail,
                    'vsport': vs_port_detail,
                    'poolname': vs_pool_detail,
                    'pool': members
                }

                if len(snatpool_members_detail_list) > 0:
                    info_dict['snatpoolname'] = vs_snatpool_name
                    info_dict['snatpool'] = snatpool_members_detail_list 
                info_list.append(info_dict)
        else:
            info_dict = {
                'vsname': vs_name_detail,
                'vsip': vs_ip_detail,
                'vsport': vs_port_detail
            }
            info_list.append(info_dict)
            
    return (net_list, info_list)   


#l = data_collect("f5config.1")
#l = data_collect("f5config.2")
#l = data_collect("../config/f5config.0")
l = data_collect("../config/f5config.1")

#print(l)

net_list = l[0]
info_list = l[1]
print(type(net_list))
print(net_list)

