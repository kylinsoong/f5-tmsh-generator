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

def poolGenerator(name, dict):
    if("serverlist" in dict and "serverport" in dict):
        serlist = dict['serverlist']
        serport = dict['serverport']
        pool = "tmsh create ltm pool " + name + " members add {"
        for ip in serlist:
            member = " " + ip + ":" + str(serport)
            pool += member
        pool += " } monitor tcp"
        print(pool)
        return True
    else:
        return False

def extract_exist_poolmembers(pool_name, infolist):
    results = []
    ip_list = []
    port_list = []
    for info in infolist:
        if "poolname" in info and pool_name == info['poolname'] and "pool" in info:
            results = info['pool']
            break
    for i in results:
        ip_list.append(i['ip'])
        port_list.append(i['port'])
    return (ip_list, list(dict.fromkeys(port_list)))     

def pool_generator_modify_add_memebers(name, dict):
    members = extract_exist_poolmembers(name, dict['infolist'])
    if("serverlist" in dict and "serverport" in dict):
        serlist = dict['serverlist']
        serport = dict['serverport']
        pool = "tmsh modify ltm pool " + name + " members add {"
        if serport not in members[1]:
            for ip in serlist:
                member = " " + ip + ":" + str(serport)
                pool += member
        else:
            for ip in serlist:
                if ip not in members[0]:
                    member = " " + ip + ":" + str(serport)
                    pool += member
        pool += " }"
        print(pool)            

def snatGenerator(name, dict):
    if("snatpoollist" in dict):
        snatlist = dict['snatpoollist']
        snat = "tmsh create ltm snatpool " + name + " members add {"
        for ip in snatlist:
            member = " " + ip
            snat += member
        snat += " }"
        print(snat)
        return True
    else:
        return False

def extract_exist_members(snat_name, infolist):
    results = []
    for info in infolist:
        if "snatpoolname" in info and snat_name == info['snatpoolname'] and "snatpool" in info:
            results = info['snatpool']
            break
    return results

def snat_generator_modify_add_memebers(snat_name, dict):
    members = extract_exist_members(snat_name, dict['infolist'])
    if("snatpoollist" in dict):
        snatlist = dict['snatpoollist']
        snat = "tmsh modify ltm snatpool " + snat_name + " members add {"
        for ip in snatlist:
            if ip not in members:
                member = " " + ip
                snat += member
        snat += " }"
        print(snat)

def profileGenerator(protocol):
    if protocol == "tcp":
        return "profiles add { fastL4 { } }"
    elif protocol == "http":
        return "profiles add { http { } }"
    else:
        return "profiles add { fastL4 { } }"

def vsGenerator(vs_name, pool_name, snat_name, addr, port, protocol):
    print(vs_name, pool_name, snat_name, addr, port, protocol)
    vs = "tmsh create ltm virtual " + vs_name + " destination " + addr + ":" + str(port) + " pool " + pool_name + " ip-protocol tcp " + profileGenerator(protocol) + " source-address-translation { type snat pool " + snat_name + " }"
    print(vs)

def vsGeneratorSnatOnly(vs_name, snat_name, addr, port, protocol):
    vs = "tmsh create ltm virtual " + vs_name + " destination " + addr + ":" + str(port) + " ip-protocol tcp " + profileGenerator(protocol) + " source-address-translation { type snat " + snat_name + " }"
    print(vs)

def vsGeneratorPoolOnly(vs_name, pool_name, addr, port, protocol):
    vs = "tmsh create ltm virtual " + vs_name + " destination " + addr + ":" + str(port) + " ip-protocol tcp  pool " + pool_name + " " + profileGenerator(protocol)
    print(vs)

def vsGeneratorVSOnly(vs_name, addr, port, protocol):
    vs = "tmsh create ltm virtual " + vs_name + " destination " + addr + ":" + str(port) + " ip-protocol tcp " + profileGenerator(protocol)
    print(vs)

def vs_generator_modify_reference_pool_snat(vs_name, pool_name, snat_name):
    vs = "tmsh modify ltm virtual " + vs_name + " pool " + pool_name + " source-address-translation { type snat pool "+ snat_name +" }"
    print(vs)

def vs_generator_modify_reference_pool(vs_name, pool_name):
    vs = "tmsh modify ltm virtual " + vs_name + " pool " + pool_name
    print(vs)

def vs_generator_modify_reference_snat(vs_name, snat_name):
    vs = "tmsh modify ltm virtual " + vs_name +  " source-address-translation { type snat pool "+ snat_name +" }"
    print(vs)


def network_generate(ip, config):
    vlan_name = "external"
    vlan_inter = "2.1"
    vlan_type = "untagged" 
    vlan = "tmsh create net vlan " + vlan_name + " interfaces add { " + vlan_inter + " { " + vlan_type + " } }"
    gateway_ip = "10.1.10.240"
    gateway_net = "10.1.10.240/24"
    vlan_gateway = "tmsh create net self " + gateway_ip + " address " + gateway_net + " vlan " + vlan_name + " allow-service default"
    #print(vlan)
    #print(vlan_gateway)


def is_vs_exist(vs_name, dict):
    infolist = dict['infolist']
    vs_ip = dict['ip']
    vs_port = dict['port']
    for info in infolist:
        if info['vsname'] == vs_name and info['vsip'] == vs_ip and info['vsport'] == vs_port:
            return True
    return False

def is_pool_exist(pool_name, dict):
    infolist = dict['infolist']
    for info in infolist:
        if "poolname" in info and pool_name == info['poolname']:
            return True
    return False


def is_snatpool_exist(snat_name, dict):
    infolist = dict['infolist']
    for info in infolist:
        if "snatpoolname" in info and snat_name == info['snatpoolname']:
            return True
    return False


def is_net_exists(ip, netlist):
    for n in netlist:
        if ipaddress.ip_address(ip) in ipaddress.ip_network(n, False):
            return True
    return False

def verify_and_generate_net_scripts(ip, config):
    netlist = config['netlist']
    if not is_net_exists(ip, netlist):
        network_generate(ip, config)

def generate_net_scripts(config):
    vip = config['ip']
    verify_and_generate_net_scripts(vip, config)

    poolip = config['serverlist']
    for ip in poolip:
        verify_and_generate_net_scripts(ip, config)

    snatpoolip = config['snatpoollist']
    for ip in snatpoolip:
        verify_and_generate_net_scripts(ip, config)


def generate_vs_exist(vs_name, pool_name, snat_name, dict):
    isPoolCreated = False
    isSnatCreated = False

    if is_pool_exist(pool_name, dict):
        pool_generator_modify_add_memebers(pool_name, dict)
    else:
        isPoolCreated = poolGenerator(pool_name, dict)

    if is_snatpool_exist(snat_name, dict):
        snat_generator_modify_add_memebers(snat_name, dict)
    else:
        isSnatCreated = snatGenerator(snat_name, dict)


    if(isPoolCreated and isSnatCreated):
        vs_generator_modify_reference_pool_snat(vs_name, pool_name, snat_name)
    elif(isPoolCreated and ~isSnatCreated):
        vs_generator_modify_reference_pool(vs_name, pool_name)
    elif(~isPoolCreated and isSnatCreated):
        vs_generator_modify_reference_snat(vs_name, snat_name)    


def generate_vs_not_exist(vs_name, pool_name, snat_name, dict):

    isPoolCreated = poolGenerator(pool_name, dict)
    isSnatCreated = snatGenerator(snat_name, dict)

    if(isPoolCreated and isSnatCreated):
        vsGenerator(vs_name, pool_name, snat_name, dict['ip'], dict['port'], dict['protocol'])
    elif(isPoolCreated and ~isSnatCreated):
        vsGeneratorPoolOnly(vs_name, pool_name, dict['ip'], dict['port'], dict['protocol'])
    elif(~isPoolCreated and isSnatCreated):
        vsGeneratorSnatOnly(vs_name, snat_name, dict['ip'], dict['port'], dict['protocol'])
    else:
        vsGeneratorVSOnly(vs_name, dict['ip'], dict['port'], dict['protocol'])


'''
Generate tmsh for create vs/pool/snat/profile/health/monitor via a dictionary

The dictionary should contains the following key:

  ip       - VS ip
  port     - VS port
  protocol - VS Protocol
  netlist  - show running-config contained network
  infolist - show running-config contained VS/Pool/Snat Info
  
The following keys are optional:

  serverlist   - The list of server ip address
  serverport   - server port
  snatpoollist - The list if snat pool ip address
'''
def generateNewVirtualServer(dict):
    first_later_list = pinyin(dict['name'], style=Style.FIRST_LETTER)
    prefix = listToString(first_later_list) + "_" + dict['ip'] + "_"
    prefix_port = prefix + str(dict['port']) + "_"
    vs_name = prefix_port + "vs"
    pool_name = prefix_port + "pool"
    snat_name = prefix + "snat"

    generate_net_scripts(dict)

    if is_vs_exist(vs_name, dict):
        generate_vs_exist(vs_name, pool_name, snat_name, dict)
    else:
        generate_vs_not_exist(vs_name, pool_name, snat_name, dict)



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


def data_collect_snat(data_all, vs_data_detail):
    vs_snatpool_name = ""
    snatpool_members_detail_list = []
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
            snatpool_members_list = re.search(r'members\s+(\S+)', vs_snatpool_data_detail, re.I)
            if snatpool_members_list:
                vs_snatpool_data_detail = vs_snatpool_data_detail[snatpool_members_list.start():]
                snatpool_members_detail_list = re.findall(r'(\d+\.\d+\.\d+\.\d+)', vs_snatpool_data_detail, re.I)
            else:
                snatpool_members_detail_list = None
        else:
            vs_snatpool_name = None
            snatpool_members_detail_list = None
    else:
        vs_snatpool_name = None
        snatpool_members_detail_list = None

    return (vs_snatpool_name, snatpool_members_detail_list)


def append_snat_info(vs_snatpool_name, snatpool_members_detail_list, info_dict):
    if vs_snatpool_name is not None:
        info_dict['snatpoolname'] = vs_snatpool_name
    if snatpool_members_detail_list is not None and len(snatpool_members_detail_list) > 0:
        info_dict['snatpool'] = snatpool_members_detail_list


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

        snatpool_results = data_collect_snat(data_all, vs_data_detail)
        vs_snatpool_name = snatpool_results[0]
        snatpool_members_detail_list = snatpool_results[1]

        vs_pool_detail_list = re.search(r'pool\s+(\S+)', vs_data_detail, re.I)
        if vs_pool_detail_list:
            vs_pool_detail = vs_pool_detail_list.group(1)

            if vs_pool_detail == "{" :
                tmp_list = re.findall(r'pool\s+(\S+)', vs_data_detail, re.I)
                vs_pool_detail = tmp_list[1]

            # The re.search(r'pool\s+(\S+)', vs_data_detail, re.I) search may get both pool and snatpool
            #   If vs has pool, then the vs_pool_detail is the name of pool
            #   if vs don't has pool, then the vs_pool_detail may be the snatpool name
            #
            # If pool name equals snatpool name, should skip the pool match parse
            #        VS has snatpool, but no has pool
            if vs_pool_detail == vs_snatpool_name:
                info_dict = {
                    'vsname': vs_name_detail,
                    'vsip': vs_ip_detail,
                    'vsport': vs_port_detail
                }
                append_snat_info(vs_snatpool_name, snatpool_members_detail_list, info_dict)
                info_list.append(info_dict)
            else:
                pool_data_start = re.search(r'ltm pool\s+'+vs_pool_detail, data_all, re.I).start()
                pool_data_end = re.search(r'}\s+}', data_all[pool_data_start:]).start()
                pool_data_detail = data_all[pool_data_start:][:pool_data_end]
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
                    append_snat_info(vs_snatpool_name, snatpool_members_detail_list, info_dict)
                    info_list.append(info_dict)
                else:    # VS has pool, but the pool does not has member                    
                    info_dict = {
                        'vsname': vs_name_detail,
                        'vsip': vs_ip_detail,
                        'vsport': vs_port_detail,
                        'poolname': vs_pool_detail
                    }
                    append_snat_info(vs_snatpool_name, snatpool_members_detail_list, info_dict)
                    info_list.append(info_dict)
        else: # VS does not has a pool
            info_dict = {
                'vsname': vs_name_detail,
                'vsip': vs_ip_detail,
                'vsport': vs_port_detail
            }
            append_snat_info(vs_snatpool_name, snatpool_members_detail_list, info_dict)
            info_list.append(info_dict)
            
    return (net_list, info_list)


if not sys.argv[2:]:
    print("Usage: f5-tmsh-generator.py [file] [file]")
    sys.exit()

fileconfig = sys.argv[1]
fileadd = sys.argv[2]

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
    config_results = data_collect(fileconfig)
    for line in file:
        line = line.replace('[', '{').replace(']', '}')
        dict = ast.literal_eval(line)
        config = {'name': dict[k_name], 'ip': dict[k_vip], 'port': dict[k_vport], 'protocol': dict[k_protocol]}
        config['serverlist'] = format_ip_addr_list(dict[k_serveraddr])
        config['serverport'] = dict[k_serverport]
        config['snatpoollist'] = format_ip_addr_list(dict[k_snataddr])
        config['internal'] = dict[k_internal]
        config['internalvlan'] = dict[k_internalvlan]
        config['external'] = dict[k_external]
        config['externalvlan'] = dict[k_externalvlan]
        config['netlist'] = config_results[0]
        config['infolist'] = config_results[1]
        generateNewVirtualServer(config)
