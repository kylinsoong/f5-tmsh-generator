#!/usr/bin/python3

import sys
import ast
import re
import socket
import ipaddress

from f5bigip import configParse

from pypinyin import pinyin, Style

def listToString(s):
    result = ""
    for l in s:
        item = l[0]
        item = item[0].upper() + item[1:]
        result += item
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

def poolGenerator(name, dict, rollback_tmsh_list):
    if("serverlist" in dict and "serverport" in dict):
        serlist = dict['serverlist']
        serport = dict['serverport']
        pool = "tmsh create ltm pool " + name + " members add {"
        for ip in serlist:
            member = " " + ip + ":" + str(serport)
            pool += member
        pool += " } monitor tcp"
        print(pool)
        rollback_tmsh_list.append("tmsh delete ltm pool " + name)
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

def pool_generator_modify_add_memebers(name, dict, rollback_tmsh_list):
    members = extract_exist_poolmembers(name, dict['infolist'])
    isPoolNotEmpty = True
    isMemberAdded = False
    if("serverlist" in dict and "serverport" in dict):
        serlist = dict['serverlist']
        serport = dict['serverport']
        if len(serlist) == 1 and serlist[0] == "":
            isPoolNotEmpty = False
        pool = "tmsh modify ltm pool " + name + " members add {"
        pool_rollback = "tmsh modify ltm pool " + name + " members delete {"
        if serport not in members[1]:
            for ip in serlist:
                member = " " + ip + ":" + str(serport)
                pool += member
                pool_rollback += member
                isMemberAdded = True
        else:
            for ip in serlist:
                if ip not in members[0]:
                    member = " " + ip + ":" + str(serport)
                    pool += member
                    pool_rollback += member
                    isMemberAdded = True
        pool += " }"
        pool_rollback += " }"
        if isPoolNotEmpty and isMemberAdded:
            print("====")
            print(pool)
            rollback_tmsh_list.append(pool_rollback)            

def snatGenerator(name, dict, rollback_tmsh_list):
    if("snatpoollist" in dict):
        snatlist = dict['snatpoollist']
        snat = "tmsh create ltm snatpool " + name + " members add {"
        members = ""
        for ip in snatlist:
            if is_valid_ip_address(ip) :
                member = " " + ip
                members += member
        if len(members) > 1:
            snat += members;
            snat += " }"
            print(snat)
            rollback_tmsh_list.append("tmsh delete ltm snatpool " + name )
            return True
        else:
            return False
    else:
        return False

def extract_exist_members(snat_name, infolist):
    results = []
    for info in infolist:
        if "snatpoolname" in info and snat_name == info['snatpoolname'] and "snatpool" in info:
            results = info['snatpool']
            break
    return results

def snat_generator_modify_add_memebers(snat_name, dict, rollback_tmsh_list):
    members = extract_exist_members(snat_name, dict['infolist'])
    isSNATPoolNotEmpty = True
    isMemberAdded = False
    if("snatpoollist" in dict):
        snatlist = dict['snatpoollist']
        if len(snatlist) == 1 and snatlist[0] == "":
            isSNATPoolNotEmpty = False
        snat = "tmsh modify ltm snatpool " + snat_name + " members add {"
        snat_rollback = "tmsh modify ltm snatpool " + snat_name + " members delete {"
        for ip in snatlist:
            if ip not in members:
                member = " " + ip
                snat += member
                snat_rollback += member
                isMemberAdded = True
        snat += " }"
        snat_rollback += " }"
        if isSNATPoolNotEmpty and isMemberAdded:
            print(snat)
            rollback_tmsh_list.append(snat_rollback)

def profileGenerator(protocol):
    if protocol == "tcp":
        return "profiles add { fastL4 { } }"
    elif protocol == "http" and BIGIP_TMOS_VERSION >= 12:
        return "profiles add { http { } } service-down-immediate-action reset"
    elif protocol == "http" and BIGIP_TMOS_VERSION < 12:
        return "profiles add { http { } }"
    else:
        return "profiles add { fastL4 { } }"

def vsGenerator(vs_name, pool_name, snat_name, addr, port, protocol, rollback_tmsh_list):
    vs = "tmsh create ltm virtual " + vs_name + " destination " + addr + ":" + str(port) + " pool " + pool_name + " ip-protocol tcp " + profileGenerator(protocol) + " source-address-translation { type snat pool " + snat_name + " }"
    vs_rollback = "tmsh delete ltm virtual " + vs_name 
    print(vs)
    rollback_tmsh_list.append(vs_rollback)

def vsGeneratorSnatOnly(vs_name, snat_name, addr, port, protocol, rollback_tmsh_list):
    vs = "tmsh create ltm virtual " + vs_name + " destination " + addr + ":" + str(port) + " ip-protocol tcp " + profileGenerator(protocol) + " source-address-translation { type snat " + snat_name + " }"
    vs_rollback = "tmsh modify ltm virtual " + vs_name + " pool none source-address-translation { type none }"
    print(vs)
    rollback_tmsh_list.append(vs_rollback)

def vsGeneratorPoolOnly(vs_name, pool_name, addr, port, protocol, rollback_tmsh_list):
    vs = "tmsh create ltm virtual " + vs_name + " destination " + addr + ":" + str(port) + " ip-protocol tcp  pool " + pool_name + " " + profileGenerator(protocol)
    vs_rollback = "tmsh delete ltm virtual " + vs_name
    print(vs)
    rollback_tmsh_list.append(vs_rollback)

def vsGeneratorVSOnly(vs_name, addr, port, protocol, rollback_tmsh_list):
    vs = "tmsh create ltm virtual " + vs_name + " destination " + addr + ":" + str(port) + " ip-protocol tcp " + profileGenerator(protocol)
    vs_rollback = "tmsh delete ltm virtual " + vs_name 
    print(vs)
    rollback_tmsh_list.append(vs_rollback)

def vs_generator_modify_reference_pool_snat(vs_name, pool_name, snat_name, rollback_tmsh_list):
    vs = "tmsh modify ltm virtual " + vs_name + " pool " + pool_name + " source-address-translation { type snat pool "+ snat_name +" }"
    vs_rollback = "tmsh modify ltm virtual " + vs_name + " pool none source-address-translation { type none }"
    print(vs)
    rollback_tmsh_list.append(vs_rollback)

def vs_generator_modify_reference_pool(vs_name, pool_name, rollback_tmsh_list):
    vs = "tmsh modify ltm virtual " + vs_name + " pool " + pool_name
    vs_rollback = "tmsh modify ltm virtual " + vs_name + " pool none"
    print(vs)
    rollback_tmsh_list.append(vs_rollback)

def vs_generator_modify_reference_snat(vs_name, snat_name, rollback_tmsh_list):
    vs = "tmsh modify ltm virtual " + vs_name +  " source-address-translation { type snat pool "+ snat_name +" }"
    vs_rollback = "tmsh modify ltm virtual " + vs_name + " source-address-translation { type none }"
    print(vs)
    rollback_tmsh_list.append(vs_rollback)


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
        if info['vsip'] == vs_ip and info['vsport'] == vs_port:
            dict['existed_vs_name'] = info['vsname'] 
            if 'poolname' in info.keys():
                dict['existed_pool_name'] = info['poolname']
            else:
                dict['existed_pool_name'] = None
            if 'snatpoolname' in info.keys(): 
                dict['existed_snatpool_name'] = info['snatpoolname']
            else:
                dict['existed_snatpool_name'] = None
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

def is_valid_ip_address(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def is_valid_ip_network(address):
    try:
        ipaddress.ip_network(address, False)
        return True
    except ValueError:
        return False

def verify_and_generate_net_scripts(ip, config):
    if is_valid_ip_address(ip): 
        netlist = config['netlist']
        if not is_net_exists(ip, netlist):
            network_generate(ip, config)

def itertor_and_generate_net_scripts(config):
    vip = config['ip']
    verify_and_generate_net_scripts(vip, config)
        
    poolip = config['serverlist']
    for ip in poolip:
        verify_and_generate_net_scripts(ip, config)
        
    snatpoolip = config['snatpoollist']
    for ip in snatpoolip:
        verify_and_generate_net_scripts(ip, config)

def generate_net_vlan(vlan_name, trunk, tag, rollback_tmsh_list, isActive):
    tmsh = "tmsh create net vlan " + vlan_name + " interfaces add { " + trunk + " { tagged } } tag " + tag
    tmsh_rollback = "tmsh delete net vlan " + vlan_name
    print(tmsh)
    if isActive:
        rollback_tmsh_list.append(tmsh_rollback)

def extract_floating_address(network):
    ip_address_str = network[0:len(network) - 3]
    ip_address = ipaddress.ip_address(ip_address_str) + 2
    floatingip = str(ip_address) + network[len(network) - 3:]
    return floatingip

def extract_standby_address(network):
    ip_address_str = network[0:len(network) - 3]
    ip_address = ipaddress.ip_address(ip_address_str) + 1
    standbyip = str(ip_address) + network[len(network) - 3:]
    return standbyip

def generate_net_gateway(self, floating, vlan_name, self_name, floating_name, standby, isActive, rollback_tmsh_list):
    tmsh_self = "tmsh create net self " + self_name + " address " + self + " vlan " + vlan_name + " allow-service default"
    tmsh_self_rollback = "tmsh delete net self " + self_name 
    tmsh_standby = "tmsh create net self " + self_name + " address " + standby + " vlan " + vlan_name + " allow-service default"
    tmsh_floating = "tmsh create net self " + floating_name + " address " + floating + " vlan " + vlan_name + " allow-service default traffic-group /Common/traffic-group-1"
    tmsh_floating_rollback = "tmsh delete net self " + floating_name
    if isActive:
        print(tmsh_self)
        rollback_tmsh_list.append(tmsh_self_rollback)
        rollback_tmsh_list.append(tmsh_floating_rollback)
    else:
        print(tmsh_standby)
    print(tmsh_floating)

def generate_save_sync(dict, sync_group_name):
    print("tmsh save sys config")
    if sync_group_name is not None:
        print("tmsh run cm config-sync to-group " + sync_group_name)

def generate_net_scripts_with_flag(net_externaltag, net_externaltrunk, net_internaltag, net_internaltrunk, net_external, net_internal, isActive, rollback_tmsh_list):
    isExternalVlanCreated = False
    isInternalVlanCreated = False

    if len(net_externaltag) > 0 and len(net_externaltrunk) > 0:
        vlan_name = "External_vlan" + net_externaltag
        generate_net_vlan(vlan_name, net_externaltrunk, net_externaltag, rollback_tmsh_list, isActive)
        isExternalVlanCreated = True

    if len(net_internaltag) > 0 and len(net_internaltrunk) > 0:
        vlan_name = "Internal_vlan" + net_internaltag
        generate_net_vlan(vlan_name, net_internaltrunk, net_internaltag, rollback_tmsh_list, isActive)
        isInternalVlanCreated = True
    
    if isExternalVlanCreated and is_valid_ip_network(net_external):
        vlan_name = "External_vlan" + net_externaltag
        self_name = "External_selfip_vlan" + net_externaltag
        floating_name = "External_floatingip_vlan" + net_externaltag
        floatingip = extract_floating_address(net_external)
        standby = extract_standby_address(net_external)
        generate_net_gateway(net_external, floatingip, vlan_name, self_name, floating_name, standby, isActive, rollback_tmsh_list)

    if isInternalVlanCreated and is_valid_ip_network(net_internal):
        vlan_name = "Internal_vlan" + net_internaltag
        self_name = "Internal_selfip_vlan" + net_internaltag
        floating_name = "Internal_floatingip_vlan" + net_internaltag
        floatingip = extract_floating_address(net_internal)
        standby = extract_standby_address(net_internal)
        generate_net_gateway(net_internal, floatingip, vlan_name, self_name, floating_name, standby, isActive, rollback_tmsh_list)

def generate_net_scripts(config, rollback_tmsh_list):
    # Current comment out itertor all VIP, Pool Member IP, SNATPool Member IP and generate netscript
    #itertor_and_generate_net_scripts(config)

    net_external = config['external']
    net_externaltag = config['externalvlan']
    net_externaltrunk = config['externaltrunk']
    net_internal = config['internal'] 
    net_internaltag = config['internalvlan'] 
    net_internaltrunk = config['internaltrunk']

    isExternalVlanCreated = False
    isInternalVlanCreated = False

    print("---- 一号机网络配置 ----")
    generate_net_scripts_with_flag(net_externaltag, net_externaltrunk, net_internaltag, net_internaltrunk, net_external, net_internal, True, rollback_tmsh_list)

    print("---- 二号机网络配置 ----")
    generate_net_scripts_with_flag(net_externaltag, net_externaltrunk, net_internaltag, net_internaltrunk, net_external, net_internal, False, rollback_tmsh_list)


def generate_vs_exist(vs_name, pool_name, snat_name, dict, rollback_tmsh_list):
    isPoolCreated = False
    isSnatCreated = False

    if is_pool_exist(pool_name, dict):
        pool_generator_modify_add_memebers(pool_name, dict, rollback_tmsh_list)
    else:
        isPoolCreated = poolGenerator(pool_name, dict, rollback_tmsh_list)

    if is_snatpool_exist(snat_name, dict):
        snat_generator_modify_add_memebers(snat_name, dict, rollback_tmsh_list)
    else:
        isSnatCreated = snatGenerator(snat_name, dict, rollback_tmsh_list)


    if(isPoolCreated and isSnatCreated):
        vs_generator_modify_reference_pool_snat(vs_name, pool_name, snat_name, rollback_tmsh_list)
    elif(isPoolCreated and ~isSnatCreated):
        vs_generator_modify_reference_pool(vs_name, pool_name, rollback_tmsh_list)
    elif(~isPoolCreated and isSnatCreated):
        vs_generator_modify_reference_snat(vs_name, snat_name, rollback_tmsh_list)    


def generate_vs_not_exist(vs_name, pool_name, snat_name, dict, rollback_tmsh_list):

    isPoolCreated = poolGenerator(pool_name, dict, rollback_tmsh_list)
    isSnatCreated = snatGenerator(snat_name, dict, rollback_tmsh_list)

    if(isPoolCreated and isSnatCreated):
        vsGenerator(vs_name, pool_name, snat_name, dict['ip'], dict['port'], dict['protocol'], rollback_tmsh_list)
    elif(isPoolCreated and ~isSnatCreated):
        vsGeneratorPoolOnly(vs_name, pool_name, dict['ip'], dict['port'], dict['protocol'], rollback_tmsh_list)
    elif(~isPoolCreated and isSnatCreated):
        vsGeneratorSnatOnly(vs_name, snat_name, dict['ip'], dict['port'], dict['protocol'], rollback_tmsh_list)
    else:
        vsGeneratorVSOnly(vs_name, dict['ip'], dict['port'], dict['protocol'], rollback_tmsh_list)


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
    first_later_list = pinyin(dict['name'], style=Style.NORMAL)
    prefix = listToString(first_later_list) + "_" + dict['ip'] + "_" + str(dict['port']) + "_"
    vs_name = prefix + "vs"
    pool_name = prefix + "pool"
    snat_name = prefix + "snat"

    rollback_tmsh_list = []

    generate_net_scripts(dict, rollback_tmsh_list)
    print("----  业务变更配置  ----")
    if is_vs_exist(vs_name, dict):
        vs_name = dict['existed_vs_name']
        if dict['existed_pool_name'] is not None:
            pool_name = dict['existed_pool_name'] 
        if dict['existed_snatpool_name'] is not None:
            snat_name = dict['existed_snatpool_name']
        generate_vs_exist(vs_name, pool_name, snat_name, dict, rollback_tmsh_list)
    else:
        generate_vs_not_exist(vs_name, pool_name, snat_name, dict, rollback_tmsh_list)

    sync_group_name = dict['syncgroup']
    generate_save_sync(dict, sync_group_name)

    print("----  变更回退配置  ----")
    num = len(rollback_tmsh_list) - 1
    for num in range(num, -1 , -1):
        print(rollback_tmsh_list[num])
    generate_save_sync(dict, sync_group_name)


def load_bigip_running_config(fileconfig):
    with open(fileconfig, 'r') as fo:
        data_all = fo.read()

    data_all = data_all.replace('[m','')
    data_all = data_all.replace('[K', '')
    error = re.findall(r'\[7m---\(less (\d+)',data_all)
    for i in error:
        error1 = '[7m---(less '+i
        data_all = data_all.replace(error1, '')
    fo.close()
    return data_all



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
k_internaltrunk = 'internaltrunk'
k_external = 'external地址'
k_externalvlan = 'externalvlan'
k_externaltrunk = 'externaltrunk'

running_config = load_bigip_running_config(fileconfig)
testresults = configParse.parse(running_config)
