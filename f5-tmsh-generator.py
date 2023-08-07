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
    elif protocol == "http" and BIGIP_TMOS_VERSION >= 13:
        return "profiles add { http { } } service-down-immediate-action reset"
    elif protocol == "http" and BIGIP_TMOS_VERSION < 13:
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
    vs_rollback = "tmsh modify ltm virtual " + vs_name + " pool none"
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

def data_collect_device_group(data_all):
    sync_group_name_data = re.findall(r'cm device-group\s+\S+',data_all, re.I)
    sync_group_list = []
    for i in sync_group_name_data:
        sync_group_list.append(i)

    sync_group_name = None
    for i,num in zip(sync_group_name_data, range(len(sync_group_name_data))):
        if num < len(sync_group_list) - 1:
            sync_group_data_start = re.search(i, data_all, re.I).start()
            sync_group_data_end = re.search(sync_group_list[num+1], data_all[sync_group_data_start:]).start()
            sync_group_data_detail = data_all[sync_group_data_start:][:sync_group_data_end]
        else:
            sync_group_data_start = re.search(i, data_all, re.I).start()
            sync_group_data_end = re.search(r'cm key', data_all[sync_group_data_start:]).start()
            sync_group_data_detail = data_all[sync_group_data_start:][:sync_group_data_end]
        if "sync-failover" in sync_group_data_detail:
            sync_group_name = sync_group_list[num]
            sync_group_name = sync_group_name[len("cm device-group"):]
            sync_group_name = sync_group_name.strip()
            break
    return sync_group_name

def trip_prefix(line, prefix):
    if len(line) > 0 and prefix in line:
        return line.strip().lstrip(prefix).strip()
    else:
        return line

def find_content_from_start_end(data, start_str, end_str):
    data_start = re.search(start_str, data, re.I).start() 
    data_end = re.search(end_str, data[data_start:], re.I).start()
    return data[data_start:][:data_end]

def data_collect_system_extract_version(data_all):
    ha_devices_data = find_content_from_start_end(data_all, "cm device", "cm device-group")
    ha_devices = ha_devices_data.split("cm device")
    version = None
    for device in ha_devices:
        if len(device) > 10:
            lines = device.splitlines()
            version = None
            for l in lines:
                line = l.strip()
                if line.startswith("version"):
                    version = trip_prefix(line, "version")

    return version

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
            
    sync_group_name_result = data_collect_device_group(data_all)

    software_version = data_collect_system_extract_version(data_all)

    return (net_list, info_list, sync_group_name_result, software_version)


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

BIGIP_TMOS_VERSION = 0

with open(fileadd, "r") as file:
    config_results = data_collect(fileconfig)

    software_version = config_results[3]
    if software_version.startswith("10"):
        BIGIP_TMOS_VERSION = 10
    elif software_version.startswith("11"):
        BIGIP_TMOS_VERSION = 11
    elif software_version.startswith("12"):
        BIGIP_TMOS_VERSION = 12
    elif software_version.startswith("13"):
        BIGIP_TMOS_VERSION = 13
    elif software_version.startswith("14"):
        BIGIP_TMOS_VERSION = 14
    elif software_version.startswith("15"):
        BIGIP_TMOS_VERSION = 15
    elif software_version.startswith("16"):
        BIGIP_TMOS_VERSION = 16
    elif software_version.startswith("17"):
        BIGIP_TMOS_VERSION = 17

    for line in file:
        line = line.replace('[', '{').replace(']', '}')
        dict = ast.literal_eval(line)
        config = {'name': dict[k_name], 'ip': dict[k_vip], 'port': dict[k_vport], 'protocol': dict[k_protocol]}
        config['serverlist'] = format_ip_addr_list(dict[k_serveraddr])
        config['serverport'] = dict[k_serverport]
        config['snatpoollist'] = format_ip_addr_list(dict[k_snataddr])
        config['internal'] = dict[k_internal]
        config['internalvlan'] = dict[k_internalvlan]
        config['internaltrunk'] = dict[k_internaltrunk]
        config['external'] = dict[k_external]
        config['externalvlan'] = dict[k_externalvlan]
        config['externaltrunk'] = dict[k_externaltrunk]
        config['netlist'] = config_results[0]
        config['infolist'] = config_results[1]
        config['syncgroup'] = config_results[2]
        generateNewVirtualServer(config)
