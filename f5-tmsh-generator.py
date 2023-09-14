#!/usr/bin/python3

import sys
import ast
import re
import socket
import ipaddress

from f5bigip import configParse
from f5bigip import tmsh
from pypinyin import pinyin, Style


def generator_tmsh_create_ltm_pool(name, dict, rollback_tmsh_list):
    if("serverlist" in dict and "serverport" in dict):
        serlist = dict['serverlist']
        serport = dict['serverport']
        members = ""
        for ip in serlist:
            member = " " + ip + ":" + str(serport)
            members += member
        pool_create = tmsh.get('tmsh', 'create.ltm.pool').replace("${replace.pool.name}", name).replace("${replace.pool.members}", members)
        pool_delete = tmsh.get('tmsh', 'delete.ltm.pool').replace("${replace.pool.name}", name)
        print(pool_create)
        rollback_tmsh_list.append(pool_delete)
        dict['create_ltm_pool'] = True
        return True
    else:
        return False


def generator_tmsh_modify_ltm_pool(name, dict, rollback_tmsh_list):
    members = dict['existed_pool_members']
    isPoolNotEmpty = True
    isMemberAdded = False
    if("serverlist" in dict and "serverport" in dict):
        serlist = dict['serverlist']
        serport = dict['serverport']
        if len(serlist) <= 1 and serlist[0] == "":
            isPoolNotEmpty = False

        pool_members = ""
        for ip in serlist:
            member = ip + ":" + str(serport)
            if member not in members:
                pool_members += member
                pool_members += " "
                isMemberAdded = True
 
        pool_members_add = tmsh.get('tmsh', 'modify.ltm.pool').replace("${replace.pool.name}", name).replace("${replace.pool.members}", pool_members)
        pool_members_del = tmsh.get('tmsh', 'modify.ltm.pool.rollback').replace("${replace.pool.name}", name).replace("${replace.pool.members}", pool_members)

        if isPoolNotEmpty and isMemberAdded:
            print(pool_members_add)
            rollback_tmsh_list.append(pool_members_del)


def generator_tmsh_create_ltm_snatpool(name, dict, rollback_tmsh_list):
    if("snatpoollist" in dict):
        snatlist = dict['snatpoollist']
        snat = "tmsh create ltm snatpool " + name + " members add {"
        members = ""
        for ip in snatlist:
            member = " " + ip
            members += member
        # BIG-IP DO NOT SUPPORT CREATE A SNATPOOL WITH ZERO MEMBERS
        # MINIMUM LENGTH OF A IPV4 IS 7
        if len(members) > 7:
            snat_create = tmsh.get('tmsh', 'create.ltm.snatpool').replace("${replace.snatpool.name}", name).replace("${replace.snatpool.members}", members)
            snat_delete = tmsh.get('tmsh', 'delete.ltm.snatpool').replace("${replace.snatpool.name}", name)
            print(snat_create)
            rollback_tmsh_list.append(snat_delete)
            dict['create_ltm_snatpool'] = True
            return True
        else:
            return False
    else:
        return False


def generator_tmsh_modify_ltm_snatpool(snat_name, dict, rollback_tmsh_list):
    members = dict['existed_snatpool_members']
    isSNATPoolNotEmpty = True
    isMemberAdded = False
    if("snatpoollist" in dict):
        snatlist = dict['snatpoollist']
        if len(snatlist) == 1 and snatlist[0] == "":
            isSNATPoolNotEmpty = False
        
        snat = ""
        for ip in snatlist: 
            if ip not in members:
                member = " " + ip
                snat += member
                isMemberAdded = True

        if isSNATPoolNotEmpty and isMemberAdded:
            snat_members_add = tmsh.get('tmsh', 'modify.ltm.snatpool').replace("${replace.snatpool.name}", snat_name).replace("${replace.snatpool.members}", snat)
            snat_members_del = tmsh.get('tmsh', 'modify.ltm.snatpool.rollback').replace("${replace.snatpool.name}", snat_name).replace("${replace.snatpool.members}", snat)
            print(snat_members_add)
            rollback_tmsh_list.append(snat_members_del)


def generator_tmsh_persist(persistname, protocol, dict, rollback_tmsh_list):
    results = is_persist_exist(persistname, dict)
    if results == False and protocol == "tcp":
        tmsh_persist_create = tmsh.get('tmsh', 'create.ltm.persist').replace("${replace.persist.type}", "source-addr").replace("${replace.persist.name}", persistname).replace("${replace.persist.timeout}", "300")
        tmsh_persist_delete = tmsh.get('tmsh', 'delete.ltm.persist').replace("${replace.persist.type}", "source-addr").replace("${replace.persist.name}", persistname)
        print(tmsh_persist_create)
        rollback_tmsh_list.append(tmsh_persist_delete)        
    elif results == False and protocol == "http":
        tmsh_persist_create = tmsh.get('tmsh', 'create.ltm.persist.http').replace("${replace.persist.name}", persistname)
        tmsh_persist_delete = tmsh.get('tmsh', 'delete.ltm.persist').replace("${replace.persist.type}", "cookie").replace("${replace.persist.name}", persistname)    
        print(tmsh_persist_create)
        rollback_tmsh_list.append(tmsh_persist_delete)


def form_persist_name(protocol, dict, rollback_tmsh_list):
    persistname = config['persistname']
    if len(persistname) <= 0 and protocol == "tcp":
        return "source_addr"
    elif len(persistname) <= 0 and protocol == "http":
        return "cookie"
    else:
        generator_tmsh_persist(persistname, protocol, dict, rollback_tmsh_list)
        return persistname


def generator_tmsh_create_ltm_virtual(vs_name, pool_name, snat_name, addr, port, protocol, rollback_tmsh_list, dict):
    
    vs_create = None
    
    destination = addr + ":" + str(port)
    key_pool = 'create_ltm_pool'
    key_snat = 'create_ltm_snatpool'
    persist_name = form_persist_name(protocol, dict, rollback_tmsh_list)
    
    if key_pool in dict and key_snat in dict and dict[key_pool] and dict[key_snat] and protocol == "tcp" and dict['syslist'][0] > 10:
        vs_create = form_create_ltm_tmsh('create.ltm.virtual.tcp', vs_name, pool_name, snat_name, destination, persist_name)
    elif key_pool in dict and key_snat in dict and dict[key_pool] and dict[key_snat] and protocol == "tcp" and dict['syslist'][0] <= 10:
        vs_create = form_create_ltm_tmsh('create.ltm.virtual.tcp.legacy', vs_name, pool_name, snat_name, destination, persist_name)
    elif key_pool in dict and key_snat in dict and dict[key_pool] and dict[key_snat] and protocol == "http" and dict['syslist'][0] >= 12:
        vs_create = form_create_ltm_tmsh('create.ltm.virtual.http', vs_name, pool_name, snat_name, destination, persist_name)
    elif key_pool in dict and key_snat in dict and dict[key_pool] and dict[key_snat] and protocol == "http" and dict['syslist'][0] == 11:
        vs_create = form_create_ltm_tmsh('create.ltm.virtual.http.legacy', vs_name, pool_name, snat_name, destination, persist_name)
    elif key_pool in dict and key_snat in dict and dict[key_pool] and dict[key_snat] and protocol == "http" and dict['syslist'][0] <= 10:
        vs_create = form_create_ltm_tmsh('create.ltm.virtual.http.legacy.old', vs_name, pool_name, snat_name, destination, persist_name)
    elif key_pool in dict and key_snat not in dict and dict[key_pool] and protocol == "tcp" and dict['syslist'][0] > 10:
        vs_create = form_create_ltm_tmsh_nosnat('create.ltm.virtual.tcp.nosnat', vs_name, pool_name, destination, persist_name)
    elif key_pool in dict and key_snat not in dict and dict[key_pool] and protocol == "tcp" and dict['syslist'][0] <= 10:
        vs_create = form_create_ltm_tmsh_nosnat('create.ltm.virtual.tcp.legacy.nosnat', vs_name, pool_name, destination, persist_name)
    elif key_pool in dict and key_snat not in dict and dict[key_pool] and protocol == "http" and dict['syslist'][0] >= 12:
        vs_create = form_create_ltm_tmsh_nosnat('create.ltm.virtual.http.nosnat', vs_name, pool_name, destination, persist_name)
    elif key_pool in dict and key_snat not in dict and dict[key_pool] and protocol == "http" and dict['syslist'][0] < 12:
        vs_create = form_create_ltm_tmsh_nosnat('create.ltm.virtual.http.legacy.nosnat', vs_name, pool_name, destination, persist_name)
    elif key_pool not in dict and key_snat in dict and dict[key_snat] and protocol == "tcp" and dict['syslist'][0] > 10:
        vs_create = form_create_ltm_tmsh_nopool('create.ltm.virtual.tcp.nopool', vs_name, snat_name, destination, persist_name)
    elif key_pool not in dict and key_snat in dict and dict[key_snat] and protocol == "tcp" and dict['syslist'][0] <= 10:
        vs_create = form_create_ltm_tmsh_nopool('create.ltm.virtual.tcp.legacy.nopool', vs_name, snat_name, destination, persist_name)
    elif key_pool not in dict and key_snat in dict and dict[key_snat] and protocol == "http" and dict['syslist'][0] >= 12:
        vs_create = form_create_ltm_tmsh_nopool('create.ltm.virtual.http.nopool', vs_name, snat_name, destination, persist_name)
    elif key_pool not in dict and key_snat in dict and dict[key_snat] and protocol == "http" and dict['syslist'][0] == 11:
        vs_create = form_create_ltm_tmsh_nopool('create.ltm.virtual.http.legacy.nopool', vs_name, snat_name, destination, persist_name)
    elif key_pool not in dict and key_snat in dict and dict[key_snat] and protocol == "http" and dict['syslist'][0] <= 10:
        vs_create = form_create_ltm_tmsh_nopool('create.ltm.virtual.http.legacy.nopool.old', vs_name, snat_name, destination, persist_name)
    elif key_pool not in dict and key_snat not in dict and protocol == "tcp":
        vs_create =  form_create_ltm_tmsh_nopool_nosnat('create.ltm.virtual.tcp.nopool.nosnat', vs_name, destination, persist_name)
    elif key_pool not in dict and key_snat not in dict and protocol == "http" and dict['syslist'][0] >= 12:
        vs_create =  form_create_ltm_tmsh_nopool_nosnat('create.ltm.virtual.http.nopool.nosnat', vs_name, destination, persist_name)
    elif key_pool not in dict and key_snat not in dict and protocol == "http" and dict['syslist'][0] < 12:
        vs_create =  form_create_ltm_tmsh_nopool_nosnat('create.ltm.virtual.http.legacy.nopool.nosnat', vs_name, destination, persist_name)

    vs_delete = tmsh.get('tmsh', 'delete.ltm.virtual').replace("${replace.virtual.name}", vs_name)
 
    if vs_create is not None:
        print(vs_create)
        rollback_tmsh_list.append(vs_delete)



def generator_tmsh_modify_ltm_virtual(vs_name, pool_name, snat_name, rollback_tmsh_list, dict):

    vs_modify = None
    vs_rollback = None

    key_pool = 'create_ltm_pool'
    key_snat = 'create_ltm_snatpool'

    if key_pool in dict and key_snat in dict and dict[key_pool] and dict[key_snat] and dict['syslist'][0] > 10:
        vs_modify = form_modify_ltm_tmsh('modify.ltm.virtual', vs_name, pool_name, snat_name)
        vs_rollback = form_modify_ltm_tmsh_rollback('modify.ltm.virtual.rollback', vs_name)
    elif key_pool in dict and key_snat in dict and dict[key_pool] and dict[key_snat] and dict['syslist'][0] <= 10:
        vs_modify = form_modify_ltm_tmsh('modify.ltm.virtual.legacy', vs_name, pool_name, snat_name)
        vs_rollback = form_modify_ltm_tmsh_rollback('modify.ltm.virtual.legacy.rollback', vs_name)
    elif key_pool in dict and key_snat not in dict and dict[key_pool]:
        vs_modify = tmsh.get('tmsh', 'modify.ltm.virtual.nosnat').replace("${replace.virtual.name}", vs_name).replace("${replace.pool.name}", pool_name)
        vs_rollback = form_modify_ltm_tmsh_rollback('modify.ltm.virtual.nosnat.rollback', vs_name)
    elif key_pool not in dict and key_snat in dict and dict[key_snat] and dict['syslist'][0] > 10:
        vs_modify = form_modify_ltm_tmsh_nopool('modify.ltm.virtual.nopool', vs_name, snat_name)
        vs_rollback = form_modify_ltm_tmsh_rollback('modify.ltm.virtual.nopool.rollback', vs_name)
    elif key_pool not in dict and key_snat in dict and dict[key_snat] and dict['syslist'][0] <= 10:
        vs_modify = form_modify_ltm_tmsh_nopool('modify.ltm.virtual.legacy.nopool', vs_name, snat_name)
        vs_rollback = form_modify_ltm_tmsh_rollback('modify.ltm.virtual.legacy.nopool.rollback', vs_name)

    if vs_modify is not None and vs_rollback is not None:
        print(vs_modify)
        rollback_tmsh_list.append(vs_rollback)


def form_modify_ltm_tmsh_rollback(key, vs_name):
    return tmsh.get('tmsh', key).replace("${replace.virtual.name}", vs_name)

def form_modify_ltm_tmsh_nopool(key, vs_name, snat_name):
    return tmsh.get('tmsh', key).replace("${replace.virtual.name}", vs_name).replace("${replace.snatpool.name}", snat_name)

def form_modify_ltm_tmsh(key, vs_name, pool_name, snat_name):
    return tmsh.get('tmsh', key).replace("${replace.virtual.name}", vs_name).replace("${replace.pool.name}", pool_name).replace("${replace.snatpool.name}", snat_name)

def form_create_ltm_tmsh(key, vs_name, pool_name, snat_name, destination, persist_name):
    return tmsh.get('tmsh', key).replace("${replace.virtual.name}", vs_name).replace("${replace.virtual.destination}", destination).replace("${replace.pool.name}", pool_name).replace("${replace.snatpool.name}", snat_name).replace("${replace.virtual.persist}", persist_name)

def form_create_ltm_tmsh_nosnat(key, vs_name, pool_name, destination, persist_name):
    return tmsh.get('tmsh', key).replace("${replace.virtual.name}", vs_name).replace("${replace.virtual.destination}", destination).replace("${replace.pool.name}", pool_name).replace("${replace.virtual.persist}", persist_name)

def form_create_ltm_tmsh_nopool(key, vs_name, snat_name, destination, persist_name):
    return tmsh.get('tmsh', key).replace("${replace.virtual.name}", vs_name).replace("${replace.virtual.destination}", destination).replace("${replace.snatpool.name}", snat_name).replace("${replace.virtual.persist}", persist_name)

def form_create_ltm_tmsh_nopool_nosnat(key, vs_name, destination, persist_name):
    return tmsh.get('tmsh', key).replace("${replace.virtual.name}", vs_name).replace("${replace.virtual.destination}", destination).replace("${replace.virtual.persist}", persist_name)


def is_vs_exist(vs_name, dict):
    infolist = dict['infolist']
    vs_ip = dict['ip']
    vs_port = dict['port']
    for info in infolist:
        if info[1] == vs_ip and info[2] == vs_port:
            dict['existed_vs_name'] = info[0] 
            dict['existed_pool_name'] = info[3]
            dict['existed_pool_members'] = info[4]
            dict['existed_snatpool_name'] = info[5]
            dict['existed_snatpool_members'] = info[5]
            return True
    return False

def is_persist_exist(persist_name, dict):
    infolist = dict['infolist']
    for info in infolist:
        if info[7] == persist_name:
            return True
    return False         

def generate_save_sync(dict, sync_group_name):

    config_save = tmsh.get('tmsh', 'save.sys.config')
    print(config_save)

    if sync_group_name is not None and dict['syslist'][0] > 10:
        config_sync = tmsh.get('tmsh', 'run.cm.config.sync').replace("${replace.sync.group.name}", sync_group_name)
        print(config_sync)
    elif dict['syslist'][0] <= 10:
        config_sync = tmsh.get('tmsh', 'run.cm.config.sync.legacy')
        print(config_sync)



'''
Generate Network Script Start, related fucntion:
    
    generate_net_scripts()
    generate_net_scripts_with_flag()
    generate_net_vlan()
    extract_floating_address()
    extract_standby_address()
    generate_net_gateway()
'''
def is_net_exists(ip, netlist):
    for n in netlist:
        if ipaddress.ip_address(ip) in ipaddress.ip_network(n, False):
            return True
    return False


def is_valid_ip_network(address):
    try:
        ipaddress.ip_network(address, False)
        return True
    except ValueError:
        return False


def generate_net_vlan(vlan_name, trunk, tag, rollback_tmsh_list, isActive):
    vlan_create = tmsh.get('tmsh', 'create.net.vlan').replace("${replace.vlan.name}", vlan_name).replace("${replace.vlan.trunk}", trunk).replace("${replace.vlan.tag}", tag) 
    vlan_delete = tmsh.get('tmsh', 'delete.net.vlan').replace("${replace.vlan.name}", vlan_name)
    print(vlan_create)
    if isActive:
        rollback_tmsh_list.append(vlan_delete)

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
    tmsh_self = tmsh.get('tmsh', 'create.net.self').replace("${replace.self.name}", self_name).replace("${replace.self.address}", self).replace("${replace.self.vlan}", vlan_name)
    tmsh_self_rollback = tmsh.get('tmsh', 'delete.net.self').replace("${replace.self.name}", self_name)
    tmsh_standby = tmsh.get('tmsh', 'create.net.self').replace("${replace.self.name}", self_name).replace("${replace.self.address}", standby).replace("${replace.self.vlan}", vlan_name)
    tmsh_floating = tmsh.get('tmsh', 'create.net.self.floating').replace("${replace.self.name}", floating_name).replace("${replace.self.address}", floating).replace("${replace.self.vlan}", vlan_name)
    tmsh_floating_rollback = tmsh.get('tmsh', 'delete.net.self').replace("${replace.self.name}", floating_name)
    if isActive:
        print(tmsh_self)
        rollback_tmsh_list.append(tmsh_self_rollback)
        rollback_tmsh_list.append(tmsh_floating_rollback)
    else:
        print(tmsh_standby)
    print(tmsh_floating)


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
'''
Generate Network Script End
'''



def generate_vs_exist(vs_name, pool_name, snat_name, dict, rollback_tmsh_list):

    if dict['existed_pool_name'] is None:
        generator_tmsh_create_ltm_pool(pool_name, dict, rollback_tmsh_list)
    else:
        generator_tmsh_modify_ltm_pool(pool_name, dict, rollback_tmsh_list)

    if dict['existed_snatpool_name'] is None:
        generator_tmsh_create_ltm_snatpool(snat_name, dict, rollback_tmsh_list)
    else:
        generator_tmsh_modify_ltm_snatpool(snat_name, dict, rollback_tmsh_list)

    generator_tmsh_modify_ltm_virtual(vs_name, pool_name, snat_name, rollback_tmsh_list, dict)



def generate_vs_not_exist(vs_name, pool_name, snat_name, dict, rollback_tmsh_list):

    generator_tmsh_create_ltm_pool(pool_name, dict, rollback_tmsh_list)
    generator_tmsh_create_ltm_snatpool(snat_name, dict, rollback_tmsh_list)
    generator_tmsh_create_ltm_virtual(vs_name, pool_name, snat_name, dict['ip'], dict['port'], dict['protocol'], rollback_tmsh_list, dict)



'''
The endpoint of tmsh generator, generate tmsh for create vs/pool/snat/profile/health/monitor via a dictionary

The dictionary should contains the following key:

  ip       - VS ip
  port     - VS port
  protocol - VS Protocol
  netset   - show running-config contained network
  infolist - show running-config contained VS/Pool/Snat Info
  syslist  - show running-config contained software version and divice group 
  
'''
def generate(dict):
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

    sync_group_name = dict['syslist'][1]
    generate_save_sync(dict, sync_group_name)

    print("----  变更回退配置  ----")
    num = len(rollback_tmsh_list) - 1
    for num in range(num, -1 , -1):
        print(rollback_tmsh_list[num])
    generate_save_sync(dict, sync_group_name)


def listToString(s):
    result = ""
    for l in s:
        item = l[0]
        item = item[0].upper() + item[1:]
        result += item
    return result

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


'''
Function used to load application requestion table as dict, related fucntion:

    load_app_request_form()
    format_app_table_ip_addr_to_list()
    format_app_table_ip_addr()
    find_last_index()
'''
def find_last_index(str, substr):
    last_index = -1
    while True:
        index = str.find(substr, last_index + 1)
        if index == -1:
            return last_index
        last_index = index

def format_app_table_ip_addr(ip):
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

def format_app_table_ip_addr_to_list(ip):
    list = []
    if("," in ip) :
        ips = ip.split(",")
        for i in ips:
            list.extend(format_app_table_ip_addr(i))
    else:
        list = format_app_table_ip_addr(ip)
    return list

def load_app_request_form(fileadd):
    config_list = []
    with open(fileadd, "r") as file:
        for line in file:
            line = line.replace('[', '{').replace(']', '}')
            dict = ast.literal_eval(line)
            config = {'name': dict[k_name], 'ip': dict[k_vip], 'port': dict[k_vport], 'protocol': dict[k_protocol]}
            config['serverlist'] = format_app_table_ip_addr_to_list(dict[k_serveraddr])
            config['serverport'] = dict[k_serverport]
            config['snatpoollist'] = format_app_table_ip_addr_to_list(dict[k_snataddr])
            config['internal'] = dict[k_internal]
            config['internalvlan'] = dict[k_internalvlan]
            config['internaltrunk'] = dict[k_internaltrunk]
            config['external'] = dict[k_external]
            config['externalvlan'] = dict[k_externalvlan]
            config['externaltrunk'] = dict[k_externaltrunk]
            config['persistname'] = dict[k_persist]
            config_list.append(config)
    file.close
    return config_list
'''
Function used to load application requestion table as dict end
'''


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
k_persist = '会话保持'
k_internal = 'internal地址'
k_internalvlan = 'internalvlan'
k_internaltrunk = 'internaltrunk'
k_external = 'external地址'
k_externalvlan = 'externalvlan'
k_externaltrunk = 'externaltrunk'

config_list = load_app_request_form(fileadd)
running_config = load_bigip_running_config(fileconfig)
infolists = configParse.existinfolist(running_config)

for config in config_list:
    config['infolist'] = infolists[0]
    config['netset'] = infolists[1]
    config['syslist'] = infolists[2]
    generate(config)

