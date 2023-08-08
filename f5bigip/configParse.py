#!/usr/bin/python3

import sys
import ast
import re
import socket
import ipaddress

class BIGIPDevice:
    def __init__(self, configsync_ip, failover_state, hostname, management_ip, self_device, time_zone, unicast_address, unicast_port, version):
        self.configsync_ip = configsync_ip
        self.failover_state = failover_state
        self.hostname = hostname
        self.management_ip = management_ip
        self.self_device = self_device
        self.time_zone = time_zone
        self.unicast_address = unicast_address
        self.unicast_port = unicast_port
        self.version = version

class BIGIPAuthUser:
    def __init__(self, name, role, shell):
        self.name = name
        self.role = role
        self.shell = shell


class BIGIPVS:
    def __init__(self, vs_name, vs_ip, vs_port, vs_mask, ip_protocol, pool, profiles, rules, persist, serviceDownReset, vlans, snatpool, snatType):
        self.vs_name = vs_name
        self.vs_ip = vs_ip
        self.vs_port = vs_port
        self.vs_mask = vs_mask
        self.ip_protocol = ip_protocol
        self.pool = pool
        self.profiles = profiles
        self.rules = rules
        self.persist = persist
        self.serviceDownReset = serviceDownReset
        self.vlans = vlans
        self.snatpool = snatpool
        self.snatType = snatType

class BIGIPPool:
    def __init__(self, name, lb_methods, members, monitor):
        self.name = name
        self.lb_methods = lb_methods
        self.members = members
        self.monitor = monitor

class BIGIPPoolMember:
    def __init__(self, member, address, port, session, state, connectionlimit):
        self.member = member
        self.address = address
        self.port = port
        self.session = session
        self.state = state
        self.connectionlimit = connectionlimit

class BIGIPNode:
    def __init__(self, name, address, monitor, session, state):
        self.name = name
        self.address = address
        self.monitor = monitor
        self.session = session
        self.state = state

class BIGIPProfile:
    def __init__(self, name, parent):
        self.name = name
        self.parent = parent

class BIGIPProfileFastl4(BIGIPProfile):
    def __init__(self, name, parent, idle_timeout, tcp_handshake_timeout):
        super().__init__(name, parent)
        self.idle_timeout = idle_timeout
        self.tcp_handshake_timeout = tcp_handshake_timeout

class BIGIPProfileHttp(BIGIPProfile):
    def __init__(self, name, parent, xff):
        super().__init__(name, parent)
        self.xff = xff

class BIGIPSnatPool:
    def __init__(self, name, members):
        self.name = name
        self.members = members




def trip_prefix(line, prefix):
    if len(line) > 0 and prefix is not None and prefix in line:
        return line.strip().lstrip(prefix).strip()
    else:
        return line.strip()

def find_content_from_start_end(data, start_str, end_str):

    if start_str not in data:
        return ""

    data_start = re.search(start_str, data, re.I).start()
    if end_str is None:
        return data[data_start:]
    data_end = re.search(end_str, data, re.I).start()
    return data[data_start:data_end]
    #data_end = re.search(end_str, data[data_start:], re.I).start()
    #return data[data_start:][:data_end] 

def find_content_from_start(data, start_str):
    data_start = re.search(start_str, data, re.I).start()
    line = data[:data_start]
    return trip_prefix(line, None)

def find_line_content_from_start_str(data, prefix):
    lines = data.splitlines()
    for l in lines:
        line = l.strip()
        if line.startswith(prefix):
            return trip_prefix(line, prefix.strip())
    return None

def split_destination(destination):
    destination_array = destination.split(":")
    ip = destination_array[0]
    port = convert_servicename_to_port(destination_array[1])
    return (ip, port)

def replace_with_patterns(data, patterns):
    for pattern in patterns:
        data = data.replace(pattern, "")
    return data


def convert_servicename_to_port(input):
    if input in f5_services_dict:
        return f5_services_dict[input]
    elif input == 'any':
        return '0'
    elif isinstance(input, str):
        try:
            return socket.getservbyname(input)
        except OSError:
            return input
    else:
        return input 


'''
Split a large content to small block base on re pattern, return each blocks as a content list.

    data_all - original data
    pattern  - re pattern
    end_str  - the end of big blok

eg, the following content

    ltm node 192.168.32.158 { }
    ltm node 192.168.32.174 { }
    ltm node 192.168.33.46 { }
    ltm persistence global-settings { }
   
the data_all is the above 4 lines, the pattern is 
    r'ltm node\s+\S+'
and the end_str is
    'ltm persistence'

The final return results is ['ltm node 192.168.32.158 { }', 'ltm node 192.168.32.174 { }', ltm node 192.168.33.46 { }]
'''
def split_content_to_list(data_all, pattern, end_str):
    results = []
    content_list = []
    content_data = re.findall(pattern, data_all, re.I)
    for i in content_data:
        content_list.append(i)

    for i, num in zip(content_data, range(len(content_data))):
        data_start = re.search(i, data_all, re.I).start()
        if num < len(content_list) - 1:
            data_detail = find_content_from_start_end(data_all[data_start:], i, content_list[num+1])
        else:
            data_detail = find_content_from_start_end(data_all[data_start:], i, end_str)

        results.append(data_detail)

    return results



def data_collect_system_extract_hostname(data_all):

    management_ip = None
    hostname = None

    matches = re.search(r'sys management-ip\s+(\S+)', data_all, re.I)
    if matches:
        management_ipr_raw = matches.group()
        management_ip = management_ipr_raw.lstrip("sys management-ip").strip()        

    pattern = r"sys global-settings(.*?)}"
    blocks = re.findall(pattern, data_all, re.DOTALL)
    if len(blocks) >= 1:
        content = blocks[0]
        hostname_list = re.search(r'hostname\s+(\S+)', content, re.I)
        if hostname_list:
            hostname_raw = hostname_list.group()
            hostname = hostname_raw.lstrip("hostname").strip()

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

    return (hostname, management_ip, version)




'''
[f5bigip % configParse.py] Parse running config data to form profiles related functions:

    extract_http_profile()
    extract_fastl4_profile()
'''
def extract_http_profile(data_all):
    http_profile_results = []
    results = split_content_to_list(data_all, r'ltm profile http\s+\S+', "}")
    for i in results:
        profile = i.lstrip("ltm profile http").replace("{", "").replace("}", "") 
        lines = profile.splitlines()
        profile_name = lines[0].strip()
        profile_parent = None
        profile_xff = None
        for l in lines:
            line = l.strip()
            if line.startswith("defaults-from"):
                profile_parent = trip_prefix(line, "defaults-from")
            elif line.startswith("insert-xforwarded-for"):
                profile_xff = trip_prefix(line, "insert-xforwarded-for")
        http_profile_results.append(BIGIPProfileHttp(profile_name, profile_parent, profile_xff))
    return http_profile_results

def extract_fastl4_profile(data_all):
    fastl4_profile_results = []
    results = split_content_to_list(data_all, r'ltm profile fastl4\s+\S+', "}")
    for i in results:
        profile = i[len("ltm profile fastl4"):].replace("{", "").replace("}", "") 
        lines = profile.splitlines()
        profile_name = lines[0].strip()
        profile_parent = None
        profile_idle_timeout = None
        profile_handshake_timeout = None
        for l in lines:
            line = l.strip()
            if line.startswith("defaults-from"):
                profile_parent = trip_prefix(line, "defaults-from")
            elif line.startswith("idle-timeout"):
                profile_idle_timeout = trip_prefix(line, "idle-timeout")
            elif line.startswith("tcp-handshake-timeout"):
                profile_handshake_timeout = trip_prefix(line, "tcp-handshake-timeou")
        fastl4_profile_results.append(BIGIPProfileFastl4(profile_name, profile_parent, profile_idle_timeout, profile_handshake_timeout))
    return fastl4_profile_results
'''
[f5bigip % configParse.py] Parse running config data to form profiles end
'''


def data_collect_snatpool_list(data_all):
    snatpool_results = []
    snatpool_start_str = "ltm snatpool"
    snatpool_end_str = "ltm virtual"
    if "ltm tacdb" in data_all:
        snatpool_end_str = "ltm tacdb"
    snatpool_data_all = find_content_from_start_end(data_all, snatpool_start_str, snatpool_end_str)
    snatpool_data_list = snatpool_data_all.split("ltm snatpool")
    for i in snatpool_data_list:
        if len(i) > 0:
            snatpool_data = replace_with_patterns(i, ["members", "{", "}"])
            lines = snatpool_data.splitlines()
            snat_name = trip_prefix(lines[0], None)
            snat_members = []
            for l in lines:
                line = trip_prefix(l, None)
                if snat_name not in line and len(line) > 0:
                    snat_members.append(line)
            snatpool_results.append(BIGIPSnatPool(snat_name, snat_members))
        
    return snatpool_results




def data_collect_node_list(data_all):
    node_list = []
    node_start_str = "ltm node"
    node_end_str = "ltm pool"
    if "ltm persistence" in data_all:
        node_end_str = "ltm persistence"
    elif "ltm policy" in data_all:
        node_end_str = "ltm policy"
    node_data_all = find_content_from_start_end(data_all, node_start_str, node_end_str)
    node_data_list = node_data_all.split("ltm node")
    for i in node_data_list:
        if len(i) > 0:
            node_data = trip_prefix(replace_with_patterns(i, ["{", "}"]), None) 
            lines = node_data.splitlines()
            name = trip_prefix(lines[0], None)
            address = None
            monitor = None
            session = None
            state = None
            for l in lines:
                line = trip_prefix(l, None)
                if line.startswith("address"):
                    address = trip_prefix(line, "address")
                elif line.startswith("monitor"):
                    monitor = trip_prefix(line, "monitor")
                elif line.startswith("session"):
                    session = trip_prefix(line, "session")
                elif line.startswith("state"):
                    state = trip_prefix(line, "state")

            node_list.append(BIGIPNode(name, address, monitor, session, state))

    return node_list



'''
[f5bigip % configParse.py] Parse all Pool data as list start, related functions:

    data_collect_pool_list()
    extract_poolmember_attributes()

'''
def data_collect_pool_list(data_all):

    pool_list = []

    pool_start_str = "ltm pool"
    pool_end_str = "ltm virtual"
    if "ltm profile" in data_all:
        vs_end_str = "ltm profile"
    elif "ltm rule" in data_all:
        vs_end_str = "ltm rule"
    elif "ltm tacdb" in data_all:
        vs_end_str = "ltm tacdb"

    pool_data_all = find_content_from_start_end(data_all, pool_start_str, pool_end_str)
    pool_data_list = pool_data_all.split("ltm pool")
    for i in pool_data_list:
        if len(i) > 0:
            pool_name = find_content_from_start(i, "{")
            pool_data_all = trip_prefix(i, pool_name)
            pool_lb = None
            pool_members = pool_data_all
            if "members" in pool_data_all:
                pool_header = find_content_from_start(pool_data_all, "members")
                pool_lb = find_line_content_from_start_str(pool_header, "load-balancing-mode")
                pool_members = pool_data_all[len(pool_header):]
            pool_members_list = []
            pool_monitor = None
            separator = "monitor "
            if "min-active-members" in pool_members:
                separator = "min-active-members"

            if separator in pool_members:
                pool_members = find_content_from_start(pool_members, separator)
                pool_monitor = find_line_content_from_start_str(pool_members[len(pool_members):], "monitor") 
            
            if pool_members is not None:
                pool_members = replace_with_patterns(pool_members, ["members", "{"])            
                pool_members = pool_members.split("}")
                for m in pool_members: 
                    pool_member = extract_poolmember_attributes(m)   
                    if pool_member is not None:
                        pool_members_list.append(pool_member)

            pool_list.append(BIGIPPool(pool_name, pool_lb, pool_members_list, pool_monitor))

    return pool_list


def extract_poolmember_attributes(data_all):
    members = trip_prefix(data_all, None)
    lines = members.splitlines()
    member = None
    address = None
    port = None
    session = None
    state = None 
    connectionlimit = None
    if len(lines) > 0:
        array = split_destination(lines[0])
        member = array[0] + ":" + array[1]
        port = array[1]
    for l in lines:
        line = trip_prefix(l, None)
        if line.startswith("address"):
            address = trip_prefix(line, "address")
        elif line.startswith("session"):
            session = trip_prefix(line, "session")
        elif line.startswith("state"):
            state = trip_prefix(line, "state")
        elif line.startswith("connection-limit"):
            connectionlimit = trip_prefix(line, "connection-limit")

    if member is not None:
        return BIGIPPoolMember(member, address, port, session, state, connectionlimit)
    return None
'''
[f5bigip % configParse.py] Parse all Pool data as list - end
'''



'''
[f5bigip % configParse.py] Parse all VS data as list start, related functions:

    data_collect_vs_list()
    extract_snat_attributes()
    extract_vs_attributes()
    convert_profiles_rules_to_list()

'''
def data_collect_vs_list(data_all):
    vs_list = []

    vs_start_str = "ltm virtual"
    vs_data_all = find_content_from_start_end(data_all, vs_start_str, None)
    vs_data_list = vs_data_all.split("ltm virtual")
    for i in vs_data_list:
        if len(i) > 0:
            vs_name = None
            vs_ip = None
            vs_port = None
            vs_mask = None
            ip_protocol = None
            pool = None
            profiles = None
            rules = None
            snatpool = None
            snatType = None
            vs_data = i.strip()
            vs_attributes = None
            snat_attributes = None
            snat_search_results = re.search("source-address-translation", vs_data,re.I)
            if snat_search_results:
                snat_start = snat_search_results.start()
                vs_data_header = vs_data[0:snat_start]
                vs_data_tail = vs_data[snat_start:]
                vs_attributes = extract_vs_attributes(vs_data_header)
                snat_attributes = extract_snat_attributes(vs_data_tail)
            else:
                vs_attributes = extract_vs_attributes(vs_data)

            vs_name = vs_attributes[0]
            vs_ip = vs_attributes[1]
            vs_port = vs_attributes[2]
            vs_mask = vs_attributes[3]
            ip_protocol = vs_attributes[4]
            pool = vs_attributes[5]
            profiles = vs_attributes[6]
            rules = vs_attributes[7]
            persist = vs_attributes[8]
            serviceDownReset = vs_attributes[9]
            vlans = vs_attributes[10]
            snatpool = None
            snatType = None
            if snat_attributes is not None:
                snatpool = snat_attributes[0]
                snatType = snat_attributes[1]

            vs_list.append(BIGIPVS(vs_name, vs_ip, vs_port, vs_mask, ip_protocol, pool, profiles, rules, persist, serviceDownReset, vlans, snatpool, snatType))

    return vs_list

def extract_snat_attributes(data_all):

    snatpool = None
    snatType = None

    data_lines = data_all.splitlines()
    for data_line in data_lines:
        line = data_line.strip()
        if line.startswith("pool"):
            snatpool = trip_prefix(line, "pool")
        elif line.startswith("type"):
            snatType = trip_prefix(line, "type")

    return (snatpool, snatType)

def extract_vs_attributes(data_all):

    vs_name = None
    vs_ip = None
    vs_port = None
    vs_mask = None
    ip_protocol = None
    pool = None
    profiles = None
    rules = None
    serviceDownReset = None
    vlans = None
    persist = None

    lines = data_all.splitlines()
    vs_name = lines[0].replace("{", "").strip()
    for l in lines:
        line = l.strip()
        if line.startswith("destination"):
            destination_array = split_destination(trip_prefix(line, "destination"))
            vs_ip = destination_array[0]
            vs_port = destination_array[1]
        elif line.startswith("ip-protocol"):
            ip_protocol = trip_prefix(line, "ip-protocol")
        elif line.startswith("pool"):
            pool = trip_prefix(line, "pool")
        elif line.startswith("mask"):
            vs_mask = trip_prefix(line, "mask")
        elif line.startswith("service-down-immediate-action"):
            serviceDownReset = trip_prefix(line, "service-down-immediate-action")
    
    profiles_data_start = re.search("profiles", data_all, re.I).start()
    profiles_data = data_all[profiles_data_start:]
    if "source" in profiles_data:
        profiles_data = find_content_from_start_end(data_all, "profiles", "source")
    rules_search_results = re.search("rules", profiles_data, re.I)
    if rules_search_results:
        rules_data_start = rules_search_results.start()
        profiles_raw = profiles_data[:rules_data_start]
        rules_raw = profiles_data[rules_data_start:]
        profiles = convert_profiles_rules_to_list(profiles_raw, "profiles")
        rules = convert_profiles_rules_to_list(rules_raw, "rules")
    else:
        profiles = convert_profiles_rules_to_list(profiles_data, "profiles")

    if "vlans" in data_all:
        vlans_search_results = find_content_from_start_end(data_all, "vlans", "}")
        if vlans_search_results:
            vlans = convert_profiles_rules_to_list(vlans_search_results, "vlans")

    if "persist" in data_all:
        persist_search_results = find_content_from_start_end(data_all, "persist", "}")
        if persist_search_results:
            persist_list = convert_profiles_rules_to_list(persist_search_results, "persist")
            if len(persist_list) >= 1:
                persist = persist_list[0]

    return(vs_name, vs_ip, vs_port, vs_mask, ip_protocol, pool, profiles, rules, persist, serviceDownReset, vlans)

def convert_profiles_rules_to_list(data_all, item):
    results = []
    data_origin = data_all[:data_all.rfind("}")]
    results_raw = data_origin.strip().lstrip(item).replace("default yes", "").replace("context serverside", "").replace("context clientside", "").replace("{", "").replace("}", "").splitlines()
    for l in results_raw:
        line = l.strip()
        if len(line) > 0:
            results.append(line)
    return results
'''
[f5bigip % configParse.py] Parse all VS data as list - end
'''


def data_collect_auth_user(data_all):

    auth_user_list = []

    auth_user_end_str = "cli global-settings"
    if "cli admin-partitions" in data_all:
        auth_user_end_str = "cli admin-partitions"
    auth_users = split_content_to_list(data_all, r'auth user\s+\S+', auth_user_end_str)
    for auth_user in auth_users:
        user_data = auth_user[len("auth user"):]
        lines = user_data.splitlines()
        name = trip_prefix(replace_with_patterns(lines[0], "{"), None)
        role = None
        shell = None
        for l in lines:
            line = l.strip()
            if line.startswith("role"):
                role = trip_prefix(line, "role")
            elif line.startswith("shell"):
                shell = trip_prefix(line, "shell")
        auth_user_list.append(BIGIPAuthUser(name, role, shell))

    return auth_user_list


def load_f5_services_as_map():
    all_dict = {}
    with open("f5-services") as myfile:
        for line in myfile:
            name, var = line.partition(" ")[::2]
            all_dict[name.strip()] = var.strip()
    myfile.close()
    return all_dict

f5_services_dict = load_f5_services_as_map() 

def split_data_all(data_all):

    ltm_start_str = "ltm default-node-monitor"
    if "ltm data-group" in data_all:
        ltm_start_str = "ltm data-group"
    ltm_data_start = re.search(ltm_start_str, data_all, re.I).start()

    net_start_str = "net fdb"
    if "net cos" in data_all:
        net_start_str = "net cos"
    elif "net dag-globals" in data_all:
        net_start_str = "net dag-globals"
    net_data_start = re.search(net_start_str, data_all, re.I).start()
    
    sys_start_str = "sys daemon-log-settings"
    if "sys config-sync" in data_all:
        sys_start_str = "sys config-sync"
    elif "sys aom" in data_all:
        sys_start_str = "sys aom"
    elif "sys autoscale-group" in data_all:
        sys_start_str = "sys autoscale-group"
    sys_data_start = re.search(sys_start_str, data_all, re.I).start()
    
    return (data_all[:ltm_data_start], data_all[ltm_data_start:net_data_start], data_all[net_data_start:sys_data_start], data_all[sys_data_start:])


def parse(data_all):
    data_all_list  = split_data_all(data_all)

    vs_list = data_collect_vs_list(data_all_list[1])
    pool_list = data_collect_pool_list(data_all_list[1])
    snatpool_list = data_collect_snatpool_list(data_all_list[1])
    node_list = data_collect_node_list(data_all_list[1])
    profile_fastl4_list = extract_fastl4_profile(data_all_list[1])
    profile_http_list = extract_http_profile(data_all_list[1])

    print(len(vs_list), len(pool_list), len(snatpool_list), len(node_list), len(profile_fastl4_list), len(profile_http_list))

 
    auth_user_list = data_collect_auth_user(data_all_list[0])
    print(auth_user_list)

    return (vs_list, pool_list, snatpool_list, node_list, profile_fastl4_list, profile_http_list)
