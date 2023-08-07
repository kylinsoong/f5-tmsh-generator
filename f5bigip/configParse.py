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
    if len(line) > 0 and prefix in line:
        return line.strip().lstrip(prefix).strip()
    else:
        return line


def find_content_from_start_end(data, start_str, end_str):
    data_start = re.search(start_str, data, re.I).start()
    data_end = re.search(end_str, data[data_start:], re.I).start()
    return data[data_start:][:data_end] 


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



def extract_snatpool(data_all):
    snatpool_results = []
    pattern = r'ltm snatpool\s+\S+'
    results = extract_profiles(data_all, pattern)
    for i in results:
        snat_data = i.replace("ltm snatpool", "").strip()
        lines = snat_data.splitlines()
        snat_name = lines[0].strip().rstrip("{").strip()
        snat_members_raw = snat_data.replace(snat_name, "").replace("members", "").replace("{", "").replace("}", "")
        snat_members = []
        snat_members_list = snat_members_raw.splitlines()
        for snat in snat_members_list:
            snat_member = snat.strip()
            if len(snat_member) > 0:
                snat_members.append(snat_member)
        snatpool_results.append(BIGIPSnatPool(snat_name, snat_members))

    return snatpool_results




'''
[f5bigip % configParse.py] Parse running config data to form profiles related functions:

    extract_http_profile()
    extract_fastl4_profile()
    extract_profiles()
'''
def extract_http_profile(data_all):
    http_profile_results = []
    pattern = r'ltm profile http\s+\S+'
    results = extract_profiles(data_all, pattern)
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
    pattern = r'ltm profile fastl4\s+\S+'
    results = extract_profiles(data_all, pattern)
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


def extract_profiles(data_all, pattern):
    results = []
    profiles_list = []
    profiles_data = re.findall(pattern, data_all, re.I)
    for i in profiles_data:
        profiles_list.append(i)

    for i, num in zip(profiles_data, range(len(profiles_data))):
        if num < len(profiles_list) - 1:
            data_start = re.search(i, data_all, re.I).start()
            data_end = re.search(profiles_list[num+1], data_all[data_start:]).start()
            data_detail = data_all[data_start:][:data_end]
        else:
            data_start = re.search(i, data_all, re.I).start()
            data_end = re.search(r'}', data_all[data_start:]).start()
            data_detail = data_all[data_start:][:data_end]
        results.append(data_detail)

    return results
'''
[f5bigip % configParse.py] Parse running config data to form profiles end
'''



'''
[f5bigip % configParse.py] Parse all VS data as list start, related functions:

    data_collect_app_vs_list()
    extract_snat_attributes()
    extract_vs_attributes()
    convert_profiles_rules_to_list()

'''
def data_collect_app_vs_list(data_all):
    vs_list = []

    va_data_all = find_content_from_start_end(data_all, "ltm virtual", "net cos")
    va_data_list = va_data_all.split("ltm virtual")
    for i in va_data_list:
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
            destination = trip_prefix(line, "destination")
            destination_array = destination.split(":")
            vs_ip = destination_array[0]
            vs_port = convert_servicename_to_port(destination_array[1])
        elif line.startswith("ip-protocol"):
            ip_protocol = trip_prefix(line, "ip-protocol")
        elif line.startswith("pool"):
            pool = trip_prefix(line, "pool")
        elif line.startswith("mask"):
            vs_mask = trip_prefix(line, "mask")
        elif line.startswith("service-down-immediate-action"):
            serviceDownReset = trip_prefix(line, "service-down-immediate-action")

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


def load_f5_services_as_map():
    all_dict = {}
    with open("f5-services") as myfile:
        for line in myfile:
            name, var = line.partition(" ")[::2]
            all_dict[name.strip()] = var.strip()
    myfile.close()
    return all_dict

f5_services_dict = load_f5_services_as_map() 


def parse(data_all):
    vs_list = data_collect_app_vs_list(data_all)
    profile_fastl4_list = extract_fastl4_profile(data_all)
    profile_http_list = extract_http_profile(data_all)
    snatpool_list = extract_snatpool(data_all)
    print(len(vs_list), len(profile_fastl4_list), len(profile_http_list), len(snatpool_list))

    return (vs_list, profile_fastl4_list, profile_http_list, snatpool_list)
