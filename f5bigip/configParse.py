#!/usr/bin/python3

import sys
import ast
import re
import socket
import ipaddress
import os

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

class BIGIPDeviceGroup:
    def __init__(self, name, autosync, devices, fullloadonsync, networkfailover, type):
        self.name = name 
        self.autosync = autosync 
        self.devices = devices 
        self.fullloadonsync = fullloadonsync
        self.networkfailover = networkfailover
        self.type = type

class BIGIPAuthUser:
    def __init__(self, name, role, shell):
        self.name = name
        self.role = role
        self.shell = shell

class BIGIPNetL3:
    def __init__(self, name, address, allowservice, floating, trafficgroup, vlan):
        self.name = name
        self.address = address
        self.allowservice = allowservice
        self.floating = floating
        self.trafficgroup = trafficgroup
        self.vlan = vlan

class BIGIPNetL2:
    def __init__(self, name, failsafe, failsafe_action, failsafe_timeout, fwd_mode, if_index, interfaces, sflow_poll_interval_global, sflow_sampling_rate_global, tag):
        self.name = name
        self.failsafe = failsafe
        self.failsafe_action = failsafe_action
        self.failsafe_timeout = failsafe_timeout
        self.fwd_mode = fwd_mode 
        self.if_index = if_index 
        self.interfaces = interfaces 
        self.sflow_poll_interval_global = sflow_poll_interval_global 
        self.sflow_sampling_rate_global = sflow_sampling_rate_global 
        self.tag = tag

class BIGIPNetL2Trunk:
    def __init__(self, name, bandwidth, interfaces, mac_address, media, lacp):
        self.name = name
        self.bandwidth = bandwidth
        self.interfaces = interfaces
        self.mac_address = mac_address
        self.media = media
        self.lacp = lacp

class BIGIPNetL2InterfaceDetail:
    def __init__(self, name, disabled, mac_address, media_active, mtu, serial, vendor):
        self.name = name
        self.disabled = disabled
        self.mac_address = mac_address
        self.media_active = media_active
        self.mtu = mtu
        self.serial = serial
        self.vendor = vendor

class BIGIPNetRoute:
    def __init__(self, name, gw, network):
        self.name = name
        self.gw = gw
        self.network = network

class BIGIPNetL2Interface:
    def __init__(self, name, tag_mode, tagged):
        self.name = name
        self.tag_mode = tag_mode
        self.tagged = tagged 

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

class BIGIPMonitor:
    def __init__(self, type, name, interval, timeout):
        self.type = type
        self.name = name
        self.interval = interval
        self.timeout = timeout

class BIGIPMonitorHTTP(BIGIPMonitor):
    def __init__(self, type, name, interval, timeout):
        super().__init__(type, name, interval, timeout)

class BIGIPMonitorTCP(BIGIPMonitor):
    def __init__(self, type, name, interval, timeout):
        super().__init__(type, name, interval, timeout)

class BIGIPMonitorUDP(BIGIPMonitor):
    def __init__(self, type, name, interval, timeout):
        super().__init__(type, name, interval, timeout)


class BIGIPProfile:
    def __init__(self, name, parent):
        self.name = name
        self.parent = parent

class BIGIPProfileFastl4(BIGIPProfile):
    def __init__(self, name, parent, idle_timeout, tcp_handshake_timeout, pva_acceleration):
        super().__init__(name, parent)
        self.idle_timeout = idle_timeout
        self.tcp_handshake_timeout = tcp_handshake_timeout
        self.pva_acceleration = pva_acceleration

class BIGIPProfileHttp(BIGIPProfile):
    def __init__(self, name, parent, xff):
        super().__init__(name, parent)
        self.xff = xff

class BIGIPProfileWebAcceleration(BIGIPProfile):
    def __init__(self, name, parent):
        super().__init__(name, parent)

class BIGIPPersistSourceAddr:
    def __init__(self, name, timeout, default_from):
        self.name = name
        self.timeout = timeout
        self.default_from = default_from

class BIGIPPersistCookie:
    def __init__(self, name, cookie_encryption, cookie_name, default_from, expiration, method):
        self.name = name
        self.cookie_encryption = cookie_encryption 
        self.cookie_name = cookie_name
        self.default_from = default_from 
        self.expiration = expiration 
        self.method = method 


class BIGIPSnatPool:
    def __init__(self, name, members):
        self.name = name
        self.members = members

class BIGIPSysSSHD:
    def __init__(self, allow, inactivity_timeout):
        self.allow = allow
        self.inactivity_timeout = inactivity_timeout

class BIGIPSysHTTPD:
    def __init__(self, allow, auth_pam_idle_timeout):
        self.allow = allow
        self.auth_pam_idle_timeout = auth_pam_idle_timeout

class BIGIPSysNTP:
    def __init__(self, servers, timezone):
        self.servers = servers
        self.timezone = timezone

class BIGIPSysSNMP:
    def __init__(self, agent_addresses, allowed_addresses, communities, disk_monitors, process_monitors, traps):
        self.agent_addresses = agent_addresses
        self.allowed_addresses = allowed_addresses
        self.communities = communities
        self.disk_monitors = disk_monitors
        self.process_monitors = process_monitors
        self.traps = traps

class BIGIPSysSNMPCommunity:
    def __init__(self, community, community_name, oid_subset, source):
        self.community = community
        self.community_name = community_name
        self.oid_subset = oid_subset
        self.source = source

class BIGIPSysSNMPDiskMonitor:
    def __init__(self, disk_monitor, minspace, path):
        self.disk_monitor = disk_monitor
        self.minspace = minspace
        self.path = path

class BIGIPSysSNMPProcessMonitor:
    def __init__(self, process_monitor, max_processes, process):
        self.process_monitor = process_monitor
        self.max_processes = max_processes
        self.process = process

class BIGIPSysSNMPTrap:
    def __init__(self, trap, auth_password_encrypted, community, host, network, port, privacy_password_encrypted):
        self.trap = trap
        self.auth_password_encrypted = auth_password_encrypted
        self.community = community
        self.host = host
        self.network = network
        self.port = port
        self.privacy_password_encrypted = privacy_password_encrypted

class BIGIPSyslog:
    def __init__(self, remote_servers):
        self.remote_servers = remote_servers

class BIGIPSyslogRemoteServers:
    def __init__(self, remote_server, host, local_ip):
        self.remote_server = remote_server
        self.host = host
        self.local_ip = local_ip    

class BIGIPSysManagementRoute:
    def __init__(self, name, gateway, network):
        self.name = name
        self.gateway = gateway
        self.network = network



def auth_user(data_all):
            
    auth_user_list = []
    
    auth_user_end_str = find_end_str(data_all, "auth user", f5_config_dict['header'])
    auth_users = split_content_to_list_pattern(data_all, r'auth user\s+\S+', auth_user_end_str)
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


def cm_device(data_all):

    cm_device_list = []

    cm_device = split_content_to_list_split(data_all, "cm device", "cm device-group")
    for device in cm_device:
        if len(device) > 10:
            lines = device.splitlines()
            configsync_ip, failover_state, hostname, management_ip, self_device, time_zone, version, unicast_address, unicast_port = None, None, None, None, None, None, None, [], None
            for l in lines:
                line = l.strip()
                if line.startswith("configsync-ip"):
                    configsync_ip = trip_prefix(line, "configsync-ip")
                elif line.startswith("failover-state"):
                    failover_state = trip_prefix(line, "failover-state")
                elif line.startswith("hostname"):
                    hostname = trip_prefix(line, "hostname")
                elif line.startswith("management-ip"):
                    management_ip = trip_prefix(line, "management-ip")
                elif line.startswith("self-device"):
                    self_device = trip_prefix(line, "self-device")
                elif line.startswith("time-zone"):
                    time_zone = trip_prefix(line, "time-zone")
                elif line.startswith("version"):
                    version = trip_prefix(line, "version")
            unicast_addres_data = find_content_from_start_end(device, "unicast-address", "version")
            unicast_lines = unicast_addres_data.splitlines()
            for unicast in unicast_lines:
                address = unicast.strip()
                if address.startswith("effective-ip"):
                    unicast_address.append(trip_prefix(address, "effective-ip"))
                elif address.startswith("effective-port"):
                    unicast_port = convert_servicename_to_port(trip_prefix(address, "effective-port"))
                elif address.startswith("ip"):
                    unicast_address.append(trip_prefix(address, "ip"))
            cm_device_list.append(BIGIPDevice(configsync_ip, failover_state, hostname, management_ip, self_device, time_zone, unicast_address, unicast_port, version))

    return cm_device_list




def cm_device_group(data_all):

    cm_device_group_lists = []

    cm_device_group_end_str = "cm key"
    cm_device_group_list = split_content_to_list_pattern(data_all, r'cm device-group\s+\S+', cm_device_group_end_str)
    for dg in cm_device_group_list:
        device_group_data = dg[len("cm device-group"):]
        lines = device_group_data.splitlines()
        dg_name = trip_prefix(replace_with_patterns(lines[0], "{"), None)
        autosync, devices, fullloadonsync, networkfailover, type = None, [], None, None, None
        for l in lines:
            line = l.strip()
            if line.startswith("auto-sync"):
                autosync = trip_prefix(line, "auto-sync")
            elif line.startswith("full-load-on-sync"):
                fullloadonsync = trip_prefix(line, "full-load-on-sync")
            elif line.startswith("network-failover"):
                networkfailover = trip_prefix(line, "network-failover")
            elif line.startswith("type"):
                type = trip_prefix(line, "type")
            elif "{" in line and "}" in line:
                device = trip_prefix(replace_with_patterns(line, ["{", "}"]), None)
                devices.append(device)
        cm_device_group_lists.append(BIGIPDeviceGroup(dg_name, autosync, devices, fullloadonsync, networkfailover, type))

    return cm_device_group_lists




def ltm_monitor_http(data_all):
    monitor_http_list = []
    results = split_content_to_list_pattern(data_all, r'ltm monitor http\s+\S+', "}")
    for i in results:
        monitor = i[len("ltm monitor http"):].replace("{", "").replace("}", "")
        lines = monitor.splitlines()
        monitor_name = lines[0].strip()
        monitor_interval = None
        monitor_timeout = None
        for l in lines:
            line = l.strip()
            if line.startswith("interval"):
                monitor_interval = trip_prefix(line, "interval")
            elif line.startswith("timeout"):
                monitor_timeout = trip_prefix(line, "timeout")
        monitor_http_list.append(BIGIPMonitorHTTP("http", monitor_name, monitor_interval, monitor_timeout))
    return monitor_http_list


def ltm_monitor_tcp(data_all):
    monitor_tcp_list = []
    results = split_content_to_list_pattern(data_all, r'ltm monitor tcp\s+\S+', "}")
    for i in results:
        monitor = i[len("ltm monitor tcp"):].replace("{", "").replace("}", "")
        lines = monitor.splitlines()
        monitor_name = lines[0].strip()
        monitor_interval = None
        monitor_timeout = None
        for l in lines:
            line = l.strip()
            if line.startswith("interval"):
                monitor_interval = trip_prefix(line, "interval")
            elif line.startswith("timeout"):
                monitor_timeout = trip_prefix(line, "timeout")
        monitor_tcp_list.append(BIGIPMonitorTCP("tcp", monitor_name, monitor_interval, monitor_timeout))
    return monitor_tcp_list


def ltm_monitor_udp(data_all):
    monitor_udp_list = []
    results = split_content_to_list_pattern(data_all, r'ltm monitor udp\s+\S+', "}")
    for i in results:
        monitor = i[len("ltm monitor udp"):].replace("{", "").replace("}", "")
        lines = monitor.splitlines()
        monitor_name = lines[0].strip()
        monitor_interval = None
        monitor_timeout = None
        for l in lines:
            line = l.strip()
            if line.startswith("interval"):
                monitor_interval = trip_prefix(line, "interval")
            elif line.startswith("timeout"):
                monitor_timeout = trip_prefix(line, "timeout")
        monitor_udp_list.append(BIGIPMonitorUDP("udp", monitor_name, monitor_interval, monitor_timeout))
    return monitor_udp_list



def ltm_node(data_all):

    node_list = []

    node_start_str = "ltm node"
    node_end_str = find_end_str(data_all, node_start_str, f5_config_dict['ltm'])
    node_data_list = split_content_to_list_split(data_all, node_start_str, node_end_str)
    for i in node_data_list:
        node_data = trip_prefix(i, None)
        name = replace_with_patterns(find_first_line(node_data), ["{", "}"])
        lines = node_data.splitlines()
        address, monitor, session, state = None, None, None, None
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



def ltm_persistence_source_addr(data_all):
  
    persist_list = []

    persist_start_str = "ltm persistence source-addr"
    persist_end_str = find_end_str(data_all, persist_start_str, f5_config_dict['ltm'])
    persist_data_list = split_content_to_list_split(data_all, persist_start_str, persist_end_str)
    for i in persist_data_list:
        persist_data = trip_prefix(i, None)
        name = replace_with_patterns(find_first_line(persist_data), ["{", "}"]) 
        lines = persist_data.splitlines()
        timeout, default_from = None, None
        for l in lines:
            line = trip_prefix(l, None)
            if line.startswith("timeout"):
                timeout = trip_prefix(line, "timeout")
            elif line.startswith("defaults-from"):
                default_from = trip_prefix(line, "defaults-from")

        persist_list.append(BIGIPPersistSourceAddr(name, timeout, default_from))

    return persist_list



def ltm_persistence_cookie(data_all):

    persist_list = []

    persist_end_str = find_end_str(data_all, "ltm persistence cookie", f5_config_dict['ltm'])
    persist_data_list = split_content_to_list_pattern(data_all, r'ltm persistence cookie\s+\S+', "}")
    for i in persist_data_list:
        persist_data = trip_prefix(i, None)
        name = replace_with_patterns(find_first_line(persist_data), ["{", "ltm persistence cookie"])
        lines = persist_data.splitlines()
        cookie_encryption, cookie_name, default_from, expiration, method = None, None, None, None, None
        for l in lines:
            line = trip_prefix(l, None)
            if line.startswith("cookie-encryption"):
                cookie_encryption = trip_prefix(line, "cookie-encryption")
            elif line.startswith("cookie-name"):
                cookie_name = trip_prefix(line, "cookie-name")
            elif line.startswith("defaults-from"):
                default_from = trip_prefix(line, "defaults-from")
            elif line.startswith("expiration"):
                expiration = trip_prefix(line, "expiration")
            elif line.startswith("method"):
                method = trip_prefix(line, "method")
        persist_list.append(BIGIPPersistCookie(name, cookie_encryption, cookie_name, default_from, expiration, method))

    return persist_list



def ltm_pool(data_all):

    pool_list = []

    pool_start_str = "ltm pool"
    pool_end_str = find_end_str(data_all, pool_start_str, f5_config_dict['ltm'])
    pool_data_list = split_content_to_list_split(data_all, pool_start_str, pool_end_str)
    for i in pool_data_list:
        pool_data = trip_prefix(i, None)
        pool_name = replace_with_patterns(find_first_line(pool_data), "{")
        pool_lb_mode, pool_min_active_member, pool_monitor = None, None, None # TODO-- pool_min_active_member not used
        isMembersStart = False
        pool_members_list, pool_member_list, poolmembers = [], [], []
        lines = pool_data.splitlines()
        for l in lines:
            line = trip_prefix(l, None)
            if line.startswith("load-balancing-mode"):
                pool_lb_mode = trip_prefix(line, "load-balancing-mode")
            elif line.startswith("min-active-members"):
                pool_min_active_member = trip_prefix(line, "min-active-members")
            elif line.startswith("monitor"):
                pool_monitor = trip_prefix(line, "monitor")
            elif line.startswith("members") or "members" in line :
                isMembersStart = True
            elif isMembersStart and (line != "}" or "}" not in line):
                pool_member_list.append(line)
            elif isMembersStart and (line == "}" or "}" in line )  and len(pool_member_list) > 0:
                cloned_list = pool_member_list[:]
                pool_members_list.append(cloned_list)
                pool_member_list = []
            elif isMembersStart and (line == "}" or "}" in line) and len(pool_member_list) == 0:
                isMembersStart = False

        for m_list in pool_members_list:
            member, address, port, session, state, connectionlimit = None, None, None, None, None, None
            if len(m_list) > 0 and len(m_list[0]) >= 12:
                array = split_destination(replace_with_patterns(m_list[0], "{"))
                if is_valid_ip_network(array[0]):  
                    member = str(array[0]) + ":" + str(array[1])
                else:
                    member = find_ip_from_line(array[0])  + ":" + str(array[1])
                port = array[1]
            for l in m_list:
                line = trip_prefix(l, None)
                if line.startswith("address"):
                    address = trip_prefix(line, "address")
                elif ~line.startswith("address") and "address" in line:
                    address = find_ip_from_line(line)
                elif line.startswith("session"):
                    session = trip_prefix(line, "session")
                elif line.startswith("state"):
                    state = trip_prefix(line, "state")
                elif line.startswith("connection-limit"):
                    connectionlimit = trip_prefix(line, "connection-limit")
            if member is not None:
                poolmembers.append(BIGIPPoolMember(member, address, port, session, state, connectionlimit))

        pool_list.append(BIGIPPool(pool_name, pool_lb_mode, poolmembers, pool_monitor))

    return pool_list



def ltm_profile_http(data_all):
    http_profile_results = []
    results = split_content_to_list_pattern(data_all, r'ltm profile http\s+\S+', "}")
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


def ltm_profile_fastl4(data_all):
    fastl4_profile_results = []
    results = split_content_to_list_pattern(data_all, r'ltm profile fastl4\s+\S+', "}")
    for i in results:
        profile = i[len("ltm profile fastl4"):].replace("{", "").replace("}", "")
        lines = profile.splitlines()
        profile_name = lines[0].strip()
        profile_parent, profile_idle_timeout, profile_handshake_timeout, pva_acceleration = None, None, None, None
        for l in lines:
            line = l.strip()
            if line.startswith("defaults-from"):
                profile_parent = trip_prefix(line, "defaults-from")
            elif line.startswith("idle-timeout"):
                profile_idle_timeout = trip_prefix(line, "idle-timeout")
            elif line.startswith("tcp-handshake-timeout"):
                profile_handshake_timeout = trip_prefix(line, "tcp-handshake-timeout")
            elif line.startswith("pva-acceleration"):
                pva_acceleration = trip_prefix(line, "pva-acceleration")
        fastl4_profile_results.append(BIGIPProfileFastl4(profile_name, profile_parent, profile_idle_timeout, profile_handshake_timeout, pva_acceleration))
    return fastl4_profile_results


def ltm_profile_web_acceleration(data_all):
    web_acceleration_results = []
    results = split_content_to_list_pattern(data_all, r'ltm profile web-acceleration\s+\S+', "}")
    for i in results:
        profile = i[len("ltm profile web-acceleration"):].replace("{", "").replace("}", "")
        lines = profile.splitlines()
        profile_name = lines[0].strip()
        profile_parent = None
        for l in lines:
            line = l.strip()
            if line.startswith("defaults-from"):
                profile_parent = trip_prefix(line, "defaults-from")
        web_acceleration_results.append(BIGIPProfileWebAcceleration(profile_name, profile_parent))
    return web_acceleration_results


def ltm_snatpool(data_all):

    snatpool_results = []

    snatpool_start_str = "ltm snatpool"
    snatpool_end_str = find_end_str(data_all, snatpool_start_str, f5_config_dict['ltm']) 
    snatpool_data_list = split_content_to_list_split(data_all, snatpool_start_str, snatpool_end_str)
    for i in snatpool_data_list:
        snatpool_data = trip_prefix(i, None)
        snat_name = replace_with_patterns(find_first_line(snatpool_data), "{")
        snatpool_data = replace_with_patterns(snatpool_data, [snat_name, "members", "{", "}"])
        lines = snatpool_data.splitlines()
        snat_members = []
        for l in lines:
            line = trip_prefix(l, None)
            if len(line) > 7 and is_valid_ip_network(line):
                snat_members.append(line)
            else:
               ip = find_ip_from_line(line)
               if ip is not None:  
                   snat_members.append(ip)
        snatpool_results.append(BIGIPSnatPool(snat_name, snat_members))

    return snatpool_results



def ltm_virtual(data_all):

    vs_list = []

    vs_start_str = "ltm virtual"
    vs_end_str = find_end_str(data_all, vs_start_str, f5_config_dict['net'])
    vs_data_list = split_content_to_list_split(data_all, vs_start_str, vs_end_str)
    for i in vs_data_list:
        vs_data = trip_prefix(i, None)
        vs_name, vs_ip, vs_port, vs_mask, ip_protocol, pool, profiles, rules, persist, serviceDownReset, vlans, snatpool, snatType = None, None, None, None, None, None, [], [], None, None, [], None, None
        vs_name = replace_with_patterns(find_first_line(vs_data), "{")
        lines = vs_data.splitlines()
        isProfileStart, isProfileEnd, isRulesStart, isSnatpoolStart, isVlanStart, isPersistStart, isPersistEnd = False, False, False, False, False, False, False
        for l in lines:
            line = trip_prefix(l, None)
            if line.startswith("destination"):
                array = split_destination(trip_prefix(line, "destination"))
                vs_ip = array[0]
                vs_port = array[1]
            elif ~line.startswith("destination") and "destination" in line:
                vs_ip = find_ip_from_line(line)
                vs_port = convert_servicename_to_port(trip_prefix(find_content_from_start_end(line, vs_ip, None)[len(vs_ip) + 1:], None))
            elif line.startswith("ip-protocol"):
                ip_protocol = trip_prefix(line, "ip-protocol")
            elif line.startswith("mask"):
                vs_mask = trip_prefix(line, "mask")
            elif line.startswith("persist"):
                isPersistStart = True
            elif isPersistStart and "{" in line:
                persist = replace_with_patterns(line, "{")
                isPersistStart = False 
            elif line.startswith("pool") and isSnatpoolStart == False:
                pool = trip_prefix(line, "pool") 
            elif line.startswith("profiles"):
                isProfileStart = True
            elif isProfileStart and isProfileEnd and line == "}":
                isProfileStart = False
            elif isProfileStart and "{" in line:
                isProfileEnd = False
                proile = trip_prefix(line[0: line.index("{")], None)
                profiles.append(proile) 
                if "}" in line: 
                    isProfileEnd = True 
            elif line.startswith("rules"):
                isRulesStart = True
            elif isRulesStart and "}" in line:
                isRulesStart = False
            elif isRulesStart and len(line) > 0:
                rules.append(trip_prefix(line, None))
            elif line.startswith("source-address-translation"):
                isSnatpoolStart = True
            elif isSnatpoolStart and "}" in line:
                isSnatpoolStart = False
            elif isSnatpoolStart and line.startswith("pool"):
                snatpool = trip_prefix(line, "pool")
            elif isSnatpoolStart and line.startswith("type"):
                snatType = trip_prefix(line, "type")
            elif line.startswith("service-down-immediate-action"):
                serviceDownReset = trip_prefix(line, "service-down-immediate-action")
            elif line.startswith("vlans"):
                isVlanStart = True
            elif isVlanStart and "}" in line:
                isVlanStart = False
            elif isVlanStart and len(line) > 0:
                vlans.append(line)

        vs_list.append(BIGIPVS(vs_name, vs_ip, vs_port, vs_mask, ip_protocol, pool, profiles, rules, persist, serviceDownReset, vlans, snatpool, snatType))

    return vs_list



def net_interface(data_all):

    net_interface_list = []
   
    net_interface_start_str = "net interface"
    net_interface_end_str = find_end_str(data_all, net_interface_start_str, f5_config_dict['net'])
    net_interface_data_list = split_content_to_list_split(data_all, net_interface_start_str, net_interface_end_str)
    for data in net_interface_data_list:
        interface_data = trip_prefix(data, None)
        name = replace_with_patterns(find_first_line(interface_data), "{")        
        disabled, mac_address, media_active, mtu, serial, vendor = False, None, None, None, None, None
        lines = interface_data.splitlines()
        for l in lines:
            line = l.strip() 
            if line.startswith("disabled"):
                disabled = True
            elif line.startswith("mac-address"):
                mac_address = trip_prefix(line, "mac-address")
            elif line.startswith("media-active"):
                media_active = trip_prefix(line, "media-active")  
            elif line.startswith("mtu"):
                mtu = trip_prefix(line, "mtu")  
            elif line.startswith("serial"):
                serial = trip_prefix(line, "serial")  
            elif line.startswith("vendor "):
                vendor = trip_prefix(line, "vendor")
        net_interface_list.append(BIGIPNetL2InterfaceDetail(name, disabled, mac_address, media_active, mtu, serial, vendor))

    return net_interface_list      



def net_route(data_all):

    net_route_list = []
    net_route_start_str = "net route"
    net_route_end_str = find_end_str(data_all, net_route_start_str, f5_config_dict['net'])
    net_route_data_list = split_content_to_list_split(data_all, net_route_start_str, net_route_end_str)
    for data in net_route_data_list:
        route_data = trip_prefix(data, None)
        name = replace_with_patterns(find_first_line(route_data), "{")
        gw, network = None, None
        lines = route_data.splitlines()
        for l in lines:
            line = l.strip()
            if line.startswith("gw"):
                gw = trip_prefix(line, "gw")
            elif line.startswith("network"):
                network = trip_prefix(line, "network")
        net_route_list.append(BIGIPNetRoute(name, gw, network))

    return net_route_list
        


def net_self(data_all):

    net_self_list = []

    net_self_data_list = split_content_to_list_split(data_all, "net self", "net self-allow")
    for data in net_self_data_list:
        self_data = trip_prefix(data, None)
        self_name = replace_with_patterns(find_first_line(self_data), "{")
        lines = self_data.splitlines()
        self_address, floating, self_trafficgroup, self_vlan = None, None, None, None
        self_allow_service = trip_prefix(replace_with_patterns(find_content_from_start_end(self_data, "allow-service", "}"), ["allow-service", "{"] ), None)
        for l in lines:
            line = l.strip()
            if line.startswith("address"):
                self_address = trip_prefix(line, "address")
            elif line.startswith("floating"):
                floating = trip_prefix(line, "floating")
            elif line.startswith("traffic-group"):
                self_trafficgroup = trip_prefix(line, "traffic-group")
            elif line.startswith("vlan"):
                self_vlan = trip_prefix(line, "vlan")

        net_self_list.append(BIGIPNetL3(self_name, self_address, self_allow_service, floating, self_trafficgroup, self_vlan))

    return net_self_list


def net_trunk(data_all):

    net_trunk_list = []

    net_trunk_start_str = "net trunk"
    net_trunk_end_str = find_end_str(data_all, net_trunk_start_str, f5_config_dict['net'])
    net_trunk_data_list = split_content_to_list_split(data_all, net_trunk_start_str, net_trunk_end_str)
    for data in net_trunk_data_list:
        trunk_data = trip_prefix(data, None)
        name = replace_with_patterns(find_first_line(trunk_data), "{")
        bandwidth, interfaces, mac_address, media, lacp = None, [], None, None, None
        lines = trunk_data.splitlines()
        isInterfaceStart = False
        for l in lines:
            line = l.strip()
            if line.startswith("bandwidth"):
                bandwidth = trip_prefix(line, "bandwidth")
            elif line.startswith("interfaces"):
                isInterfaceStart = True
            elif isInterfaceStart and "}" in line:
                isInterfaceStart = False
            elif isInterfaceStart and len(line) >= 3:
                interfaces.append(line)
            elif line.startswith("mac-address"):
                mac_address = trip_prefix(line, "mac-address")
            elif line.startswith("media"):
                media = trip_prefix(line, "media")
            elif line.startswith("lacp"):
                lacp = trip_prefix(line, "lacp")

        net_trunk_list.append(BIGIPNetL2Trunk(name, bandwidth, interfaces, mac_address, media, lacp))

    return net_trunk_list


def net_vlan(data_all):
    
    net_vlan_list = []

    net_vlan_start_str = "net vlan"
    net_vlan_end_str = find_end_str(data_all, net_vlan_start_str, f5_config_dict['tail'])
    net_vlan_data_list = split_content_to_list_split(data_all, net_vlan_start_str, net_vlan_end_str)
    for data in net_vlan_data_list:
        vlan_data = trip_prefix(data, None)
        vlan_name = replace_with_patterns(find_first_line(vlan_data), "{")
        failsafe, failsafe_action, failsafe_timeout, fwd_mode, if_index, interfaces, sflow_poll_interval_global, sflow_sampling_rate_global, tag = None, None, None, None, None, [], None, None, None
        lines = vlan_data.splitlines()
        sflowStart, interfaceStart, interfaceEnd = False, False, False
        interface_name, interface_tag_mode, interface_tagged = None, None, False
        for l in lines:
            line = l.strip()
            if line.startswith("failsafe"):
                failsafe = trip_prefix(line, "failsafe")
            elif line.startswith("failsafe-action"):
                failsafe_action = trip_prefix(line, "failsafe-action")
            elif line.startswith("failsafe-timeout"):
                failsafe_timeout = trip_prefix(line, "failsafe-timeout")
            elif line.startswith("fwd-mode"):
                fwd_mode = trip_prefix(line, "fwd-mode")
            elif line.startswith("if-index"):
                if_index = trip_prefix(line, "if-index")
            elif line.startswith("interfaces"):
                interfaceStart = True
            elif interfaceStart and interfaceEnd and "}" in line:
                interfaceStart = False
            elif interfaceStart and "{" in line:
                interfaceEnd = False
                interface_name = replace_with_patterns(line, ["{", "}"] )
                if "}" in line:
                    interfaceEnd = True
                    interfaces.append(BIGIPNetL2Interface(interface_name, interface_tag_mode, interface_tagged))
                    interface_name, interface_tag_mode, interface_tagged = None, None, False
            elif interfaceStart and interfaceEnd == False and line.startswith("tag-mode"):
                interface_tag_mode = trip_prefix(line, "tag-mode")
            elif interfaceStart and interfaceEnd == False and "tagged" in line:
                interface_tagged = True
            elif interfaceStart and "}" in line:
                interfaceEnd = True
                interfaces.append(BIGIPNetL2Interface(interface_name, interface_tag_mode, interface_tagged))    
                interface_name, interface_tag_mode, interface_tagged = None, None, False
            elif line.startswith("sflow"):
                sflowStart = True
            elif sflowStart and "}" in line:
                sflowStart = False
            elif sflowStart and line.startswith("poll-interval-global"):
                sflow_poll_interval_global = trip_prefix(line, "poll-interval-global")
            elif sflowStart and line.startswith("sampling-rate-global"):
                sflow_sampling_rate_global = trip_prefix(line, "sampling-rate-global")
            elif line.startswith("tag"):
                tag = trip_prefix(line, "tag")
    
        net_vlan_list.append(BIGIPNetL2(vlan_name, failsafe, failsafe_action, failsafe_timeout, fwd_mode, if_index, interfaces, sflow_poll_interval_global, sflow_sampling_rate_global, tag))

    return net_vlan_list



def sys_httpd(data_all):
    
    sys_httpd_start_str = "sys httpd"
    sys_httpd_end_str = find_end_str(data_all, sys_httpd_start_str, f5_config_dict['tail']) 
    sys_httpd_data = find_content_from_start_end(data_all, sys_httpd_start_str, sys_httpd_end_str)
    lines = sys_httpd_data.splitlines()
    allow, auth_pam_idle_timeout = None, None
    for l in lines:
        line = l.strip()
        if line.startswith("allow"):
            allow_list = replace_with_patterns(trip_prefix(line, "allow"), ["{", "}"])
            allow = split_to_list(allow_list, " ")
        elif line.startswith("auth-pam-idle-timeout"):
            auth_pam_idle_timeout = trip_prefix(line, "auth-pam-idle-timeout")

    return BIGIPSysHTTPD(allow, auth_pam_idle_timeout)



def sys_management_route(data_all):

    sys_management_route_list = []

    sys_management_route_start_str = "sys management-route"
    sys_management_route_end_str = find_end_str(data_all, sys_management_route_start_str, f5_config_dict['tail'])
    sys_management_route_data_list = split_content_to_list_split(data_all, sys_management_route_start_str, sys_management_route_end_str)
    for data in sys_management_route_data_list: 
        management_route_data = trip_prefix(data, None)
        name = replace_with_patterns(find_first_line(management_route_data), "{")
        gateway, network = None, None
        lines = management_route_data.splitlines()
        for l in lines:
            line = l.strip()
            if line.startswith("gateway"):
                gateway = trip_prefix(line, "gateway")
            elif line.startswith("network"):
                network = trip_prefix(line, "network")
        sys_management_route_list.append(BIGIPSysManagementRoute(name, gateway, network))

    return sys_management_route_list



def sys_ntp(data_all):

    sys_ntp_start_str = "sys ntp"
    sys_ntp_end_str = find_end_str(data_all, sys_ntp_start_str, f5_config_dict['tail'])
    sys_ntp_data = find_content_from_start_end(data_all, sys_ntp_start_str, sys_ntp_end_str)
    servers, timezone = [], None
    lines = sys_ntp_data.splitlines()
    for l in lines:
        line = l.strip()
        if line.startswith("servers"):
            server_list = replace_with_patterns(trip_prefix(line, "servers"), ["{", "}"])
            servers = split_to_list(server_list, " ")
        elif line.startswith("timezone"):
            timezone = trip_prefix(line, "timezone")

    return BIGIPSysNTP(servers, timezone)


def sys_snmp(data_all):
   
    sys_snmp_start_str = "sys snmp"
    sys_snmp_end_str = find_end_str(data_all, sys_snmp_start_str, f5_config_dict['tail'])
    sys_snmp_data = find_content_from_start_end(data_all, sys_snmp_start_str, sys_snmp_end_str)
    agent_addresses, allowed_addresses, communities, disk_monitors, process_monitors, traps = [], [], [], [], [], []
    isComminutiesStart, isComminutiesEnd, isDiskMonitorStart, isDiskMonitorEnd, isProcessMonitorStart, isProcessMonitorEnd, isTrapStart, isTrapEnd = False, False, False, False, False, False, False, False
    community, community_name, oid_subset, source, disk_monitor, minspace, path, process_monitor, max_processes, process, trap, auth_password_encrypted, community, host, network, port, privacy_password_encrypted = None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None
    lines = sys_snmp_data.splitlines()
    for l in lines:
        line = l.strip()
        if line.startswith("agent-addresses"):
            agent_addresses_list = replace_with_patterns(trip_prefix(line, "agent-addresses"), ["{", "}"])
            agent_addresses = split_to_list(agent_addresses_list, " ")
        elif line.startswith("allowed-addresses"):
            allowed_addresses_list = replace_with_patterns(trip_prefix(line, "allowed-addresses"), ["{", "}"])
            allowed_addresses = split_to_list(allowed_addresses_list, " ")
        elif line.startswith("communities"):
            isComminutiesStart = True
        elif isComminutiesStart and isComminutiesEnd and "}" == line:
            isComminutiesStart = False
        elif isComminutiesStart and "{" in line:
            isComminutiesEnd = False
            community = replace_with_patterns(line, "{")
        elif isComminutiesStart and isComminutiesEnd == False and line.startswith("community-name"):
            community_name = trip_prefix(line, "community-name")
        elif isComminutiesStart and isComminutiesEnd == False and line.startswith("oid-subset"):
            oid_subset = trip_prefix(line, "oid-subset")
        elif isComminutiesStart and isComminutiesEnd == False and line.startswith("source"):
            source = trip_prefix(line, "source")
        elif isComminutiesStart and isComminutiesEnd == False and "}" == line:
            isComminutiesEnd = True
            communities.append(BIGIPSysSNMPCommunity(community, community_name, oid_subset, source))
            community, community_name, oid_subset, source = None, None, None, None
        elif line.startswith("disk-monitors"):
            isDiskMonitorStart = True
        elif isDiskMonitorStart and isDiskMonitorEnd and "}" == line:
            isDiskMonitorStart = False
        elif isDiskMonitorStart and "{" in line:
            isDiskMonitorEnd = False
            disk_monitor = replace_with_patterns(line, "{")
        elif isDiskMonitorStart and isDiskMonitorEnd == False and line.startswith("minspace"):
            minspace = trip_prefix(line, "minspace")
        elif isDiskMonitorStart and isDiskMonitorEnd == False and line.startswith("path"):
            path = trip_prefix(line, "path")
        elif isDiskMonitorStart and isDiskMonitorEnd == False and "}" == line:
            isDiskMonitorEnd = True
            disk_monitors.append(BIGIPSysSNMPDiskMonitor(disk_monitor, minspace, path))
            disk_monitor, minspace, path = None, None, None
        elif line.startswith("process-monitors"):
            isProcessMonitorStart = True
        elif isProcessMonitorStart and isProcessMonitorEnd and "}" == line:
            isProcessMonitorStart = False
        elif isProcessMonitorStart and "{" in line:
            isProcessMonitorEnd = False
            process_monitor = replace_with_patterns(line, "{")
        elif isProcessMonitorStart and isProcessMonitorEnd == False and line.startswith("max-processes"):
            max_processes = trip_prefix(line, "max-processes")
        elif isProcessMonitorStart and isProcessMonitorEnd == False and line.startswith("process"):
            process = trip_prefix(line, "process")
        elif isProcessMonitorStart and isProcessMonitorEnd == False and "}" == line:
            isProcessMonitorEnd = True
            process_monitors.append(BIGIPSysSNMPProcessMonitor(process_monitor, max_processes, process))
            process_monitor, max_processes, process = None, None, None
        elif line.startswith("traps"):
            isTrapStart = True
        elif isTrapStart and isTrapEnd and "}" == line:
            isTrapStart = False
        elif isTrapStart and "{" in line:
            isTrapEnd = False
            trap = replace_with_patterns(line, "{")
        elif isTrapStart and isTrapEnd == False and line.startswith("auth-password-encrypted"):
            auth_password_encrypted = trip_prefix(line, "auth-password-encrypted")
        elif isTrapStart and isTrapEnd == False and line.startswith("community"):
            community = trip_prefix(line, "community")
        elif isTrapStart and isTrapEnd == False and line.startswith("host"):
            host = trip_prefix(line, "host")
        elif isTrapStart and isTrapEnd == False and line.startswith("network"):
            network = trip_prefix(line, "network")
        elif isTrapStart and isTrapEnd == False and line.startswith("port"):
            port = convert_servicename_to_port(trip_prefix(line, "port"))
        elif isTrapStart and isTrapEnd == False and line.startswith("privacy-password-encrypted"):
            privacy_password_encrypted = trip_prefix(line, "privacy-password-encrypted")
        elif isTrapStart and isTrapEnd == False and "}" == line:
            isTrapEnd = True
            traps.append(BIGIPSysSNMPTrap(trap, auth_password_encrypted, community, host, network, port, privacy_password_encrypted))
            trap, auth_password_encrypted, community, host, network, port, privacy_password_encrypted = None, None, None, None, None, None, None
    
    return BIGIPSysSNMP(agent_addresses, allowed_addresses, communities, disk_monitors, process_monitors, traps)


def sys_sshd(data_all):

    sys_sshd_start_str = "sys sshd"
    sys_sshd_end_str = find_end_str(data_all, sys_sshd_start_str, f5_config_dict['tail'])
    sys_sshd_data = find_content_from_start_end(data_all, sys_sshd_start_str, sys_sshd_end_str)
    lines = sys_sshd_data.splitlines()
    allow, auth_pam_idle_timeout = None, None
    for l in lines:
        line = l.strip()
        if line.startswith("allow"):
            allow_list = replace_with_patterns(trip_prefix(line, "allow"), ["{", "}"])
            allow = split_to_list(allow_list, " ")
        elif line.startswith("inactivity-timeout"):
            auth_pam_idle_timeout = trip_prefix(line, "inactivity-timeout")

    return BIGIPSysSSHD(allow, auth_pam_idle_timeout)


def sys_syslog(data_all):

    syslog_start_str = "sys syslog"
    syslog_end_str = find_end_str(data_all, syslog_start_str, f5_config_dict['tail'])
    syslog_data = find_content_from_start_end(data_all, syslog_start_str, syslog_end_str)
    remote_servers, remote_server, host, local_ip = [], None, None, None
    isRemoteServerStart, isRemoteServerEnd = False, False
    lines = syslog_data.splitlines()
    for l in lines:
        line = l.strip()
        if line.startswith("remote-servers"):
            isRemoteServerStart = True
        elif isRemoteServerStart and isRemoteServerEnd and "}" == line:
            isRemoteServerStart = False
        elif isRemoteServerStart and "{" in line:
            isRemoteServerEnd = False
            remote_server = replace_with_patterns(line, "{")
        elif isRemoteServerStart and isRemoteServerEnd == False and line.startswith("host"):
            host = trip_prefix(line, "host")
        elif isRemoteServerStart and isRemoteServerEnd == False and line.startswith("local-ip"):
            local_ip = trip_prefix(line, "local-ip")
        elif isRemoteServerStart and isRemoteServerEnd == False and "}" == line:
            isRemoteServerEnd = True
            remote_servers.append(BIGIPSyslogRemoteServers(remote_server, host, local_ip))
            remote_server, host, local_ip = None, None, None
    
    return BIGIPSyslog(remote_servers)



def trip_prefix(line, prefix):
    if len(line) > 0 and prefix is not None and prefix in line:
        return line.strip().lstrip(prefix).strip()
    else:
        return line.strip()


def find_first_line(data_all):
    first_line_end = data_all.find('\n')
    if first_line_end != -1:
        return data_all[:first_line_end]
    else:
        return data_all

def find_content_from_start_end(data, start_str, end_str):

    if start_str not in data:
        return ""

    data_start = re.search(start_str, data, re.I).start()
    if end_str is None:
        return data[data_start:]
    data_end = re.search(end_str, data, re.I).start()
    return data[data_start:data_end]


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


def find_ip_from_line(line):
    if len(line) <= 7:
        return None
    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ipv4_addresses = re.findall(ipv4_pattern, line)
    if len(ipv4_addresses) > 0:
        return ipv4_addresses[0]
    ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    ipv6_addresses = re.findall(ipv6_pattern, line)
    if len(ipv6_addresses) > 0 :
        return ipv6_addresses[0]
    return None

def find_port_from_line(line):
    tcp_port_pattern = r'\b\d{1,5}\b'
    tcp_ports = re.findall(tcp_port_pattern, line)
    if len(tcp_ports) > 0:
        return tcp_ports[0]
    return None


def split_to_list(content, splits):
    content = content.strip()
    return content.split(splits)


def split_destination(destination):
    if "any:any" == destination:
        return ("0.0.0.0", "0")
    destination_array = destination.split(":")
    ip = destination_array[0]
    port = convert_servicename_to_port(destination_array[1])
    if is_valid_ip_network(ip) == False:
        ip = find_ip_from_line(destination)
        if ip is None:
            destination_array = destination.split(".")
            ip = destination_array[0]
            port = convert_servicename_to_port(destination_array[1])
    return (ip, port)


def replace_with_patterns(data, patterns):
    for pattern in patterns:
        data = data.replace(pattern, "")
    return trip_prefix(data, None)

def convert_list_to_str(data_list):
    result_string = " ".join(data_list)
    return result_string

def convert_servicename_to_port(input):
    input = trip_prefix(input, None)
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
def split_content_to_list_pattern(data_all, pattern, end_str):
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


'''
Split a large content to small block base on re pattern, return each blocks as a content list, provide same functionality as split_content_to_list_pattern(), but has better performance if the search targe data_all is large, 100 times faster than split_content_to_list_pattern().

    data_all - original data
    pattern  - re pattern
    end_str  - the end of big blok

'''
def split_content_to_list_split(data_all, start_str, end_str):
    data = find_content_from_start_end(data_all, start_str, end_str)
    data_list = data.split(start_str)
    return data_list[1:]



def find_end_str(data_all, start_str, items):
    if start_str not in items:
        for i in items:
            if i in data_all:
                return i
    else:  
        isStart = False
        for i in items:
            if i == start_str:
                isStart = True
                continue
            if isStart and i in data_all:
                return i
    return None



def is_valid_ip_network(address):
    try:
        ipaddress.ip_network(address, False)
        return True
    except ValueError:
        return False



'''
Deprecated funtions:

    extract_http_profile()
    extract_fastl4_profile()
    data_collect_snatpool_list()
    data_collect_node_list()
    data_collect_pool_list()
    extract_poolmember_attributes()
    data_collect_vs_list()
    extract_snat_attributes()
    extract_vs_attributes()
    convert_profiles_rules_to_list()
    data_collect_auth_user()
    data_collect_net_self()
    data_collect_cm_device_group()
    data_collect_cm_device()
'''
def extract_http_profile(data_all):
    http_profile_results = []
    results = split_content_to_list_pattern(data_all, r'ltm profile http\s+\S+', "}")
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
    results = split_content_to_list_pattern(data_all, r'ltm profile fastl4\s+\S+', "}")
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


def data_collect_pool_list(data_all):

    pool_list = []

    pool_start_str = "ltm pool"
    pool_end_str = find_end_str(data_all, pool_start_str, f5_config_dict['ltm'])

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
            
            if pool_members is not None :
                pool_members = replace_with_patterns(pool_members, ["members", "{"])            
                pool_members = pool_members.split("}")
                for m in pool_members: 
                    if len(trip_prefix(m, None)) <= 10:
                        continue 
                    pool_member = extract_poolmember_attributes(m)   
                    if pool_member is not None :
                        pool_members_list.append(pool_member)

            pool_list.append(BIGIPPool(pool_name, pool_lb, pool_members_list, pool_monitor))

    return pool_list


def extract_poolmember_attributes(data_all):
    #if "\x1b" in data_all:
    #    data_all = data_all.replace("\x1b", "")
    #    data_all = trip_prefix(data_all, None)
    members = trip_prefix(data_all, None)
    lines = members.splitlines()
    member = None
    address = None
    port = None
    session = None
    state = None 
    connectionlimit = None
    if len(lines) > 0 and len(lines[0]) >= 10:
        array = split_destination(lines[0])
        member = str(array[0]) + ":" + str(array[1])
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


def data_collect_auth_user(data_all):

    auth_user_list = []

    auth_user_end_str = "cli global-settings"
    if "cli admin-partitions" in data_all:
        auth_user_end_str = "cli admin-partitions"
    auth_users = split_content_to_list_pattern(data_all, r'auth user\s+\S+', auth_user_end_str)
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


def data_collect_net_self(data_all):

    net_self_list = []

    net_self_data_list = split_content_to_list_pattern(data_all, r'net self\s+\S+', "net self-allow")
    for data in net_self_data_list:
        self_data = trip_prefix(data[len("net self"):], None)
        lines = self_data.splitlines()
        self_name = trip_prefix(replace_with_patterns(lines[0], "{"), None)
        self_address = None
        self_allow_service = trip_prefix(replace_with_patterns(find_content_from_start_end(self_data, "allow-service", "}"), ["allow-service", "{"] ), None)
        self_trafficgroup = None 
        self_vlan = None
        for l in lines:
            line = l.strip()
            if line.startswith("address"):
                self_address = trip_prefix(line, "address")
            elif line.startswith("traffic-group"):
                self_trafficgroup = trip_prefix(line, "traffic-group")
            elif line.startswith("vlan"):
                self_vlan = trip_prefix(line, "vlan")

        net_self_list.append(BIGIPNetL3(self_name, self_address, self_allow_service, None, self_trafficgroup, self_vlan))


    return net_self_list


def data_collect_cm_device_group(data_all):

    cm_device_group_lists = [] 
    
    cm_device_group_end_str = "cm key"
    cm_device_group_list = split_content_to_list_pattern(data_all, r'cm device-group\s+\S+', cm_device_group_end_str)
    for dg in cm_device_group_list:
        device_group_data = dg[len("cm device-group"):]
        lines = device_group_data.splitlines()
        dg_name = trip_prefix(replace_with_patterns(lines[0], "{"), None)
        autosync = None 
        devices = [] 
        fullloadonsync = None 
        networkfailover = None 
        type = None
        for l in lines:
            line = l.strip()
            if line.startswith("auto-sync"):
                autosync = trip_prefix(line, "auto-sync")
            elif line.startswith("full-load-on-sync"):
                fullloadonsync = trip_prefix(line, "full-load-on-sync")
            elif line.startswith("network-failover"):
                networkfailover = trip_prefix(line, "network-failover")
            elif line.startswith("type"):
                type = trip_prefix(line, "type")
            elif "{" in line and "}" in line:
                device = trip_prefix(replace_with_patterns(line, ["{", "}"]), None)
                devices.append(device)
        cm_device_group_lists.append(BIGIPDeviceGroup(dg_name, autosync, devices, fullloadonsync, networkfailover, type))
    
    return cm_device_group_lists


def data_collect_cm_device(data_all):

    cm_device_list = []

    cm_device_data = find_content_from_start_end(data_all, "cm device", "cm device-group")
    cm_device = cm_device_data.split("cm device")
    for device in cm_device:
        if len(device) > 10:
            lines = device.splitlines()
            configsync_ip = None
            failover_state = None
            hostname = None 
            management_ip = None
            self_device = None
            time_zone = None
            version = None
            unicast_address = []
            unicast_port = None
            for l in lines:
                line = l.strip()
                if line.startswith("configsync-ip"):
                    configsync_ip = trip_prefix(line, "configsync-ip")
                elif line.startswith("failover-state"):
                    failover_state = trip_prefix(line, "failover-state")
                elif line.startswith("hostname"):
                    hostname = trip_prefix(line, "hostname")
                elif line.startswith("management-ip"):
                    management_ip = trip_prefix(line, "management-ip")
                elif line.startswith("self-device"):
                    self_device = trip_prefix(line, "self-device")
                elif line.startswith("time-zone"):
                    time_zone = trip_prefix(line, "time-zone")
                elif line.startswith("version"):
                    version = trip_prefix(line, "version")
            unicast_addres_data = find_content_from_start_end(device, "unicast-address", "version")
            unicast_lines = unicast_addres_data.splitlines()
            for unicast in unicast_lines:
                address = unicast.strip()
                if address.startswith("effective-ip"):
                    unicast_address.append(trip_prefix(address, "effective-ip"))
                elif address.startswith("effective-port"):
                    unicast_port = convert_servicename_to_port(trip_prefix(address, "effective-port"))
                elif address.startswith("ip"):
                    unicast_address.append(trip_prefix(address, "ip"))
            cm_device_list.append(BIGIPDevice(configsync_ip, failover_state, hostname, management_ip, self_device, time_zone, unicast_address, unicast_port, version))

    return cm_device_list
'''
Deprecated funtions End
'''



def load_f5_services_as_map():
    all_dict = {}
    current_directory = os.path.dirname(os.path.abspath(__file__))
    services_file_path = os.path.join(current_directory,  'f5-services')
    with open(services_file_path) as myfile:
        for line in myfile:
            name, var = line.partition(" ")[::2]
            all_dict[name.strip()] = var.strip()
    myfile.close()
    return all_dict


f5_services_dict = load_f5_services_as_map() 
f5_config_dict = {
    "header": ["auth password-policy", "auth remote-role", "auth remote-user", "auth source", "auth user", "cli admin-partitions", "cli global-settings", "cli preference", "cm cert", "cm device", "cm device-group", "cm key", "cm traffic-group", "cm trust-domain"],
    "ltm": ["ltm data-group", "ltm default-node-monitor", "ltm dns", "ltm global-settings", "ltm monitor", "ltm monitor http", "ltm monitor tcp", "ltm monitor udp", "ltm node", "ltm persistence", "ltm persistence cookie", "ltm persistence global-settings", "ltm persistence source-addr", "ltm policy", "ltm pool", "ltm profile", "ltm profile client-ssl", "ltm profile dns", "ltm profile fastl4", "ltm profile http", "ltm profile http-compression", "ltm profile one-connect", "ltm profile server-ssl", "ltm profile tcp", "ltm profile udp", "ltm profile web-acceleration", "ltm rule", "ltm snat-translation", "ltm snatpool", "ltm tacdb", "ltm virtual"],
    "net": ["net address-list", "net cos", "net dag-globals", "net dns-resolver", "net fdb", "net interface", "net ipsec ike-daemon", "net lldp-globals", "net multicast-globals", "net packet-filter-trusted", "net route", "net route-domain", "net self", "net self-allow", "net stp-globals", "net trunk", "net tunnels", "net vlan"],
    "tail": ["sys config-sync", "sys aom", "sys autoscale-group", "sys daemon-log-settings", "sys datastor", "sys diags", "sys disk", "sys dns", "sys failover", "sys dynad key", "sys dynad", "sys feature-module", "sys file", "sys folder", "sys fpga", "sys global-settings", "sys httpd", "sys icontrol-soap", "sys log-rotate", "sys management-dhcp", "sys management-ip", "sys management-ovsdb", "sys management-route", "sys ntp", "sys outbound-smtp", "sys provision", "sys scriptd", "sys sflow", "sys snmp", "sys software", "sys sshd", "sys state-mirroring", "sys syslog", "sys turboflex", "sys url-db"]
}

def split_data_all(data_all):
 
    data_all = replace_with_patterns(data_all, ["\x1b", "\x1b7", "\x1b6", "\x1b5"])

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

    auth_user_list = data_collect_auth_user(data_all_list[0])
    cm_device_list = data_collect_cm_device(data_all_list[0])
    cm_device_group_list = data_collect_cm_device_group(data_all_list[0])

    net_sel_list = data_collect_net_self(data_all_list[2])

    return {"vs": vs_list, "pool": pool_list, "snatpool": snatpool_list, "node": node_list, "fastl4": profile_fastl4_list, "http": profile_http_list, "auth-user": auth_user_list, "device": cm_device_list, "device-group": cm_device_group_list}


def form_snat_members(memebers, name):
    if name is not None:
        for member in memebers:
            if name == member.name:
                return member.members
    return []
    
def form_pool_members(memebers, name):
    pool_members = []
    if name is not None:
        for member in memebers:
            if name == member.name:
                for m in member.members:
                    pool_members.append(m.member)
                return pool_members
    return pool_members

def form_self_list(net_self_list):
    net_list = []
    for i in net_self_list:
        if i.address is not None:
            net_list.append(ipaddress.ip_network(i.address, False))
    return set(net_list)    

def form_sys_list(devices, device_groups):
    version = 0
    for device in devices:
        if device.version.startswith("10"):
            version = 10
        elif device.version.startswith("11"):
            version = 11
        elif device.version.startswith("12"):
            version = 12
        elif device.version.startswith("13"):
            version = 13
        elif device.version.startswith("14"):
            version = 14
        elif device.version.startswith("15"):
            version = 15
        elif device.version.startswith("16"):
            version = 16
        elif device.version.startswith("17"):
            version = 17 

    device_group = None
    for d in device_groups:
        if d.type == "sync-failover":
            device_group = d.name
            break

    return (version, device_group)


'''
The exist info list contains 3 list:

    info_list: each item represent a list, represent a vs, vs list item:
        0 - vs name
        1 - vs ip
        2 - vs port
        3 - pool name
        4 - pool members
        5 - snatpool name
        6 - snatpool members

    net_set: all exist networks
        eg , {IPv4Network('10.1.10.0/24'), IPv4Network('10.1.20.0/24')}

    sys_list: contain 2 str items:
        0 - software version
        1 - sync group name 
'''
def existinfolist(data_all):

    data_all_list  = split_data_all(data_all)

    vs_list = ltm_virtual(data_all_list[1])
    pool_list = ltm_pool(data_all_list[1])
    snatpool_list = ltm_snatpool(data_all_list[1])
    cm_device_list = cm_device(data_all_list[0])
    cm_device_group_list = cm_device_group(data_all_list[0])
    net_self_list = net_self(data_all_list[2])

    info_list = []
    net_set = form_self_list(net_self_list)
    sys_list = form_sys_list(cm_device_list, cm_device_group_list)
    for vs in vs_list:
        info_list.append((vs.vs_name, vs.vs_ip, vs.vs_port, vs.pool, form_pool_members(pool_list, vs.pool), vs.snatpool, form_snat_members(snatpool_list, vs.snatpool)))

    return (info_list, net_set, sys_list)
