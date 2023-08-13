#!/usr/bin/python3

import sys
import ast
import re
import socket
import ipaddress

from f5bigip import configParse
from f5bigip import tmsh

'''
The Administrator and Auditor user roles that you can assign to a BIG-IP user account:
    
    Administrator          - This is the most powerful user role on the system and grants users complete access to all objects on the system. 
    Auditor                - This is a powerful role that grants read-only access to all configuration data on the system, except for ARP data, archives, 
                             and support tools. Users with this role cannot have other user roles on the system but can change their own user account password. 
                             When granted terminal access, a user with this role has access to TMSH, but not the advanced shell.
'''
def spec_user_management_validation(data_all):
   
    user_role_dict = {}
    user_list = configParse.auth_user(data_all)    
    for i in user_list:
        user_role_dict[i.name] = i.role    
    
    user_validation_list = []
    user_config_note = []
    user_config_spec = SPEC_BASELINE_YES
    user_config_tmsh = []
    user_config_rollback_tmsh = []
    if "psbc" not in user_role_dict:
        user_config_note.append(SPEC_USER_MANAGEMENT_PSBC_NOT_EXIST)
        user_config_spec = SPEC_BASELINE_NO
        user_config_tmsh.append("tmsh create auth user psbc password PSBC@BJ*sc*sjzx2022 partition-access add { all-partitions { role admin } } shell bash")
        user_config_rollback_tmsh.append("tmsh delete auth user psbc")
    if "view" not in user_role_dict:
        user_config_note.append(SPEC_USER_MANAGEMENT_VIEW_NOT_EXIST)
        user_config_spec = SPEC_BASELINE_NO
        user_config_tmsh.append("tmsh create auth user view password Viewmon@2020 partition-access add { all-partitions { role auditor } } shell tmsh")
        user_config_rollback_tmsh.append("tmsh delete auth user view")

    user_validation_list.append((1, user_config_note, user_config_spec, user_config_tmsh,user_config_rollback_tmsh,  False))

    default_user_note = ""
    default_user_spec = SPEC_BASELINE_YES
    default_user_tmsh = ""
    default_user_rollback_tmsh = ""
    if "admin" in user_role_dict:
        default_user_note = SPEC_USER_MANAGEMENT_ADMIN_NOT_DELETE
        default_user_spec = SPEC_BASELINE_NO
        default_user_tmsh = "tmsh modify sys db systemauth.primaryadminuser value psbc"
        default_user_rollback_tmsh = "tmsh modify sys db systemauth.primaryadminuser value admin"

    user_validation_list.append((2, default_user_note, default_user_spec, default_user_tmsh, default_user_rollback_tmsh, False))

    user_role_config_note = []
    user_role_config_spec = SPEC_BASELINE_YES
    user_role_config_tmsh = []
    user_role_config_rollback_tmsh = []
    if "psbc" in user_role_dict and user_role_dict['psbc'] != "admin":
        user_role_config_note.append(SPEC_USER_MANAGEMENT_PSBC_NO_EXPECT_RIGHT)
        user_role_config_spec = SPEC_BASELINE_NO
        user_role_config_tmsh.append("tmsh modify auth user psbc partition-access modify { all-partitions { role admin }}")
        user_role_config_rollback_tmsh.append("tmsh modify auth user psbc partition-access modify { all-partitions { role " + user_role_dict['psbc'] + " }}")

    if "view" in user_role_dict and user_role_dict['view'] != "auditor":
        user_role_config_note.append(SPEC_USER_MANAGEMENT_VIEW_NO_EXPECT_RIGHT)
        user_role_config_spec = SPEC_BASELINE_NO
        user_role_config_tmsh.append("tmsh modify auth user view partition-access modify { all-partitions { role auditor }}")
        user_role_config_rollback_tmsh.append("tmsh modify auth user view partition-access modify { all-partitions { role " + user_role_dict['view'] + " }}")

    user_validation_list.append((3, user_role_config_note, user_role_config_spec, user_role_config_tmsh, user_role_config_rollback_tmsh, False))

    return user_validation_list



def spec_login_methods_validation(data_all):

    user_login_validation_list = []
    self_allow_default_note = ""
    self_allow_default_spec = SPEC_BASELINE_YES
    self_allow_default_tmsh = []
    self_allow_default_rollback_tmsh = []

    net_self_list = configParse.net_self(data_all)
    for i in net_self_list:
        if i.allowservice == "default":
            self_allow_default_note = SPEC_LOGIN_METHODS_ALLOW_DEFAULT
            self_allow_default_spec = SPEC_BASELINE_NO
            tmsh = "tmsh modify net self " + i.name + " allow-service none"
            tmsh_rollback = "tmsh modify net self " + i.name + " allow-service default"
            self_allow_default_tmsh.append(tmsh)
            self_allow_default_rollback_tmsh.append(tmsh_rollback)


    user_login_validation_list.append((4, self_allow_default_note, self_allow_default_spec, self_allow_default_tmsh, self_allow_default_rollback_tmsh, False))
    user_login_validation_list.append((5, self_allow_default_note, self_allow_default_spec, self_allow_default_tmsh, self_allow_default_rollback_tmsh, False))

    timeout_validation_note = ""
    timeout_validation_spec = SPEC_BASELINE_YES
    timeout_validation_tmsh = []
    timeout_validation_rollback_tmsh = []
    sshd_data_start = re.search(r'sys sshd\s+(\S+)', data_all,re.I).start()
    sshd_timeout_start = re.search(r'inactivity-timeout\s+(\S+)', data_all[sshd_data_start:],re.I).start()
    sshd_timeout_end = re.search(r'}', data_all[sshd_data_start:][sshd_timeout_start:]).start()
    sshd_timeout = data_all[sshd_data_start:][sshd_timeout_start:][:sshd_timeout_end]
    sshd_timeout = sshd_timeout.lstrip("inactivity-timeout").rstrip("}").strip()
    if sshd_timeout != "720":
        timeout_validation_note = SPEC_LOGIN_METHODS_TIMEOUT_NO_12_MINS
        timeout_validation_spec = SPEC_BASELINE_NO
        timeout_validation_tmsh.append("tmsh modify sys sshd inactivity-timeout 720")
        timeout_validation_rollback_tmsh.append("tmsh modify sys sshd inactivity-timeout " + sshd_timeout)

    httpd_data_start = re.search(r'sys httpd\s+(\S+)', data_all,re.I).start()
    httpd_timeout_start = re.search(r'auth-pam-idle-timeout\s+(\S+)', data_all[httpd_data_start:],re.I).start()
    httpd_timeout_end = re.search(r'}', data_all[httpd_data_start:][httpd_timeout_start:]).start()
    httpd_timeout = data_all[httpd_data_start:][httpd_timeout_start:][:httpd_timeout_end]
    httpd_timeout_line = re.search(r'auth-pam-idle-timeout\s+(\S+)', httpd_timeout, re.I).group()
    httpd_timeout = httpd_timeout_line.lstrip("auth-pam-idle-timeout").strip()
    if httpd_timeout != "720":
        timeout_validation_note = SPEC_LOGIN_METHODS_TIMEOUT_NO_12_MINS
        timeout_validation_spec = SPEC_BASELINE_NO
        timeout_validation_tmsh.append("tmsh modify sys httpd auth-pam-idle-timeout 720")
        timeout_validation_rollback_tmsh.append("tmsh modify sys httpd auth-pam-idle-timeout " + httpd_timeout)

    user_login_validation_list.append((6, timeout_validation_note, timeout_validation_spec, timeout_validation_tmsh, timeout_validation_rollback_tmsh, False))
    
    return user_login_validation_list



def spec_ntp_settings_validation(data_all):
    ntp_validation_list = []
    ntp_data_start = re.search("sys ntp", data_all,re.I).start()
    ntp_data_end = re.search("sys outbound-smtp", data_all[ntp_data_start:],re.I).start()
    ntp_data = data_all[ntp_data_start:][:ntp_data_end]
    timezone_line = re.search(r'timezone\s+(\S+)', ntp_data, re.I).group()
    timezone = timezone_line.lstrip("timezone").strip()
    timezone_validation_note = ""
    timezone_validation_spec = SPEC_BASELINE_YES
    timezone_validation_tmsh = []
    timezone_validation_rollback_tmsh = []
    if timezone != "Asia/Shanghai" :
        timezone_validation_note = SPEC_NTP_SETTINGS_TIMEZONE_WRONG
        timezone_validation_spec = SPEC_BASELINE_NO
        timezone_validation_tmsh.append("tmsh modify sys  ntp { timezone  Asia/Shanghai}")
        timezone_validation_rollback_tmsh.append("tmsh modify sys  ntp { timezone  " + timezone + "}")
    ntp_validation_list.append((7, timezone_validation_note, timezone_validation_spec, timezone_validation_tmsh, False))

    servers_start = re.search("servers", ntp_data,re.I).start()
    servers_end = re.search("}", ntp_data[servers_start:],re.I).start()
    servers = ntp_data[servers_start:][:servers_end]
    servers = servers.replace("{ ", "")
    ntp_validation_list.append((8, "", SPEC_BASELINE_YES, ["ntp " + servers], [], True))
    return ntp_validation_list



def spec_snmp_management_validation(data_all):
    snmp_validation_list = []
    snmp_data_start = re.search("sys snmp", data_all,re.I).start()
    snmp_data_end = re.search("sys software image", data_all[snmp_data_start:],re.I).start()
    snmp_data = data_all[snmp_data_start:][:snmp_data_end]

    snmp_validation_list.append((9, "", SPEC_BASELINE_YES, [], [], False))
    snmp_validation_list.append((10, "", SPEC_BASELINE_YES, ["v2c"], [], False))

    if "psbcread" not in snmp_data:
        snmp_validation_list.append((11, "", SPEC_BASELINE_NO, ["tmsh modify sys snmp communities add { XXXXX { community-name psbcread source default oid-subset 1 access ro } }"], [], False))

    snmp_traps_data_start = re.search("traps {", snmp_data, re.I).start()
    snmp_traps_data = snmp_data[snmp_traps_data_start:]
    snmp_traps_data = snmp_traps_data.lstrip("traps")
    snmp_traps_data = snmp_traps_data.replace("{", "")
    snmp_trap_list = snmp_traps_data.split('}')
    snmp_trap_host_port_list = []
    for i in snmp_trap_list:
        lines = i.splitlines()
        isFirstLine = True
        trap_name = ""
        trap_host = ""
        trap_port = ""
        for l in lines:
            line = l.strip()
            if len(line) > 0 and isFirstLine:
                 isFirstLine = False
                 trap_name = line
            elif len(line) > 0 and line.startswith("host"):
                 trap_host = line.lstrip("host").strip()
            elif len(line) > 0 and line.startswith("port"):
                 trap_port = line.lstrip("port").strip()
        if len(trap_name) > 0 and len(trap_host) > 0 and len(trap_port):
            tmsh = "name: " + trap_name + ", host: " + trap_host + ", port: " + configParse.convert_servicename_to_port(trap_port)
            snmp_trap_host_port_list.append(tmsh)

    if len(snmp_trap_host_port_list) > 0:
        snmp_validation_list.append((12, "", SPEC_BASELINE_YES, snmp_trap_host_port_list, [], True))
    else:
        snmp_validation_list.append((12, "", SPEC_BASELINE_NO, ["tmsh modify sys snmp traps add { XXXXX  { version 2c community psbcread host XX.XX.XX.XX  port XXX } } "], [], True))

    return snmp_validation_list



'''
syslog setting spec:

'''
def spec_syslog_settings_validation(data_all):
    syslog_validation_list = []
    syslog_data_start = re.search("sys syslog", data_all,re.I).start()
    syslog_data_end = re.search("sys turboflex profile-config", data_all[syslog_data_start:],re.I).start()
    syslog_data = data_all[syslog_data_start:][:syslog_data_end]
    if len(syslog_data) > 30:
        syslog_validation_list.append((13, "", SPEC_BASELINE_YES, [syslog_data], [], True))
    else:
        syslog_validation_list.append((13, "", SPEC_BASELINE_NO, ["tmsh modify sys syslog remote-servers add { XXXX { host XXX.XXX.XXX.XXX remote-port XXX local-ip XXX.XXX.XXX.XXX } }"], [], True))

    syslog_validation_list.append((14, "", SPEC_BASELINE_YES, ["tmsh  modify  sys  syslog  local6-from notice"], [], False))
    return syslog_validation_list



def spec_secure_acl_validation(data_all):
    sshd_allow_data_start = re.search(r'sys sshd\s+(\S+)', data_all,re.I).start()
    sshd_allow_data_end = re.search(r'inactivity-timeout\s+(\S+)', data_all[sshd_allow_data_start:],re.I).start()
    sshd_allow = data_all[sshd_allow_data_start:][:sshd_allow_data_end]
    sshd_allow = sshd_allow.lstrip("sys sshd").strip().lstrip("{").strip()
    sshd_allow = "sshd " + sshd_allow

    httpd_allow_data_start = re.search(r'sys httpd\s+(\S+)', data_all,re.I).start()
    httpd_allow_data_end = re.search(r'auth-pam-idle-timeout\s+(\S+)', data_all[httpd_allow_data_start:],re.I).start()
    httpd_allow = data_all[httpd_allow_data_start:][:httpd_allow_data_end]
    httpd_allow = httpd_allow.lstrip("sys httpd").strip().lstrip("{").strip()
    httpd_allow = "https " + httpd_allow

    snmp_data_start = re.search("sys snmp", data_all,re.I).start()
    snmp_data_end = re.search("sys software image", data_all[snmp_data_start:],re.I).start()
    snmp_data = data_all[snmp_data_start:][:snmp_data_end]
    snmp_allowed_address = ""
    snmp_allowed_address_start = re.search("allowed-addresses", snmp_data,re.I).start()
    snmp_allowed_address_end = re.search("communities", snmp_data[snmp_allowed_address_start:],re.I).start()
    snmp_allowed_address_raw = snmp_data[snmp_allowed_address_start:][:snmp_allowed_address_end]
    if len(snmp_allowed_address_raw) > 20:
        snmp_allowed_address = "snmp " + snmp_allowed_address_raw

    secure_acl_validation_list = []

    if len(httpd_allow) > 20:
        secure_acl_validation_list.append((15, "", SPEC_BASELINE_YES, [httpd_allow], [], True))
    else:
        secure_acl_validation_list.append((15, "", SPEC_BASELINE_NO, ["tmsh modify sys httpd allow add { xxx.xxx.xxx.xxx/xx }"], [], True))

    if len(sshd_allow) > 20:
        secure_acl_validation_list.append((16, "", SPEC_BASELINE_YES, [sshd_allow], [], True))
    else:
        secure_acl_validation_list.append((16, "", SPEC_BASELINE_NO, ["tmsh modify sys sshd allow add { xxx.xxx.xxx.xxx/xx }"], [], True))

    #if len(snmp_allowed_address) > 30:
    #   secure_acl_validation_list.append((101, "", SPEC_BASELINE_YES, [snmp_allowed_address], [], True))
    #else:
    #   secure_acl_validation_list.append((101, "", SPEC_BASELINE_NO, ["tmsh modify sys snmp allowed-addresses add { xxx.xxx.xxx.xxx  }"], [], True))

    return secure_acl_validation_list




def net_interface_not_disabled(text):
    return "disabled" not in text

def spec_interface_configuration_validation(data_all):
    interface_validation_list = []
    net_trunk_data = re.findall(r'net trunk\s+\S+',data_all, re.I)
    net_trunk_list = []
    for i in net_trunk_data:
        net_trunk_list.append(i)

    for i,num in zip(net_trunk_data,range(len(net_trunk_list))):
        if num < len(net_trunk_list)-1:
            data_start = re.search(i, data_all, re.I).start()
            data_end = re.search(net_trunk_list[num+1], data_all[data_start:]).start()
            data_detail = data_all[data_start:][:data_end]
        else:
            data_start = re.search(i, data_all, re.I).start()
            data_end = re.search(r'net tunnels', data_all[data_start:]).start()
            data_detail = data_all[data_start:][:data_end]

        matches = re.search(r'net trunk\s+(\S+)', data_detail, re.I)
        trunk_name = matches.group()
        trunk_name = trunk_name[len("net trunk"):]
        trunk_disable_tmsh = "tmsh modify  net  trunk " + trunk_name + " lacp disabled"

        inter_data_start = re.search("interfaces", data_detail, re.I).start()
        inter_data_end = re.search(r'}', data_detail[inter_data_start:]).start()
        inter_data_detail = data_detail[inter_data_start:][:inter_data_end + 1]
        inter_data_detail = trunk_name + " " + inter_data_detail

        interface_validation_list.append((17, "", SPEC_BASELINE_YES, [inter_data_detail], [], False))

        if "lacp enabled" in data_detail:
            interface_validation_list.append((17, "", SPEC_BASELINE_NO, [trunk_disable_tmsh], [], False))

    if len(interface_validation_list) <= 0:
        interface_validation_list.append((17, "", SPEC_BASELINE_NO, ["tmsh create net trunk XXXX interfaces add { X.X }"], [], False))
        interface_validation_list.append((18, "", SPEC_BASELINE_NO, ["tmsh create net trunk XXXX interfaces add { X.X }"], [], True))
    else:
        interface_validation_list.append((18, SEPC_INTERFACE_HA_ON_BUSINESS_TRUNK, SPEC_BASELINE_YES, [""], [], True))

    net_interface_unused = []
    net_interface_data = configParse.find_content_from_start_end(data_all, "net interface", "net interface mgmt")
    net_interface_list = net_interface_data.split("}")
    for text in net_interface_list:
        if "bundle-speed" not in text and "media-active" not in text:
            net_interface_unused.append(text)
    
    net_interface_disable_list = []
    net_interface_undisabled = list(filter(net_interface_not_disabled, net_interface_unused))
    for text in net_interface_undisabled:
        lines = text.strip().splitlines()
        if len(lines) > 0:
            net_interface = lines[0]
            net_interface = net_interface.strip().rstrip("{").strip()
            tmsh_disable_interface = "tmsh modify " + net_interface + " disabled"
            net_interface_disable_list.append(tmsh_disable_interface)
          
    if len(net_interface_disable_list) > 0 :
        interface_validation_list.append((19, SPEC_INTERFACE_UNUSED_UNDISABLED, SPEC_BASELINE_NO, net_interface_disable_list, [], False))
    else:
        interface_validation_list.append((19, "", SPEC_BASELINE_YES, [], [], False))

    return interface_validation_list



def spec_route_configuration_validation(data_all):

    route_validation_list = []
    mgmt_route_data = configParse.find_content_from_start_end(data_all, "sys management-route default", "sys ntp")
    gateways = re.search(r'gateway\s+(\S+)', mgmt_route_data, re.I)
    if gateways:
        management_route = gateways.group()
        management_route = "sys management-route default " + management_route
        route_validation_list.append((20, "", SPEC_BASELINE_YES, [management_route], [], True))
    else:
        route_validation_list.append((20, "", SPEC_BASELINE_NO, ["tmsh create sys  management-route default gateway xxx.xxx.xxx.xxx"], [], True))

    net_self_all = []
    net_self_data = configParse.find_content_from_start_end(data_all, "net self", "net self-allow")
    net_self_list = net_self_data.split("net self")
    for i in net_self_list:
        net_self_results = re.search(r'address\s+(\S+)', i, re.I)
        if net_self_results:
            net_self_raw = net_self_results.group()
            net_self = net_self_raw.lstrip("address").strip()
            net_self_all.append(net_self)

    network_objects = []
    for i in net_self_all:
        cidr = ipaddress.ip_network(i, False)
        network_objects.append(cidr)

    unique_networks = set(network_objects)

    net_route_all = []
    net_route_data = configParse.find_content_from_start_end(data_all, "net route", "net route-domain")
    net_route_list = net_route_data.split("net route")
    for i in net_route_list:
        results = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b", i)
        if(len(results) > 0):
            net_route_all.append(results[0])

    if len(net_route_all) == 0:
        route_validation_list.append((21, SPEC_ROUTE_DEFAULT_GATEWAY, SPEC_BASELINE_NO, ["tmsh create net route default gw xxx.xxx.xxx.xxx"], [], True))
    
    invalid_route_list = []
    for ip in net_route_all:
        ip_addr = ipaddress.ip_address(ip)
        if not any(ip_addr in network for network in unique_networks):
            invalid_route_list.append(ip)

    if len(invalid_route_list) > 0:
        route_validation_list.append((21, SPEC_ROUTE_DEFAULT_GATEWAY_NEXT_HOP, SPEC_BASELINE_NO, invalid_route_list, [], True))
    else:
        route_validation_list.append((21, "", SPEC_BASELINE_YES, net_route_all, [], True))

    return route_validation_list



def spec_ha_configuration_validation(data_all):

    ha_validation_list = []
 
    net_vlan_list = configParse.net_vlan(data_all)
    vlan_failsafe_list = []
    for i in net_vlan_list:
        if i.failsafe is not None:
            vlan_failsafe_list.append(i)
    
    if len(vlan_failsafe_list) > 0:
        for i in vlan_failsafe_list:
            if i.failsafe_action == "failover": 
                ha_validation_list.append((23, "", SPEC_BASELINE_YES, [], [], False))
            else:
               ha_validation_list.append((23, SPEC_HA_FAILSAFE_ERROR, SPEC_BASELINE_NO, [], [], False))
    else:
        ha_validation_list.append((23, SPEC_HA_FAILSAFE_ERROR, SPEC_BASELINE_NO, [], [], False))

    ha_devices_list = configParse.cm_device(data_all)

    if len(ha_devices_list) < 2:
        ha_validation_list.append((24, SPEC_HA_NO_HA_CONF, SPEC_BASELINE_NO, [], [], False))
    elif incorrect_ha_configuration(ha_devices_list):
        ha_validation_list.append((24, SPEC_HA_HA_CONF_NOT_CORRECT, SPEC_BASELINE_NO, [], [], False))
    elif incorrect_time_zone(ha_devices_list):
        ha_validation_list.append((24, SPEC_HA_HA_CONF_NOT_CORRECT_TIMEZONE, SPEC_BASELINE_NO, [], [], False))
    elif incorrect_version(ha_devices_list):
        ha_validation_list.append((24, SPEC_HA_HA_CONF_NOT_CORRECT_VERSION, SPEC_BASELINE_NO, [], [], False))
    elif len(ha_devices_list[0].unicast_address) <= 1:
        ha_validation_list.append((24, SPEC_HA_HA_CONF_NO_MULTI_VLAN, SPEC_BASELINE_NO, [], [], False))
    else:
        ha_validation_list.append((24, "", SPEC_BASELINE_YES, [], [], False))

    ha_device_group_sync_list = []
    cm_device_greoup_list = configParse.cm_device_group(data_all)
    for i in cm_device_greoup_list:
        if i.type == "sync-failover":
            ha_device_group_sync_list.append(i)
    
    if len(ha_device_group_sync_list) == 0:
        ha_validation_list.append((25, SPEC_HA_NO_SYNC_FAILOVER, SPEC_BASELINE_NO, [], [], True))
    elif len(ha_device_group_sync_list) > 1:
        ha_validation_list.append((25, SPEC_HA_MULTI_SYNC_FAILOVER, SPEC_BASELINE_NO, [], [], True))
    elif len(ha_device_group_sync_list) == 1:
        if ha_device_group_sync_list[0].fullloadonsync == "true":
            ha_validation_list.append((25, "", SPEC_BASELINE_YES, [], [], True))
        else:
            ha_validation_list.append((25, SPEC_HA_SYNC_NOT_FINISHED, SPEC_BASELINE_NO, [], [], True))

    return ha_validation_list


def incorrect_version(ha_devices_list):
    version = ha_devices_list[0].version
    for i in ha_devices_list:
        if version != i.version:
            return True
    return False

def incorrect_time_zone(ha_devices_list):
    time_zone = ha_devices_list[0].time_zone
    for i in ha_devices_list:
        if time_zone != i.time_zone:
            return True
    return False

def incorrect_ha_configuration(ha_devices_list):
    active = None
    standby = None
    for i in ha_devices_list:
        if i.failover_state == "active":
            active = True
        elif i.failover_state == "standby":
            standby = True
    if active and standby:
        return False
    else:
        return True



def spec_failover_configuration_validation(data_all):

    failover_validation_list = []

    net_vlan_list = configParse.net_vlan(data_all)
    vlan_failsafe_list = []
    for i in net_vlan_list:
        if i.failsafe is not None:
            vlan_failsafe_list.append(i)

    if len(vlan_failsafe_list) > 0:
        vlan_failsafe = vlan_failsafe_list[0]
        failsafe_timeout = vlan_failsafe_list[0].failsafe_timeout
        if failsafe_timeout is not None and int(failsafe_timeout) > 3:
            failover_validation_list.append((26, "", SPEC_BASELINE_YES, [], False))    
        else:
            failover_validation_list.append((26, SPEC_FAILOVER_FAILSAFE_ERROR, SPEC_BASELINE_NO, [], [], False))
    else:
        failover_validation_list.append((26, SPEC_FAILOVER_FAILSAFE_ERROR, SPEC_BASELINE_NO, [], [], False))

    return failover_validation_list



class Spec:
    def __init__(self, name, hostname, management_ip, software_version, data):
        self.name = name
        self.hostname = hostname
        self.management_ip = management_ip
        self.software_version = software_version
        self.data = data
        self.spec_basic = []
        self.spec_supplementary = []
        self.parse()

    def parse(self):
        pass

    def write_to_excel(self):
        for item in self.spec_basic:
            print(item)

        for item in self.spec_supplementary:
            print(item)

class SpecUserManagement(Spec):
    def parse(self):
        validation_results = spec_user_management_validation(self.data)
        self.spec_basic.extend(validation_results)

class SpecLoginMethods(Spec):
    def parse(self):
        validation_results = spec_login_methods_validation(self.data)
        self.spec_basic.extend(validation_results)

class SpecNTPSyncSetting(Spec):
    def parse(self):
        validation_results = spec_ntp_settings_validation(self.data)
        self.spec_basic.extend(validation_results)

class SpecSNMPManagement(Spec):
    def parse(self):
        validation_results = spec_snmp_management_validation(self.data)
        self.spec_basic.extend(validation_results)

class SpecSyslogSetting(Spec):
    def parse(self):
        validation_results = spec_syslog_settings_validation(self.data)
        self.spec_basic.extend(validation_results)

class SpecSecureACLControl(Spec):
    def parse(self):
        validation_results = spec_secure_acl_validation(self.data)
        self.spec_basic.extend(validation_results)

class SpecInterfaceConfiguration(Spec):
    def parse(self):
        validation_results = spec_interface_configuration_validation(self.data)
        self.spec_basic.extend(validation_results)

class SpecRouteConfiguration(Spec):
    def parse(self):
        validation_results = spec_route_configuration_validation(self.data)
        self.spec_basic.extend(validation_results)

class SpecHAConfiguration(Spec):
    def parse(self):
        validation_results = spec_ha_configuration_validation(self.data)
        self.spec_basic.extend(validation_results)

class SpecFailoverSetting(Spec):
    def parse(self):
        validation_results = spec_failover_configuration_validation(self.data)
        self.spec_basic.extend(validation_results)

class SpecApp(Spec):
    def __init__(self, name, hostname, management_ip, software_version, data, vs_list):
        self.vs_list = vs_list
        super().__init__(name, hostname, management_ip, software_version, data)

class SpecTCPConnectionConfiguration(SpecApp):

    profiles = []

    def parse(self):
        fastl4_list = configParse.ltm_profile_fastl4(self.data)
        for i in fastl4_list:
            self.profiles.append(i.name)
   
        l4_vs_list = list(filter(self.is_tcp_application, self.vs_list))
        notes_list = []
        tmsh_list = []
        tmsh_rollback_list = []
        for vs in l4_vs_list:
            timeout = self.extract_timeout(vs.profiles, fastl4_list) 
            if int(timeout) > 300:
                notes = vs.vs_name + SPEC_APP_TCP_TIEMOUT_LARGER
                tmsh = "tmsh modify ltm profile fastl4 " + vs.profiles[0] + " idle-timeout 300"
                tmsh_rollback = "tmsh modify ltm profile fastl4 " + vs.profiles[0] + " idle-timeout " + timeout
                notes_list.append(notes)
                tmsh_list.append(tmsh)
                tmsh_rollback_list.append(tmsh_rollback)
        
        if len(tmsh_list) > 0:
            self.spec_basic.append((27, notes_list, SPEC_BASELINE_NO, tmsh_list, tmsh_rollback_list, False))
        else:
            self.spec_basic.append((27, [], SPEC_BASELINE_YES, [], [], False))
  
    def extract_timeout(self, profiles, list):
        for i in list:
            if i.name == profiles[0]:
                return i.idle_timeout
        return 0

    def is_tcp_application(self, vs):
        if vs.profiles is not None:
            for profile in vs.profiles:
                return profile in self.profiles
        return False 

class SpecSNATConfiguration(SpecApp):
    def parse(self):
        snatpool_list = configParse.ltm_snatpool(self.data)
        notes_list = []
        tmsh_list = []
        tmsh_rollback_list = [] 
        for vs in self.vs_list:
            if vs.vs_port != "0" and vs.snatpool is None and vs.snatType == "automap":
                notes = vs.vs_name + SPEC_APP_SANT_NO_SANTPOOL
                tmsh = "tmsh create ltm snatpool XX members add { xx.xx.xx.xx }"
                tmsh_rollback = "tmsh delete ltm snatpool XX"
                notes_list.append(notes)
                tmsh_list.append(tmsh)
                tmsh_rollback_list.append(tmsh_rollback)
            elif vs.vs_port != "0" and vs.snatpool is not None:
                snat_pool_obj = self.extract_from_snatpool_list(snatpool_list, vs.snatpool)
                if len(snat_pool_obj.members) < 4:
                    notes = vs.vs_name + SPEC_APP_SANT_SANTPOOL_LESS_FOUR + self.convert_list_to_string(snat_pool_obj.members)
                    tmsh = "tmsh modify ltm snatpool XX members add { xx.xx.xx.xx }" 
                    tmsh_rollback = "tmsh modify ltm snatpool XX members delete { xx.xx.xx.xx }"
                    notes_list.append(notes)
                    tmsh_list.append(tmsh)
                    tmsh_rollback_list.append(tmsh_rollback)
            elif vs.vs_port != "0" and vs.snatpool is None and vs.snatType is None:
                notes = vs.vs_name + SPEC_APP_SANT_NO_SANTPOOL_NO_AUTOMAP
                tmsh = "tmsh create ltm snatpool XX members add { xx.xx.xx.xx }"
                tmsh_rollback = "tmsh delete ltm snatpool XX"
                notes_list.append(notes)
                tmsh_list.append(tmsh)
                tmsh_rollback_list.append(tmsh_rollback)

        if len(tmsh_list) > 0:
            self.spec_basic.append((28, notes_list, SPEC_BASELINE_NO, tmsh_list, tmsh_rollback_list, False))
        else:
            self.spec_basic.append((28, [], SPEC_BASELINE_YES, [], [], False))

    def convert_list_to_string(self, members):
        members_str = ' '.join(members)
        return "[" + members_str + "]"

    def extract_from_snatpool_list(self, snatpool_list, snatpool):
        for i in snatpool_list:
            if i.name == snatpool:
                return i

class SpecHTTPRstActionDownSetting(SpecApp):
    def parse(self):
        http_profiles = []
        fastl4_profiles = []

        fastl4_list = configParse.ltm_profile_fastl4(self.data)
        for i in fastl4_list:
            fastl4_profiles.append(i.name)
        fastl4_profiles.append("fastL4")

        http_list = configParse.ltm_profile_http(self.data)
        for i in http_list:
            http_profiles.append(i.name)
        http_profiles.append("http")

        notes_list = []
        tmsh_list = []
        tmsh_rollback_list = []
        for vs in self.vs_list:
            vs_profiles_list = vs.profiles
            fastL4NotExist = True
            httpExist = False
            for profile in vs_profiles_list:
                if profile in fastl4_profiles:
                    fastL4NotExist = False
                elif profile in http_profiles:
                    httpExist = True
            if fastL4NotExist and httpExist and vs.serviceDownReset is None: 
                notes = vs.vs_name + SPEC_APP_HTTP_SERVICE_DOWN_REST
                tmsh = "tmsh modify ltm virtual " + vs.vs_name + " service-down-immediate-action reset"
                tmsh_rollback = "tmsh modify ltm virtual " + vs.vs_name + " service-down-immediate-action none"
                notes_list.append(notes)
                tmsh_list.append(tmsh)
                tmsh_rollback_list.append(tmsh_rollback)

        if len(tmsh_list) > 0:
            self.spec_basic.append((29, notes_list, SPEC_BASELINE_NO, tmsh_list, tmsh_rollback_list, False))
        else:
            self.spec_basic.append((29, [], SPEC_BASELINE_YES, [], [], False))



def data_collect_system_extract_hostname(data_all):
    devices = configParse.cm_device(data_all)
    return (devices[0].hostname, devices[0].management_ip, devices[0].version)

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
Main function(start place)
'''
if not sys.argv[2:]:
    print("Usage: f5-tmsh-validation.py [file] [file]")
    sys.exit()

fileconfig = sys.argv[1]
fileadd = sys.argv[2]


SPEC_ITEM_USER_MANAGEMENT = "用户管理"
SPEC_ITEM_EXLOGIN_METHODS = "登录方式"
SPEC_ITEM_NTPSYN_SETTINGS = "NTP时钟同步"
SPEC_ITEM_SNMP_MANAGEMENT = "SNMP管理"
SPEC_ITEM_SYSLOG_SETTINGS = "SYSLOG日志"
SPEC_ITEM_SEC_ACL_CONTROL = "安全访问控制"
SPEC_ITEM_INTERFACES_CONF = "接口配置"
SPEC_ITEM_INEXROUTER_CONF = "路由"
SPEC_ITEM_HASETTINGS_CONF = "双机配置"
SPEC_ITEM_FAILOVERS_CHECK = "切换条件检测" 
SPEC_ITEM_TCP_CONNECTIONS = "长连接业务配置"
SPEC_ITEM_SNATPOOLME_CONF = "SNAT配置项检查"
SPEC_ITEM_HTTP_RST_ONDOWN = "后台服务不可用时发rst"

SPEC_BASELINE_YES = "是"
SPEC_BASELINE_NO = "否"
SPEC_USER_MANAGEMENT_PSBC_NOT_EXIST = "psbc 用户不存在"
SPEC_USER_MANAGEMENT_VIEW_NOT_EXIST = "view 用户不存在"
SPEC_USER_MANAGEMENT_ADMIN_NOT_DELETE = "默认用户 admin 未删除"
SPEC_USER_MANAGEMENT_PSBC_NO_EXPECT_RIGHT = "psbc 用户权限不对"
SPEC_USER_MANAGEMENT_VIEW_NO_EXPECT_RIGHT = "view 用户权限不对"
SPEC_LOGIN_METHODS_ALLOW_DEFAULT = "业务口 allow default"
SPEC_LOGIN_METHODS_TIMEOUT_NO_12_MINS = "超时时间不是 12 分钟"
SPEC_NTP_SETTINGS_TIMEZONE_WRONG = "时区设定非中国时区"
SEPC_INTERFACE_HA_ON_BUSINESS_TRUNK = "HA 基于业务 trunk"
SPEC_INTERFACE_UNUSED_UNDISABLED = "未被定义使用的物理端口没有disable"
SPEC_ROUTE_DEFAULT_GATEWAY = "没有默认路由配置"
SPEC_ROUTE_DEFAULT_GATEWAY_NEXT_HOP = "路由下一跳不是对外exernal vlan在交换机上的网关地址"
SPEC_HA_FAILSAFE_ERROR = "failover 配置错误"
SPEC_HA_NO_HA_CONF = "未开启 HA 模式"
SPEC_HA_HA_CONF_NOT_CORRECT = "HA 配置错误"
SPEC_HA_HA_CONF_NOT_CORRECT_TIMEZONE = "HA 配置错误(申请时区不一样)"
SPEC_HA_HA_CONF_NOT_CORRECT_VERSION = "HA 配置错误(设备区设备版本不一致)"
SPEC_HA_HA_CONF_NO_MULTI_VLAN = "心跳传输地址基于单个链路"
SPEC_HA_NO_SYNC_FAILOVER = "无sync-failover配置同步与流量切换配置"
SPEC_HA_MULTI_SYNC_FAILOVER = "多个sync-failover配置同步与流量切换设备组"
SPEC_HA_SYNC_NOT_FINISHED = "设备组中的配置不同步"
SPEC_FAILOVER_FAILSAFE_ERROR = "切换条件检测检测失败"
SPEC_APP_TCP_TIEMOUT_LARGER = " 超时时长大于300秒"
SPEC_APP_SANT_NO_SANTPOOL = " 没有关联 snat pool，而是配置了automap"
SPEC_APP_SANT_SANTPOOL_LESS_FOUR = " snat pool 中地址小于 4, "
SPEC_APP_SANT_NO_SANTPOOL_NO_AUTOMAP = " 没有关联 snat pool"
SPEC_APP_HTTP_SERVICE_DOWN_REST = " 未设置后台服务不可用时发rst"

bigip_running_config = load_bigip_running_config(fileconfig)
device_info = data_collect_system_extract_hostname(bigip_running_config)
vs_list_all = configParse.ltm_virtual(bigip_running_config)


spec_validation_list = []

spec_validation_list.append(SpecUserManagement(SPEC_ITEM_USER_MANAGEMENT, device_info[0], device_info[1], device_info[2], bigip_running_config))
spec_validation_list.append(SpecLoginMethods(SPEC_ITEM_EXLOGIN_METHODS, device_info[0], device_info[1], device_info[2], bigip_running_config))
spec_validation_list.append(SpecNTPSyncSetting(SPEC_ITEM_NTPSYN_SETTINGS, device_info[0], device_info[1], device_info[2], bigip_running_config))
spec_validation_list.append(SpecSNMPManagement(SPEC_ITEM_SNMP_MANAGEMENT, device_info[0], device_info[1], device_info[2], bigip_running_config))
spec_validation_list.append(SpecSyslogSetting(SPEC_ITEM_SYSLOG_SETTINGS, device_info[0], device_info[1], device_info[2], bigip_running_config))
spec_validation_list.append(SpecSecureACLControl(SPEC_ITEM_SEC_ACL_CONTROL, device_info[0], device_info[1], device_info[2], bigip_running_config))

spec_validation_list.append(SpecInterfaceConfiguration(SPEC_ITEM_INTERFACES_CONF, device_info[0], device_info[1], device_info[2], bigip_running_config))
spec_validation_list.append(SpecRouteConfiguration(SPEC_ITEM_INEXROUTER_CONF, device_info[0], device_info[1], device_info[2], bigip_running_config))
spec_validation_list.append(SpecHAConfiguration(SPEC_ITEM_HASETTINGS_CONF, device_info[0], device_info[1], device_info[2], bigip_running_config))
spec_validation_list.append(SpecFailoverSetting(SPEC_ITEM_FAILOVERS_CHECK, device_info[0], device_info[1], device_info[2], bigip_running_config))

spec_validation_list.append(SpecTCPConnectionConfiguration(SPEC_ITEM_TCP_CONNECTIONS, device_info[0], device_info[1], device_info[2], bigip_running_config, vs_list_all))
spec_validation_list.append(SpecSNATConfiguration(SPEC_ITEM_SNATPOOLME_CONF, device_info[0], device_info[1], device_info[2], bigip_running_config, vs_list_all))
spec_validation_list.append(SpecHTTPRstActionDownSetting(SPEC_ITEM_HTTP_RST_ONDOWN, device_info[0], device_info[1], device_info[2], bigip_running_config, vs_list_all))

for spec in spec_validation_list:
    spec.write_to_excel()
