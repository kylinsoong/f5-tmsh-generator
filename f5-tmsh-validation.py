#!/usr/bin/python3

import sys
import ast
import re
import socket
import ipaddress

'''
The Administrator and Auditor user roles that you can assign to a BIG-IP user account:
    
    Administrator          - This is the most powerful user role on the system and grants users complete access to all objects on the system. 
    Auditor                - This is a powerful role that grants read-only access to all configuration data on the system, except for ARP data, archives, 
                             and support tools. Users with this role cannot have other user roles on the system but can change their own user account password. 
                             When granted terminal access, a user with this role has access to TMSH, but not the advanced shell.
'''
def spec_user_management_validation(data_all):
    auth_user_data = re.findall(r'auth user\s+\S+',data_all, re.I)
    user_list = []
    user_role_dict = {}
    for i in auth_user_data:
        user_list.append(i)

    for i,num in zip(auth_user_data,range(len(user_list))):
        if num < len(user_list)-1:
            user_data_start = re.search(i, data_all, re.I).start()
            user_data_end = re.search(user_list[num+1], data_all[user_data_start:]).start()
            user_data_detail = data_all[user_data_start:][:user_data_end]
        else:
            user_data_start = re.search(i, data_all, re.I).start()
            user_data_end = re.search(r'cli global-settings', data_all[user_data_start:]).start()
            user_data_detail = data_all[user_data_start:][:user_data_end]

        user_name_detail_list = re.search(r'auth user\s+(\S+)', user_data_detail,re.I)
        user_name = user_name_detail_list.group(1)
        user_role_detail_list = re.search(r'role\s+(\S+)', user_data_detail,re.I)
        user_role = user_role_detail_list.group(1)
        user_role_dict[user_name] = user_role

    user_validation_list = []
    user_config_note = []
    user_config_spec = SPEC_BASELINE_YES
    user_config_tmsh = []
    if "psbc" not in user_role_dict:
        user_config_note.append(SPEC_USER_MANAGEMENT_PSBC_NOT_EXIST)
        user_config_spec = SPEC_BASELINE_NO
        user_config_tmsh.append("tmsh create auth user psbc password PSBC@BJ*sc*sjzx2022 partition-access add { all-partitions { role admin } } shell bash")
    if "view" not in user_role_dict:
        user_config_note.append(SPEC_USER_MANAGEMENT_VIEW_NOT_EXIST)
        user_config_spec = SPEC_BASELINE_NO
        user_config_tmsh.append("tmsh create auth user view password Viewmon@2020 partition-access add { all-partitions { role auditor } } shell tmsh")

    user_validation_list.append((1, user_config_note, user_config_spec, user_config_tmsh, False))

    default_user_note = ""
    default_user_spec = SPEC_BASELINE_YES
    default_user_tmsh = ""
    if "admin" in user_role_dict:
        default_user_note = SPEC_USER_MANAGEMENT_ADMIN_NOT_DELETE
        default_user_spec = SPEC_BASELINE_NO
        default_user_tmsh = " tmsh modify sys db systemauth.primaryadminuser value psbc"

    user_validation_list.append((2, default_user_note, default_user_spec, default_user_tmsh, False))

    user_role_config_note = []
    user_role_config_spec = SPEC_BASELINE_YES
    user_role_config_tmsh = []
    if "psbc" in user_role_dict and user_role_dict['psbc'] != "admin":
        user_role_config_note.append(SPEC_USER_MANAGEMENT_PSBC_NO_EXPECT_RIGHT)
        user_role_config_spec = SPEC_BASELINE_NO
        user_role_config_tmsh.append("tmsh modify auth user psbc partition-access modify { all-partitions { role admin }}")

    if "view" in user_role_dict and user_role_dict['view'] != "auditor":
        user_role_config_note.append(SPEC_USER_MANAGEMENT_VIEW_NO_EXPECT_RIGHT)
        user_role_config_spec = SPEC_BASELINE_NO
        user_role_config_tmsh.append("tmsh modify auth user view partition-access modify { all-partitions { role auditor }}")

    user_validation_list.append((3, user_role_config_note, user_role_config_spec, user_role_config_tmsh, False))

    return user_validation_list



def spec_login_methods_validation(data_all):
    user_login_data = re.findall(r'net self\s+\S+',data_all, re.I)
    self_name_list = []
    for i in user_login_data:
        self_name_list.append(i)
    user_login_validation_list = []
    self_allow_default_note = ""
    self_allow_default_spec = SPEC_BASELINE_YES
    self_allow_default_tmsh = []
    for i,num in zip(user_login_data,range(len(self_name_list))):
        if num < len(self_name_list)-1:
            user_login_data_start = re.search(i, data_all, re.I).start()
            user_login_data_end = re.search(self_name_list[num+1], data_all[user_login_data_start:]).start()
            user_login_data_detail = data_all[user_login_data_start:][:user_login_data_end]
        else:
            user_login_data_start = re.search(i, data_all, re.I).start()
            user_login_data_end = re.search(r'net self-allow ', data_all[user_login_data_start:]).start()
            user_login_data_detail = data_all[user_login_data_start:][:user_login_data_end]

        self_name_detail_list = re.search(r'net self\s+(\S+)', user_login_data_detail,re.I)
        self_name = self_name_detail_list.group(1)
        allow_service_detail_list = re.search(r'allow-service\s+(\S+)', user_login_data_detail,re.I)
        if allow_service_detail_list:
            allow_service_start = allow_service_detail_list.start()
            allow_service_end = re.search(r'}', user_login_data_detail[allow_service_start:]).start()
            allow_service_detail = user_login_data_detail[allow_service_start:][:allow_service_end]
            allow_service_value_start = re.search(r'{\s+(\S+)', allow_service_detail,re.I).start()
            allow_service_value = allow_service_detail[allow_service_value_start:]
            allow_service_value = allow_service_value.strip().lstrip("{").strip()
            if allow_service_value == "default":
                self_allow_default_note = SPEC_LOGIN_METHODS_ALLOW_DEFAULT
                self_allow_default_spec = SPEC_BASELINE_NO
                tmsh = "tmsh modify net self " + self_name + " allow-service none"
                self_allow_default_tmsh.append(tmsh)

    user_login_validation_list.append((4, self_allow_default_note, self_allow_default_spec, self_allow_default_tmsh, False))
    user_login_validation_list.append((5, self_allow_default_note, self_allow_default_spec, self_allow_default_tmsh, False))

    timeout_validation_note = ""
    timeout_validation_spec = SPEC_BASELINE_YES
    timeout_validation_tmsh = []
    sshd_data_start = re.search(r'sys sshd\s+(\S+)', data_all,re.I).start()
    sshd_timeout_start = re.search(r'inactivity-timeout\s+(\S+)', data_all[sshd_data_start:],re.I).start()
    sshd_timeout_end = re.search(r'}', data_all[sshd_data_start:][sshd_timeout_start:]).start()
    sshd_timeout = data_all[sshd_data_start:][sshd_timeout_start:][:sshd_timeout_end]
    sshd_timeout = sshd_timeout.lstrip("inactivity-timeout").rstrip("}").strip()
    if sshd_timeout != "720":
        timeout_validation_note = SPEC_LOGIN_METHODS_TIMEOUT_NO_12_MINS
        timeout_validation_spec = SPEC_BASELINE_NO
        timeout_validation_tmsh.append("tmsh modify sys sshd inactivity-timeout 720")

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

    user_login_validation_list.append((6, timeout_validation_note, timeout_validation_spec, timeout_validation_tmsh, False))
    
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
    if timezone != "Asia/Shanghai" :
        timezone_validation_note = SPEC_NTP_SETTINGS_TIMEZONE_WRONG
        timezone_validation_spec = SPEC_BASELINE_NO
        timezone_validation_tmsh.append("tmsh modify sys  ntp { timezone  Asia/Shanghai}")
    ntp_validation_list.append((7, timezone_validation_note, timezone_validation_spec, timezone_validation_tmsh, False))

    servers_start = re.search("servers", ntp_data,re.I).start()
    servers_end = re.search("}", ntp_data[servers_start:],re.I).start()
    servers = ntp_data[servers_start:][:servers_end]
    servers = servers.replace("{ ", "")
    ntp_validation_list.append((8, "", SPEC_BASELINE_YES, ["ntp " + servers], True))
    return ntp_validation_list



def spec_snmp_management_validation(data_all):
    snmp_validation_list = []
    snmp_data_start = re.search("sys snmp", data_all,re.I).start()
    snmp_data_end = re.search("sys software image", data_all[snmp_data_start:],re.I).start()
    snmp_data = data_all[snmp_data_start:][:snmp_data_end]

    snmp_validation_list.append((9, "", SPEC_BASELINE_YES, [], False))
    snmp_validation_list.append((10, "", SPEC_BASELINE_YES, ["v2c"], False))

    if "psbcread" not in snmp_data:
        snmp_validation_list.append((11, "", SPEC_BASELINE_NO, ["tmsh modify sys snmp communities add { XXXXX { community-name psbcread source default oid-subset 1 access ro } }"], False))

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
            tmsh = "name: " + trap_name + ", host: " + trap_host + ", port: " + convert_servicename_to_port(trap_port)
            snmp_trap_host_port_list.append(tmsh)

    if len(snmp_trap_host_port_list) > 0:
        snmp_validation_list.append((12, "", SPEC_BASELINE_YES, snmp_trap_host_port_list, True))
    else:
        snmp_validation_list.append((12, "", SPEC_BASELINE_NO, ["tmsh modify sys snmp traps add { XXXXX  { version 2c community psbcread host XX.XX.XX.XX  port XXX } } "], True))

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
        syslog_validation_list.append((13, "", SPEC_BASELINE_YES, [syslog_data], True))
    else:
        syslog_validation_list.append((13, "", SPEC_BASELINE_NO, ["tmsh modify sys syslog remote-servers add { XXXX { host XXX.XXX.XXX.XXX remote-port XXX local-ip XXX.XXX.XXX.XXX } }"], True))

    syslog_validation_list.append((14, "", SPEC_BASELINE_YES, ["tmsh  modify  sys  syslog  local6-from notice"], False))
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
        secure_acl_validation_list.append((15, "", SPEC_BASELINE_YES, [httpd_allow], True))
    else:
        secure_acl_validation_list.append((15, "", SPEC_BASELINE_NO, ["tmsh modify sys httpd allow add { xxx.xxx.xxx.xxx/xx }"], True))

    if len(sshd_allow) > 20:
        secure_acl_validation_list.append((16, "", SPEC_BASELINE_YES, [sshd_allow], True))
    else:
        secure_acl_validation_list.append((16, "", SPEC_BASELINE_NO, ["tmsh modify sys sshd allow add { xxx.xxx.xxx.xxx/xx }"], True))

    #if len(snmp_allowed_address) > 30:
    #   secure_acl_validation_list.append((101, "", SPEC_BASELINE_YES, [snmp_allowed_address], True))
    #else:
    #   secure_acl_validation_list.append((101, "", SPEC_BASELINE_NO, ["tmsh modify sys snmp allowed-addresses add { xxx.xxx.xxx.xxx  }"], True))

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

        interface_validation_list.append((17, "", SPEC_BASELINE_YES, [inter_data_detail], False))

        if "lacp enabled" in data_detail:
            interface_validation_list.append((17, "", SPEC_BASELINE_NO, [trunk_disable_tmsh], False))

    if len(interface_validation_list) <= 0:
        interface_validation_list.append((17, "", SPEC_BASELINE_NO, ["tmsh create net trunk XXXX interfaces add { X.X }"], False))
        interface_validation_list.append((18, "", SPEC_BASELINE_NO, ["tmsh create net trunk XXXX interfaces add { X.X }"], True))
    else:
        interface_validation_list.append((18, SEPC_INTERFACE_HA_ON_BUSINESS_TRUNK, SPEC_BASELINE_YES, [""], True))

    net_interface_unused = []
    net_interface_data = find_content_from_start_end(data_all, "net interface", "net interface mgmt")
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
        interface_validation_list.append((19, SPEC_INTERFACE_UNUSED_UNDISABLED, SPEC_BASELINE_NO, net_interface_disable_list, False))
    else:
        interface_validation_list.append((19, "", SPEC_BASELINE_YES, [], False))

    return interface_validation_list



def spec_route_configuration_validation(data_all):

    route_validation_list = []
    mgmt_route_data = find_content_from_start_end(data_all, "sys management-route default", "sys ntp")
    gateways = re.search(r'gateway\s+(\S+)', mgmt_route_data, re.I)
    if gateways:
        management_route = gateways.group()
        management_route = "sys management-route default " + management_route
        route_validation_list.append((20, "", SPEC_BASELINE_YES, [management_route], True))
    else:
        route_validation_list.append((20, "", SPEC_BASELINE_NO, ["tmsh create sys  management-route default gateway xxx.xxx.xxx.xxx"], True))

    net_self_all = []
    net_self_data = find_content_from_start_end(data_all, "net self", "net self-allow")
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
    net_route_data = find_content_from_start_end(data_all, "net route", "net route-domain")
    net_route_list = net_route_data.split("net route")
    for i in net_route_list:
        results = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b", i)
        if(len(results) > 0):
            net_route_all.append(results[0])

    if len(net_route_all) == 0:
        route_validation_list.append((21, SPEC_ROUTE_DEFAULT_GATEWAY, SPEC_BASELINE_NO, ["tmsh create net route default gw xxx.xxx.xxx.xxx"], True))
    
    invalid_route_list = []
    for ip in net_route_all:
        ip_addr = ipaddress.ip_address(ip)
        if not any(ip_addr in network for network in unique_networks):
            invalid_route_list.append(ip)

    if len(invalid_route_list) > 0:
        route_validation_list.append((21, SPEC_ROUTE_DEFAULT_GATEWAY_NEXT_HOP, SPEC_BASELINE_NO, invalid_route_list, True))
    else:
        route_validation_list.append((21, "", SPEC_BASELINE_YES, net_route_all, True))

    return route_validation_list



def spec_ha_configuration_validation(data_all):

    ha_validation_list = []
  
    ha_devices_list = []
    ha_devices_data = find_content_from_start_end(data_all, "cm device", "cm device-group")
    ha_devices = ha_devices_data.split("cm device")
    for device in ha_devices:
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
            ha_devices_list.append(BIGIPDevice(configsync_ip, failover_state, hostname, management_ip, self_device, time_zone, unicast_address, unicast_port, version))

    for i in ha_devices_list:
        print(i.configsync_ip, i.failover_state, i.hostname, i.management_ip, i.self_device, i.time_zone, i.unicast_address, i.unicast_port, i.version)

    return ha_validation_list



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

class Spec:
    def __init__(self, name, hostname, management_ip, data):
        self.name = name
        self.hostname = hostname
        self.management_ip = management_ip
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
        print(self.management_ip, self.hostname, self.name)

class SpecTCPConnectionConfiguration(Spec):
    def parse(self):
        print(self.management_ip, self.hostname, self.name)

class SpecSNATConfiguration(Spec):
    def parse(self):
        print(self.management_ip, self.hostname, self.name)

class SpecHTTPRstActionDownSetting(Spec):
    def parse(self):
        print(self.management_ip, self.hostname, self.name)



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

    return (hostname, management_ip)
    


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



def load_f5_services_as_map():
    all_dict = {}
    with open("f5-services") as myfile:
        for line in myfile:
            name, var = line.partition(" ")[::2]
            all_dict[name.strip()] = var.strip()
    myfile.close()
    return all_dict
 


'''
Main function(start place)
'''
if not sys.argv[2:]:
    print("Usage: f5-tmsh-validation.py [file] [file]")
    sys.exit()

fileconfig = sys.argv[1]
fileadd = sys.argv[2]

#data_collect(fileconfig)

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

bigip_running_config = load_bigip_running_config(fileconfig)
f5_services_dict = load_f5_services_as_map()
device_info = data_collect_system_extract_hostname(bigip_running_config)

spec_validation_list = []

spec_validation_list.append(SpecUserManagement(SPEC_ITEM_USER_MANAGEMENT, device_info[0], device_info[1], bigip_running_config))
spec_validation_list.append(SpecLoginMethods(SPEC_ITEM_EXLOGIN_METHODS, device_info[0], device_info[1], bigip_running_config))
spec_validation_list.append(SpecNTPSyncSetting(SPEC_ITEM_NTPSYN_SETTINGS, device_info[0], device_info[1], bigip_running_config))
spec_validation_list.append(SpecSNMPManagement(SPEC_ITEM_SNMP_MANAGEMENT, device_info[0], device_info[1], bigip_running_config))
spec_validation_list.append(SpecSyslogSetting(SPEC_ITEM_SYSLOG_SETTINGS, device_info[0], device_info[1], bigip_running_config))
spec_validation_list.append(SpecSecureACLControl(SPEC_ITEM_SEC_ACL_CONTROL, device_info[0], device_info[1], bigip_running_config))

spec_validation_list.append(SpecInterfaceConfiguration(SPEC_ITEM_INTERFACES_CONF, device_info[0], device_info[1], bigip_running_config))
spec_validation_list.append(SpecRouteConfiguration(SPEC_ITEM_INEXROUTER_CONF, device_info[0], device_info[1], bigip_running_config))
spec_validation_list.append(SpecHAConfiguration(SPEC_ITEM_HASETTINGS_CONF, device_info[0], device_info[1], bigip_running_config))
spec_validation_list.append(SpecFailoverSetting(SPEC_ITEM_FAILOVERS_CHECK, device_info[0], device_info[1], bigip_running_config))

spec_validation_list.append(SpecTCPConnectionConfiguration(SPEC_ITEM_TCP_CONNECTIONS, device_info[0], device_info[1], bigip_running_config))
spec_validation_list.append(SpecSNATConfiguration(SPEC_ITEM_SNATPOOLME_CONF, device_info[0], device_info[1], bigip_running_config))
spec_validation_list.append(SpecHTTPRstActionDownSetting(SPEC_ITEM_HTTP_RST_ONDOWN, device_info[0], device_info[1], bigip_running_config))

#for spec in spec_validation_list:
#    spec.write_to_excel()
