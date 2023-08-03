#!/usr/bin/python3

import sys
import ast
import re
import socket
import ipaddress


'''
Parse Config, the main function:

    data_collect(data_all)        - Parse and extract application realated config    
    data_collect_system(data_all) - Parse and extract system realated config
'''

def data_collect_system_extract_hostname(data_all):
    pattern = r"sys global-settings(.*?)}"
    blocks = re.findall(pattern, data_all, re.DOTALL)
    if len(blocks) >= 1:
        content = blocks[0]
        hostname_list = re.search(r'hostname\s+(\S+)', content, re.I)
        if hostname_list:
            hostname_raw = hostname_list.group()
            hostname = hostname_raw.lstrip("hostname").strip()
            return hostname
        return None
    return None
    
def data_collect_system_extract_users(data_all):
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
    user_config_spec = "是"
    user_config_tmsh = []
    if "psbc" not in user_role_dict:
        user_config_note.append("psbc 用户不存在")
        user_config_spec = "否"
        user_config_tmsh.append("tmsh create auth user psbc password PSBC@BJ*sc*sjzx2022 partition-access add { all-partitions { role admin } } shell bash")
    if "view" not in user_role_dict:
        user_config_note.append("view 用户不存在")
        user_config_spec = "否"
        user_config_tmsh.append("tmsh create auth user view password Viewmon@2020 partition-access add { all-partitions { role auditor } } shell tmsh")

    user_validation_list.append((1, user_config_note, user_config_spec, user_config_tmsh, True))

    default_user_note = ""
    default_user_spec = "是"
    default_user_tmsh = ""
    if "admin" in user_role_dict:
        default_user_note = "默认用户 admin 未删除"
        default_user_spec = "否"
        default_user_tmsh = " tmsh delete auth user admin"

    user_validation_list.append((2, default_user_note, default_user_spec, default_user_tmsh, False))

    user_role_config_note = []
    user_role_config_spec = "是"
    user_role_config_tmsh = []
    if "psbc" in user_role_dict and user_role_dict['psbc'] != "admin":
        user_role_config_note.append("psbc 用户权限不对")
        user_role_config_spec = "否"
        user_role_config_tmsh.append("tmsh modify auth user psbc partition-access modify { all-partitions { role admin }}")

    if "view" in user_role_dict and user_role_dict['view'] != "auditor":
        user_role_config_note.append("view 用户权限不对")
        user_role_config_spec = "否"
        user_role_config_tmsh.append("tmsh modify auth user view partition-access modify { all-partitions { role auditor }}")

    user_validation_list.append((3, user_role_config_note, user_role_config_spec, user_role_config_tmsh, False))

    return user_validation_list

def data_collect_system_extract_login(data_all):
    user_login_data = re.findall(r'net self\s+\S+',data_all, re.I)
    self_name_list = []
    for i in user_login_data:
        self_name_list.append(i)
    user_login_validation_list = []
    self_allow_default_note = ""
    self_allow_default_spec = "是"
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
                self_allow_default_note = "业务口 allow default"
                self_allow_default_spec = "否"
                tmsh = "tmsh modify net self " + self_name + " allow-service none"
                self_allow_default_tmsh.append(tmsh)
    
    user_login_validation_list.append((4, self_allow_default_note, self_allow_default_spec, self_allow_default_tmsh, True))

    timeout_validation_note = ""
    timeout_validation_spec = "是"
    timeout_validation_tmsh = []
    sshd_data_start = re.search(r'sys sshd\s+(\S+)', data_all,re.I).start()
    sshd_timeout_start = re.search(r'inactivity-timeout\s+(\S+)', data_all[sshd_data_start:],re.I).start()
    sshd_timeout_end = re.search(r'}', data_all[sshd_data_start:][sshd_timeout_start:]).start()
    sshd_timeout = data_all[sshd_data_start:][sshd_timeout_start:][:sshd_timeout_end]
    sshd_timeout = sshd_timeout.lstrip("inactivity-timeout").rstrip("}").strip()
    if sshd_timeout != "720":
        timeout_validation_note = "超时时间不是 12 分钟"
        timeout_validation_spec = "否"
        timeout_validation_tmsh.append("tmsh modify sys sshd inactivity-timeout 720")

    sshd_allow = data_all[sshd_data_start:][:sshd_timeout_start]
    sshd_allow = sshd_allow.lstrip("sys sshd").strip().lstrip("{").strip()
    sshd_allow = "sshd " + sshd_allow

    httpd_data_start = re.search(r'sys httpd\s+(\S+)', data_all,re.I).start()
    httpd_timeout_start = re.search(r'auth-pam-idle-timeout\s+(\S+)', data_all[httpd_data_start:],re.I).start()
    httpd_timeout_end = re.search(r'}', data_all[httpd_data_start:][httpd_timeout_start:]).start()
    httpd_timeout = data_all[httpd_data_start:][httpd_timeout_start:][:httpd_timeout_end]
    httpd_timeout_line = re.search(r'auth-pam-idle-timeout\s+(\S+)', httpd_timeout, re.I).group()
    httpd_timeout = httpd_timeout_line.lstrip("auth-pam-idle-timeout").strip()
    if httpd_timeout != "720":
        timeout_validation_note = "超时时间不是 12 分钟"
        timeout_validation_spec = "否"
        timeout_validation_tmsh.append("tmsh modify sys httpd auth-pam-idle-timeout 720")

    user_login_validation_list.append((6, timeout_validation_note, timeout_validation_spec, timeout_validation_tmsh, False))

    httpd_allow = data_all[httpd_data_start:][:httpd_timeout_start]
    httpd_allow = httpd_allow.lstrip("sys httpd").strip().lstrip("{").strip()
    httpd_allow = "https " + httpd_allow

    return (user_login_validation_list, sshd_allow, httpd_allow)  

def data_collect_system_extract_ntp(data_all):
    ntp_validation_list = []
    ntp_data_start = re.search("sys ntp", data_all,re.I).start()
    ntp_data_end = re.search("sys outbound-smtp", data_all[ntp_data_start:],re.I).start()
    ntp_data = data_all[ntp_data_start:][:ntp_data_end]
    timezone_line = re.search(r'timezone\s+(\S+)', ntp_data, re.I).group()
    timezone = timezone_line.lstrip("timezone").strip()
    timezone_validation_note = ""
    timezone_validation_spec = "是"
    timezone_validation_tmsh = []
    if timezone != "Asia/Shanghai" :
        timezone_validation_note = "时区设定非中国时区"
        timezone_validation_spec = "否"
        timezone_validation_tmsh.append("tmsh modify sys  ntp { timezone  Asia/Shanghai}")
    ntp_validation_list.append((7, timezone_validation_note, timezone_validation_spec, timezone_validation_tmsh, False))

    servers_start = re.search("servers", ntp_data,re.I).start()
    servers_end = re.search("}", ntp_data[servers_start:],re.I).start()
    servers = ntp_data[servers_start:][:servers_end]
    servers = servers.replace("{ ", "")
    ntp_validation_list.append((8, "", "是", ["ntp " + servers], True))
    return ntp_validation_list
    
def data_collect_system_extract_snmp(data_all):
    snmp_validation_list = []
    snmp_data_start = re.search("sys snmp", data_all,re.I).start()
    snmp_data_end = re.search("sys software image", data_all[snmp_data_start:],re.I).start()
    snmp_data = data_all[snmp_data_start:][:snmp_data_end]
   
    snmp_validation_list.append((9, "", "是", [], False))
    snmp_validation_list.append((10, "", "是", ["v2c"], False))

    if "psbcread" not in snmp_data:
        snmp_validation_list.append((11, "", "否", ["tmsh modify sys snmp communities add { XXXXX { community-name psbcread source default oid-subset 1 access ro } }"], True))

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
            tmsh = "name: " + trap_name + ", host: " + trap_host + ", port: " + trap_port
            snmp_trap_host_port_list.append(tmsh)

    if len(snmp_trap_host_port_list) > 0:
        snmp_validation_list.append((12, "", "是", snmp_trap_host_port_list, True))
    else:
        snmp_validation_list.append((12, "", "否", ["tmsh modify sys snmp traps add { XXXXX  { version 2c community psbcread host XX.XX.XX.XX  port XXX } } "], True))

    snmp_allowed_address = ""
    snmp_allowed_address_start = re.search("allowed-addresses", snmp_data,re.I).start()
    snmp_allowed_address_end = re.search("communities", snmp_data[snmp_allowed_address_start:],re.I).start()
    snmp_allowed_address_raw = snmp_data[snmp_allowed_address_start:][:snmp_allowed_address_end]
    if len(snmp_allowed_address_raw) > 20:
        snmp_allowed_address = "snmp " + snmp_allowed_address_raw

    return (snmp_validation_list, snmp_allowed_address)

def data_collect_system_extract_syslog(data_all):
    syslog_validation_list = []
    syslog_data_start = re.search("sys syslog", data_all,re.I).start()
    syslog_data_end = re.search("sys turboflex profile-config", data_all[syslog_data_start:],re.I).start()
    syslog_data = data_all[syslog_data_start:][:syslog_data_end]
    if len(syslog_data) > 30:
        syslog_validation_list.append((13, "", "是", [syslog_data], True))
    else:
        syslog_validation_list.append((13, "", "否", ["tmsh modify sys syslog remote-servers add { XXXX { host XXX.XXX.XXX.XXX remote-port XXX local-ip XXX.XXX.XXX.XXX } }"], True))
    syslog_validation_list.append((14, "", "是", ["tmsh  modify  sys  syslog  local6-from notice"], True))
    return syslog_validation_list 

def data_collect_system_extract_acl(sshd_acl, httpd_acl, snmp_acl):
    secure_acl_validation_list = []

    if len(sshd_acl) > 20:
        secure_acl_validation_list.append((16, "", "是", [sshd_acl], True))
    else:
        secure_acl_validation_list.append((16, "", "否", ["tmsh modify sys sshd allow add { xxx.xxx.xxx.xxx/xx }"], True))
 
    if len(httpd_acl) > 20:
        secure_acl_validation_list.append((16, "", "是", [httpd_acl], True))
    else:
        secure_acl_validation_list.append((16, "", "否", ["tmsh modify sys httpd allow add { xxx.xxx.xxx.xxx/xx }"], True))    

    if len(snmp_acl) > 30:
       secure_acl_validation_list.append((15, "", "是", [snmp_acl], True))
    else:
       secure_acl_validation_list.append((15, "", "否", ["tmsh modify sys snmp allowed-addresses add { xxx.xxx.xxx.xxx  }"], True))
    
    return secure_acl_validation_list


def data_collect_system_extract_management(data_all):
    mgmt_validation_list = []
    matches = re.search(r'sys management-ip\s+(\S+)', data_all, re.I)
    if matches:
        management_ip = matches.group()
        mgmt_validation_list.append((17, "", "是", [management_ip], True))
        
    data_start = re.search("sys management-route default", data_all,re.I).start()
    data_end = re.search("sys ntp", data_all[data_start:],re.I).start()
    mgmt_route_data = data_all[data_start:][:data_end]

    gateways = re.search(r'gateway\s+(\S+)', mgmt_route_data, re.I)
    if gateways:
        management_route = gateways.group()
        management_route = "sys management-route default " + management_route 
        mgmt_validation_list.append((18, "", "是", [management_route], True))
    else:
        mgmt_validation_list.append((19, "", "否", ["tmsh create sys  management-route default gateway xxx.xxx.xxx.xxx"], True))
    
    return mgmt_validation_list


def data_collect_system(data_all):
    hostname = data_collect_system_extract_hostname(data_all)
    user_validation_results = data_collect_system_extract_users(data_all)
    login_validation_results_all = data_collect_system_extract_login(data_all)
    login_validation_results = login_validation_results_all[0]
    ntp_validation_results = data_collect_system_extract_ntp(data_all)
    snmp_validation_results_all = data_collect_system_extract_snmp(data_all)    
    snmp_validation_results = snmp_validation_results_all[0]
    syslog_validation_results = data_collect_system_extract_syslog(data_all)
    secure_acl_validation_results = data_collect_system_extract_acl(login_validation_results_all[1], login_validation_results_all[2], snmp_validation_results_all[1])
    management_validation_results = data_collect_system_extract_management(data_all)
 
    #print(management_validation_results)    

    return (hostname, user_validation_results)
 

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


def data_collect(data_all):

    info_list = []
    vs_list = []
    net_list = []

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
    print("Usage: f5-tmsh-validation.py [file] [file]")
    sys.exit()

fileconfig = sys.argv[1]
fileadd = sys.argv[2]

with open(fileconfig, 'r') as fo:
    data_all = fo.read()
    
data_all = data_all.replace('[m','')
data_all = data_all.replace('[K', '')
error = re.findall(r'\[7m---\(less (\d+)',data_all)
for i in error:
    error1 = '[7m---(less '+i
    data_all = data_all.replace(error1, '')
fo.close()
  
#config_results = data_collect(data_all)
#for item in config_results[1]:
#    print("vs name: " + item['vsname'])

system_results = data_collect_system(data_all)

print(system_results[0])

#with open(fileadd, "r") as file:
    #config_results = data_collect(fileconfig)
    #system_results = data_collect_system(fileconfig)

    #for item in config_results[1]:
    #    print("vs name: " + item['vsname'])


    #for item in system_results:
    #    print(item)
