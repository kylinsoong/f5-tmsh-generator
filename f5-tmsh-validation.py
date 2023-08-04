#!/usr/bin/python3

import sys
import ast
import re

class Spec:
    def __init__(self, name, hostname, data):
        self.name = name
        self.hostname = hostname
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
        external_function(self.data)

class SpecLoginMethods(Spec):
    def parse(self):
        external_function(self.data)

class SpecNTPSyncSetting(Spec):
    def parse(self):
        external_function(self.data)

class SpecSNMPManagement(Spec):
    def parse(self):
        external_function(self.data)

class SpecSyslogSetting(Spec):
    def parse(self):
        external_function(self.data)

class SpecSecureACLControl(Spec):
    def parse(self):
        external_function(self.data)

class SpecInterfaceConfiguration(Spec):
    def parse(self):
        external_function(self.data)

class SpecRouteConfiguration(Spec):
    def parse(self):
        external_function(self.data)

class SpecHAConfiguration(Spec):
    def parse(self):
        external_function(self.data)

class SpecFailoverSetting(Spec):
    def parse(self):
        external_function(self.data)

class SpecTCPConnectionConfiguration(Spec):
    def parse(self):
        external_function(self.data)

class SpecSNATConfiguration(Spec):
    def parse(self):
        external_function(self.data)

class SpecHTTPRstActionDownSetting(Spec):
    def parse(self):
        external_function(self.data)






def external_function(data_all):
    print(len(data_all))

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


def data_collect_system_extract_trunk(data_all):
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

        interface_validation_list.append((17, "", "是", [inter_data_detail], True))        

        if "lacp enabled" in data_detail:
            interface_validation_list.append((17, "", "否", [trunk_disable_tmsh], False))

    if len(interface_validation_list) <= 0:
        interface_validation_list.append((17, "", "否", ["tmsh create net trunk XXXX interfaces add { X.X }"], True))  
        interface_validation_list.append((18, "", "否", ["tmsh create net trunk XXXX interfaces add { X.X }"], True)) 
    else:
        interface_validation_list.append((18, "HA 基于业务 trunk ", "是", [""], False)) 
            
    return interface_validation_list


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
    data_collect_system_extract_trunk(data_all)

    #management_validation_results = data_collect_system_extract_management(data_all)
 
    #print(login_validation_results_all)    

    return (hostname, user_validation_results)

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

def data_collect(fileconfig):
    data_all = load_bigip_running_config(fileconfig)
    system_results = data_collect_system(data_all)
    print(system_results[0])
 

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

data_all = load_bigip_running_config(fileconfig)
hostname = data_collect_system_extract_hostname(data_all)

spec_validation_list = []

spec_validation_list.append(SpecUserManagement(SPEC_ITEM_USER_MANAGEMENT, hostname, data_all))
spec_validation_list.append(SpecLoginMethods(SPEC_ITEM_EXLOGIN_METHODS, hostname, data_all))
spec_validation_list.append(SpecNTPSyncSetting(SPEC_ITEM_NTPSYN_SETTINGS, hostname, data_all))
spec_validation_list.append(SpecSNMPManagement(SPEC_ITEM_SNMP_MANAGEMENT, hostname, data_all))
spec_validation_list.append(SpecSyslogSetting(SPEC_ITEM_SYSLOG_SETTINGS, hostname, data_all))
spec_validation_list.append(SpecSecureACLControl(SPEC_ITEM_SEC_ACL_CONTROL, hostname, data_all))

spec_validation_list.append(SpecInterfaceConfiguration(SPEC_ITEM_INTERFACES_CONF, hostname, data_all))
spec_validation_list.append(SpecRouteConfiguration(SPEC_ITEM_INEXROUTER_CONF, hostname, data_all))
spec_validation_list.append(SpecHAConfiguration(SPEC_ITEM_HASETTINGS_CONF, hostname, data_all))
spec_validation_list.append(SpecFailoverSetting(SPEC_ITEM_FAILOVERS_CHECK, hostname, data_all))

spec_validation_list.append(SpecTCPConnectionConfiguration(SPEC_ITEM_TCP_CONNECTIONS, hostname, data_all))
spec_validation_list.append(SpecSNATConfiguration(SPEC_ITEM_SNATPOOLME_CONF, hostname, data_all))
spec_validation_list.append(SpecHTTPRstActionDownSetting(SPEC_ITEM_HTTP_RST_ONDOWN, hostname, data_all))

for spec in spec_validation_list:
    spec.write_to_excel()
