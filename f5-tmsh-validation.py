#!/usr/bin/python3

import sys
import re
import ipaddress
import openpyxl

from f5bigip import configParse
from f5bigip import tmsh


def spec_user_management_validation(data_all):
   
    user_role_dict = {}
    user_list = configParse.auth_user(data_all)    
    for i in user_list:
        user_role_dict[i.name] = i.role    
    
    user_validation_list = []
    user_config_note = ""
    user_config_spec = SPEC_BASELINE_YES
    user_config_tmsh = []
    user_config_rollback_tmsh = []
    if "psbc" not in user_role_dict:
        user_config_note = SPEC_USER_MANAGEMENT_PSBC_NOT_EXIST
        user_config_spec = SPEC_BASELINE_NO
        user_create = tmsh.get('tmsh', 'create.auth.user').replace("${auth.user.name}", "psbc").replace("${auth.user.role}", "admin")
        user_config_tmsh.append(user_create)
        user_delete = tmsh.get('tmsh', 'delete.auth.user').replace("${auth.user.name}", "psbc")
        user_config_rollback_tmsh.append(user_delete)
    if "view" not in user_role_dict:
        user_config_note = SPEC_USER_MANAGEMENT_VIEW_NOT_EXIST
        user_config_spec = SPEC_BASELINE_NO
        user_create = tmsh.get('tmsh', 'create.auth.user').replace("${auth.user.name}", "view").replace("${auth.user.role}", "auditor")
        user_config_tmsh.append(user_create)
        user_delete = tmsh.get('tmsh', 'delete.auth.user').replace("${auth.user.name}", "view")
        user_config_rollback_tmsh.append(user_delete)

    user_validation_list.append((1, user_config_note, user_config_spec, user_config_tmsh,user_config_rollback_tmsh,  False))

    default_user_note = ""
    default_user_spec = SPEC_BASELINE_YES
    default_user_tmsh_list = []
    default_user_rollback_tmsh_list = []
    if "admin" in user_role_dict:
        default_user_note = SPEC_USER_MANAGEMENT_ADMIN_NOT_DELETE
        default_user_spec = SPEC_BASELINE_NO
        default_user_tmsh = tmsh.get('tmsh', 'modify.sys.db.systemauth').replace("${auth.user.name}", "psbc")
        default_user_rollback_tmsh = tmsh.get('tmsh', 'modify.sys.db.systemauth').replace("${auth.user.name}", "admin")
        default_user_tmsh_list.append(default_user_tmsh)
        default_user_rollback_tmsh_list.append(default_user_rollback_tmsh)

    if "root" in user_role_dict:
        default_user_note = SPEC_USER_MANAGEMENT_ADMIN_NOT_DELETE
        default_user_spec = SPEC_BASELINE_NO
        default_root_tmsh = tmsh.get('tmsh', 'modify.sys.db.systemauth.disablerootlogin').replace("${auth.disablerootlogin}", "true")
        default_root_tmsh_rollback = tmsh.get('tmsh', 'modify.sys.db.systemauth.disablerootlogin').replace("${auth.disablerootlogin}", "false")
        default_user_tmsh_list.append(default_root_tmsh)
        default_user_rollback_tmsh_list.append(default_root_tmsh_rollback)


    user_validation_list.append((2, default_user_note, default_user_spec, default_user_tmsh_list, default_user_rollback_tmsh_list, True))

    user_role_config_note = ""
    user_role_config_spec = SPEC_BASELINE_YES
    user_role_config_tmsh = []
    user_role_config_rollback_tmsh = []
    if "psbc" in user_role_dict and user_role_dict['psbc'] != "admin":
        user_role_config_note = SPEC_USER_MANAGEMENT_PSBC_NO_EXPECT_RIGHT
        user_role_config_spec = SPEC_BASELINE_NO
        user_modify = tmsh.get('tmsh', 'modify.auth.user').replace("${auth.user.name}", "psbc").replace("${auth.user.role}", "admin")
        user_role_config_tmsh.append(user_modify)
        user_modify_rollback = tmsh.get('tmsh', 'modify.auth.user').replace("${auth.user.name}", "psbc").replace("${auth.user.role}", user_role_dict['psbc'])
        user_role_config_rollback_tmsh.append(user_modify_rollback)

    if "view" in user_role_dict and user_role_dict['view'] != "auditor":
        user_role_config_note = SPEC_USER_MANAGEMENT_VIEW_NO_EXPECT_RIGHT
        user_role_config_spec = SPEC_BASELINE_NO
        user_modify = tmsh.get('tmsh', 'modify.auth.user').replace("${auth.user.name}", "view").replace("${auth.user.role}", "auditor")
        user_role_config_tmsh.append(user_modify)
        user_modify_rollback = tmsh.get('tmsh', 'modify.auth.user').replace("${auth.user.name}", "view").replace("${auth.user.role}", user_role_dict['view'])
        user_role_config_rollback_tmsh.append(user_modify_rollback)

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
            tmsh_modify = tmsh.get('tmsh', 'modify.net.self').replace("${net.self.name}", i.name).replace("${net.self.allow.service}", "none")
            tmsh_rollback = tmsh.get('tmsh', 'modify.net.self').replace("${net.self.name}", i.name).replace("${net.self.allow.service}", "default")
            self_allow_default_tmsh.append(tmsh_modify)
            self_allow_default_rollback_tmsh.append(tmsh_rollback)


    user_login_validation_list.append((4, self_allow_default_note, self_allow_default_spec, self_allow_default_tmsh, self_allow_default_rollback_tmsh, True))
    user_login_validation_list.append((5, self_allow_default_note, self_allow_default_spec, self_allow_default_tmsh, self_allow_default_rollback_tmsh, True))

    timeout_validation_note = ""
    timeout_validation_spec = SPEC_BASELINE_YES
    timeout_validation_tmsh = []
    timeout_validation_rollback_tmsh = []
    sys_sshd = configParse.sys_sshd(data_all)
    if sys_sshd.inactivity_timeout is not None and sys_sshd.inactivity_timeout != "720":
        timeout_validation_note = SPEC_LOGIN_METHODS_TIMEOUT_NO_12_MINS
        timeout_validation_spec = SPEC_BASELINE_NO
        timeout_validation_tmsh.append(tmsh.get('tmsh', 'modify.sys.sshd').replace("${sys.sshd.timeout}", "720"))
        timeout_validation_rollback_tmsh.append(tmsh.get('tmsh', 'modify.sys.sshd').replace("${sys.sshd.timeout}", sys_sshd.inactivity_timeout))

    sys_httpd = configParse.sys_httpd(data_all)
    if sys_httpd.auth_pam_idle_timeout is not None and sys_httpd.auth_pam_idle_timeout != "720":
        timeout_validation_note = SPEC_LOGIN_METHODS_TIMEOUT_NO_12_MINS
        timeout_validation_spec = SPEC_BASELINE_NO
        timeout_validation_tmsh.append(tmsh.get('tmsh', 'modify.sys.httpd').replace("${sys.httpd.timeout}", "720"))
        timeout_validation_rollback_tmsh.append(tmsh.get('tmsh', 'modify.sys.httpd').replace("${sys.httpd.timeout}", sys_httpd.auth_pam_idle_timeout))

    user_login_validation_list.append((6, timeout_validation_note, timeout_validation_spec, timeout_validation_tmsh, timeout_validation_rollback_tmsh, True))
    
    return user_login_validation_list



def spec_ntp_settings_validation(data_all):
    ntp_validation_list = []
    ntp = configParse.sys_ntp(data_all)
    timezone_validation_note = ""
    timezone_validation_spec = SPEC_BASELINE_YES
    timezone_validation_tmsh = []
    timezone_validation_rollback_tmsh = []
    if ntp.timezone != "Asia/Shanghai" :
        timezone_validation_note = SPEC_NTP_SETTINGS_TIMEZONE_WRONG
        timezone_validation_spec = SPEC_BASELINE_NO
        timezone_validation_tmsh.append(tmsh.get('tmsh', 'modify.sys.ntp').replace("${sys.ntp.timezone}", "Asia/Shanghai"))
        timezone_validation_rollback_tmsh.append(tmsh.get('tmsh', 'modify.sys.ntp').replace("${sys.ntp.timezone}", ntp.timezone))
    ntp_validation_list.append((7, timezone_validation_note, timezone_validation_spec, timezone_validation_tmsh, timezone_validation_rollback_tmsh, True))

    servers_validation_note = ""
    servers_validation_spec = SPEC_BASELINE_YES
    servers_validation_tmsh = []
    servers_validation_rollback_tmsh = []
    if len(ntp.servers) < 2:
        servers_validation_note = SPEC_NTP_SETTINGS_SERVERS_WRONG
        servers_validation_spec = SPEC_BASELINE_NO
        tmsh_ntp_add = tmsh.get('tmsh', 'modify.sys.ntp.add').replace("${sys.ntp.servers}", "x.x.x.x x.x.x.x")        
        tmsh_ntp_del = tmsh.get('tmsh', 'modify.sys.ntp.del').replace("${sys.ntp.servers}", "x.x.x.x x.x.x.x")        
        servers_validation_tmsh.append(tmsh_ntp_add)
        servers_validation_rollback_tmsh.append(tmsh_ntp_del)
    ntp_validation_list.append((8, servers_validation_note, servers_validation_spec, servers_validation_tmsh, servers_validation_rollback_tmsh, True))
        
    return ntp_validation_list



def spec_snmp_management_validation(data_all):
    snmp_validation_list = []
    snmp = configParse.sys_snmp(data_all)
    communities_name_list = []
    for i in snmp.communities:
        communities_name_list.append(i.community_name)

    snmp_validation_list.append((9, "", SPEC_BASELINE_YES, [], [], True))
    snmp_validation_list.append((10, "", SPEC_BASELINE_YES, ["v2c"], [], True))

    if "psbcread" not in communities_name_list:
        tmsh_community_add = tmsh.get('tmsh', 'modify.sys.snmp.communities.add').replace("${sys.snmp.community}", "XX").replace("${sys.snmp.community.name}", "XX")
        tmsh_community_del = tmsh.get('tmsh', 'modify.sys.snmp.communities.del').replace("${sys.snmp.community}", "XX")
        snmp_validation_list.append((11, SPEC_SNMP_COMMINITY_NOT_EXIST, SPEC_BASELINE_NO, [tmsh_community_add], [tmsh_community_del], True))
    else:
        snmp_validation_list.append((11, "", SPEC_BASELINE_YES, [], [], True))

    if len(snmp.traps) <= 0:
        tmsh_trap_add = tmsh.get('tmsh', 'modify.sys.snmp.trap.add').replace("${sys.snmp.trap.name}", "XX").replace("${sys.snmp.trap.community}", "XX").replace("${sys.snmp.trap.host}", "XX").replace("${sys.snmp.trap.port}", "XX")       
        tmsh_trap_del = tmsh.get('tmsh', 'modify.sys.snmp.trap.del').replace("${sys.snmp.trap.name}", "XX")
        snmp_validation_list.append((12, SPEC_SNMP_TRAP_NOT_EXIST, SPEC_BASELINE_NO, [tmsh_trap_add], [tmsh_trap_del], True))
    else:
        snmp_validation_list.append((12, "", SPEC_BASELINE_YES, [], [], True))

    return snmp_validation_list



def spec_syslog_settings_validation(data_all):

    syslog_validation_list = []
    syslog = configParse.sys_syslog(data_all)
    if syslog.remote_servers is not None and len(syslog.remote_servers) > 0:
        syslog_validation_list.append((13, "", SPEC_BASELINE_YES, [], [], True))
    else:
        tmsh_syslog_add = tmsh.get('tmsh', 'modify.sys.syslog.add').replace("${sys.syslog.name}", "XX").replace("${sys.syslog.host}", "X.X.X.X").replace("${sys.syslog.port}", "XX").replace("${sys.syslog.ip}", "X.X.X.X")
        tmsh_syslog_del = tmsh.get('tmsh', 'modify.sys.syslog.del').replace("${sys.syslog.name}", "XX")
        syslog_validation_list.append((13, "", SPEC_BASELINE_NO, [tmsh_syslog_add], [tmsh_syslog_del], True))

    syslog_validation_list.append((14, SPEC_SYSLOG_REMOTE_SERVER_NONE, SPEC_BASELINE_YES, [tmsh.get('tmsh', 'modify.sys.syslog.log.level')], [], True))

    return syslog_validation_list



def spec_secure_acl_validation(data_all):

    sys_sshd = configParse.sys_sshd(data_all)
    sys_httpd = configParse.sys_httpd(data_all)
    secure_acl_validation_list = []

    tmsh_httpd_allow_add = tmsh.get('tmsh', 'modify.sys.httpd.allow.add').replace("${sys.httpd.allow.addr}", "x.x.x.x x.x.x.x")
    tmsh_httpd_allow_del = tmsh.get('tmsh', 'modify.sys.httpd.allow.del').replace("${sys.httpd.allow.addr}", "x.x.x.x x.x.x.x")
    if sys_httpd.allow is not None and len(sys_httpd.allow) > 6:
        tmsh_httpd_allow_replace = tmsh.get('tmsh', 'modify.sys.httpd.allow.repl').replace("${sys.httpd.allow.addr}", configParse.convert_list_to_str(sys_httpd.allow))
        secure_acl_validation_list.append((15, SPEC_SECURE_ACL_ALLOWED_ADDR_DEL, SPEC_BASELINE_NO, [tmsh_httpd_allow_del], [tmsh_httpd_allow_replace], True))
    elif sys_httpd.allow is not None and len(sys_httpd.allow) < 6:
        tmsh_httpd_allow_replace = tmsh.get('tmsh', 'modify.sys.httpd.allow.repl').replace("${sys.httpd.allow.addr}", configParse.convert_list_to_str(sys_httpd.allow))
        secure_acl_validation_list.append((15, SPEC_SECURE_ACL_ALLOWED_ADDR_ADD, SPEC_BASELINE_NO, [tmsh_httpd_allow_add], [tmsh_httpd_allow_replace], True))
    elif sys_httpd.allow is not None and len(sys_httpd.allow) == 6:
        tmsh_httpd_allow_list = tmsh.get('tmsh', 'modify.sys.httpd.allow.list').replace("${sys.httpd.allow.addr}", configParse.convert_list_to_str(sys_httpd.allow))
        secure_acl_validation_list.append((15, "", SPEC_BASELINE_YES, [tmsh_httpd_allow_list], [], True))
    else:
        secure_acl_validation_list.append((15, SPEC_SECURE_ACL_ALLOWED_ADDR_NONE, SPEC_BASELINE_NO, [tmsh_httpd_allow_add], [tmsh_httpd_allow_del], True))


    tmsh_sshd_allow_add = tmsh.get('tmsh', 'modify.sys.sshd.allow.add').replace("${sys.sshd.allow.addr}", "x.x.x.x x.x.x.x")
    tmsh_sshd_allow_del = tmsh.get('tmsh', 'modify.sys.sshd.allow.del').replace("${sys.sshd.allow.addr}", "x.x.x.x x.x.x.x")
    if sys_sshd.allow is not None and len(sys_sshd.allow) > 6:
        tmsh_sshd_allow_replace = tmsh.get('tmsh', 'modify.sys.sshd.allow.repl').replace("${sys.sshd.allow.addr}", configParse.convert_list_to_str(sys_sshd.allow))
        secure_acl_validation_list.append((16, SPEC_SECURE_ACL_ALLOWED_ADDR_DEL, SPEC_BASELINE_NO, [tmsh_sshd_allow_del], [tmsh_sshd_allow_replace], True))
    elif sys_sshd.allow is not None and len(sys_sshd.allow) < 6:
        tmsh_sshd_allow_replace = tmsh.get('tmsh', 'modify.sys.sshd.allow.repl').replace("${sys.sshd.allow.addr}", configParse.convert_list_to_str(sys_sshd.allow))
        secure_acl_validation_list.append((16, SPEC_SECURE_ACL_ALLOWED_ADDR_ADD, SPEC_BASELINE_NO, [tmsh_sshd_allow_add], [tmsh_sshd_allow_replace], True))
    elif sys_sshd.allow is not None and len(sys_sshd.allow) == 6:
        tmsh_sshd_allow_list = tmsh.get('tmsh', 'modify.sys.sshd.allow.list').replace("${sys.sshd.allow.addr}", configParse.convert_list_to_str(sys_sshd.allow))
        secure_acl_validation_list.append((16, "", SPEC_BASELINE_YES, [tmsh_sshd_allow_list], [], True))
    else:
        secure_acl_validation_list.append((16, SPEC_SECURE_ACL_ALLOWED_ADDR_NONE, SPEC_BASELINE_NO, [tmsh_sshd_allow_add], [tmsh_sshd_allow_del], True))

    return secure_acl_validation_list



def spec_interface_configuration_validation(data_all):

    interface_validation_list = []

    net_trunk_list = configParse.net_trunk(data_all)
    if len(net_trunk_list) <= 0:
        tmsh_trunk_create = tmsh.get('tmsh', 'create.net.trunk').replace("${net.trunk.name}", "XX").replace("${net.trunk.interface}", "XX")   
        tmsh_trunk_delete = tmsh.get('tmsh', 'delete.net.trunk').replace("${net.trunk.name}", "XX")
        interface_validation_list.append((17, SPEC_INTERFACE_TRUNK_NONE, SPEC_BASELINE_NO, [tmsh_trunk_create], [tmsh_trunk_delete], False))
    else:
        tunk_interfaces_num_notes = ""
        tunk_interfaces_num_spec = SPEC_BASELINE_YES
        tunk_interfaces_num_tmsh_add = []
        tunk_interfaces_num_tmsh_del = []
        for i in net_trunk_list:
            if len(i.interfaces) < 2:
                tunk_interfaces_num_spec = SPEC_BASELINE_NO
                tunk_interfaces_num_notes += SPEC_INTERFACE_TRUNK_SINGLE_INTERFACE
                tmsh_tunk_add_interface = tmsh.get('tmsh', 'modify.net.trunk.interface.add').replace("${net.trunk.name}", i.name).replace("${net.trunk.interface}", "XX")
                tmsh_tunk_del_interface = tmsh.get('tmsh', 'modify.net.trunk.interface.del').replace("${net.trunk.name}", i.name).replace("${net.trunk.interface}", "XX")
                tunk_interfaces_num_tmsh_add.append(tmsh_tunk_add_interface)
                tunk_interfaces_num_tmsh_del.append(tmsh_tunk_del_interface)
            if i.lacp is not None and i.lacp == "enabled":
                tunk_interfaces_num_spec = SPEC_BASELINE_NO
                tunk_interfaces_num_notes += SPEC_INTERFACE_TRUNK_LACP
                tmsh_tunk_lacp_disable = tmsh.get('tmsh', 'modify.net.trunk.lacp.disable').replace("${net.trunk.name}", i.name) 
                tmsh_tunk_lacp_enabled = tmsh.get('tmsh', 'modify.net.trunk.lacp.enable').replace("${net.trunk.name}", i.name)
                tunk_interfaces_num_tmsh_add.append(tmsh_tunk_lacp_disable)
                tunk_interfaces_num_tmsh_del.append(tmsh_tunk_lacp_enabled)
        interface_validation_list.append((17, tunk_interfaces_num_notes, tunk_interfaces_num_spec, tunk_interfaces_num_tmsh_add, tunk_interfaces_num_tmsh_del, False))

    device_list = configParse.cm_device(data_all)
    if len(device_list) > 1 and len(device_list[0].unicast_address) >= 2:
        interface_validation_list.append((18, "", SPEC_BASELINE_YES, [], [], True))
    else:
        interface_validation_list.append((18, SEPC_INTERFACE_HA_TRUNK_SINGLE, SPEC_BASELINE_NO, [], [], True))

    interface_disable_notes = ""
    interface_disable_spec = SPEC_BASELINE_YES
    interface_disable_tmsh, interface_disable_tmsh_rollback = [], []
    net_interface_list = configParse.net_interface(data_all)
    for i in net_interface_list:
        if i.serial is not None and i.vendor is not None and i.disabled == False and i.media_active is None:
            interface_disable_notes = SPEC_INTERFACE_UNUSED_UNDISABLED
            interface_disable_spec = SPEC_BASELINE_NO
            tmsh_inter_disable = tmsh.get('tmsh', 'modify.net.interface.disable').replace("${net.iterface.name}", i.name) 
            tmsh_inter_enabled = tmsh.get('tmsh', 'modify.net.interface.enabled').replace("${net.iterface.name}", i.name) 
            interface_disable_tmsh.append(tmsh_inter_disable)
            interface_disable_tmsh_rollback.append(tmsh_inter_enabled)
    
    interface_validation_list.append((19, interface_disable_notes, interface_disable_spec, interface_disable_tmsh, interface_disable_tmsh_rollback, False))

    return interface_validation_list



def spec_route_configuration_validation(data_all):

    route_validation_list = []

    management_route_list = configParse.sys_management_route(data_all)
    isDefaultGateway = False
    for i in management_route_list:
        if i.name == "default":
            isDefaultGateway = True

    if isDefaultGateway:
        route_validation_list.append((20, "", SPEC_BASELINE_YES, [], [], True))
    else:
        tmsh_create_mgmt_route = tmsh.get('tmsh', 'create.sys.management-route').replace("${sys.management-route.gateway}", "x.x.x.x")
        tmsh_delete_mgmt_route = tmsh.get('tmsh', 'delete.sys.management-route')
        route_validation_list.append((20, "", SPEC_BASELINE_NO, [tmsh_create_mgmt_route], [tmsh_delete_mgmt_route], True))

    invalid_route_list = []
    net_self_list = configParse.form_self_list(configParse.net_self(data_all))
    net_route_list = configParse.net_route(data_all) 
    if len(net_route_list) <= 0:
        tmsh_create_route = tmsh.get('tmsh', 'create.net.route').replace("${net.route.ip}", "x.x.x.x")
        tmsh_delete_route = tmsh.get('tmsh', 'delete.net.route')
        route_validation_list.append((21, SPEC_ROUTE_DEFAULT_GATEWAY, SPEC_BASELINE_NO, [tmsh_create_route], [tmsh_delete_route], True))

    for i in net_route_list:
        ip_addr = ipaddress.ip_address(i.gw)
        if not any(ip_addr in network for network in net_self_list):
            invalid_route_list.append(ip_addr)

    if len(invalid_route_list) > 0:
        route_validation_list.append((21, SPEC_ROUTE_DEFAULT_GATEWAY_NEXT_HOP, SPEC_BASELINE_NO, [], [], True)) 
    else:
        route_validation_list.append((21, "", SPEC_BASELINE_YES, [], [], True))

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
                ha_validation_list.append((22, "", SPEC_BASELINE_YES, [], [], True))
            else:
               ha_validation_list.append((22, SPEC_HA_FAILSAFE_ERROR, SPEC_BASELINE_NO, [], [], True))
    else:
        ha_validation_list.append((22, SPEC_HA_FAILSAFE_ERROR, SPEC_BASELINE_NO, [], [], True))

    ha_devices_list = configParse.cm_device(data_all)

    if len(ha_devices_list) < 2:
        ha_validation_list.append((23, SPEC_HA_NO_HA_CONF, SPEC_BASELINE_NO, [], [], True))
    elif incorrect_ha_configuration(ha_devices_list):
        ha_validation_list.append((23, SPEC_HA_HA_CONF_NOT_CORRECT, SPEC_BASELINE_NO, [], [], True))
    elif incorrect_time_zone(ha_devices_list):
        ha_validation_list.append((23, SPEC_HA_HA_CONF_NOT_CORRECT_TIMEZONE, SPEC_BASELINE_NO, [], [], True))
    elif incorrect_version(ha_devices_list):
        ha_validation_list.append((23, SPEC_HA_HA_CONF_NOT_CORRECT_VERSION, SPEC_BASELINE_NO, [], [], True))
    elif len(ha_devices_list[0].unicast_address) <= 1:
        ha_validation_list.append((23, SPEC_HA_HA_CONF_NO_MULTI_VLAN, SPEC_BASELINE_NO, [], [], True))
    else:
        ha_validation_list.append((23, "", SPEC_BASELINE_YES, [], [], True))

    ha_device_group_sync_list = []
    cm_device_greoup_list = configParse.cm_device_group(data_all)
    for i in cm_device_greoup_list:
        if i.type == "sync-failover":
            ha_device_group_sync_list.append(i)
    
    if len(ha_device_group_sync_list) == 0:
        ha_validation_list.append((24, SPEC_HA_NO_SYNC_FAILOVER, SPEC_BASELINE_NO, [], [], True))
    elif len(ha_device_group_sync_list) > 1:
        ha_validation_list.append((24, SPEC_HA_MULTI_SYNC_FAILOVER, SPEC_BASELINE_NO, [], [], True))
    elif len(ha_device_group_sync_list) == 1:
        if ha_device_group_sync_list[0].fullloadonsync == "true":
            ha_validation_list.append((24, "", SPEC_BASELINE_YES, [], [], True))
        else:
            ha_validation_list.append((24, SPEC_HA_SYNC_NOT_FINISHED, SPEC_BASELINE_NO, [], [], True))

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
            failover_validation_list.append((25, "", SPEC_BASELINE_YES, [], False))    
        else:
            failover_validation_list.append((25, SPEC_FAILOVER_FAILSAFE_ERROR, SPEC_BASELINE_NO, [], [], False))
    else:
        failover_validation_list.append((25, SPEC_FAILOVER_FAILSAFE_ERROR, SPEC_BASELINE_NO, [], [], False))

    return failover_validation_list



def spec_tcp_connection_configuration_validation(data_all, vs_list):

    l4_timeout_validation_list = []
    
    profiles_list = []
    fastl4_list = configParse.ltm_profile_fastl4(data_all)
    for i in fastl4_list:
        profiles_list.append(i.name)
    
    l4_vs_list = []
    for i in vs_list:
        for profile in i.profiles:
            if profile in profiles_list:
                l4_vs_list.append(i)

    notes = ""
    tmsh_list = []
    tmsh_rollback_list = []
    for vs in l4_vs_list:
        timeout = extract_timeout(vs.profiles, fastl4_list) 
        if int(timeout) > 300:
            notes = SPEC_APP_TCP_TIEMOUT_LARGER
            tmsh_modify = tmsh.get('tmsh', 'modify.ltm.profile.fastl4').replace("${ltm.profile.name}", vs.profiles[0]).replace("${ltm.profile.timeout}", "300")
            tmsh_rollback = tmsh.get('tmsh', 'modify.ltm.profile.fastl4').replace("${ltm.profile.name}", vs.profiles[0]).replace("${ltm.profile.timeout}", timeout)
            tmsh_list.append(tmsh_modify)
            tmsh_rollback_list.append(tmsh_rollback)

    if len(tmsh_list) > 0:
        l4_timeout_validation_list.append((26, notes, SPEC_BASELINE_NO, tmsh_list, tmsh_rollback_list, False))
    else:
        l4_timeout_validation_list.append((26, notes, SPEC_BASELINE_YES, [], [], False))

    return l4_timeout_validation_list


def extract_timeout(profiles, list):
    for i in list:
        if i.name == profiles[0]:
            return i.idle_timeout
    return 0



def spec_snat_configuration_validation(data_all, vs_list):

    snat_validation_list = []
 
    snatpool_list = configParse.ltm_snatpool(data_all)
    notes_list, tmsh_list, tmsh_rollback_list = "", [], []
    for vs in vs_list:
        if vs.vs_port != "0" and vs.snatpool is None and vs.snatType == "automap":
            notes_list =  SPEC_APP_SANT_NO_SANTPOOL
            tmsh_create = tmsh.get('tmsh', 'create.ltm.snatpool').replace("${replace.snatpool.name}", "xx").replace("${replace.snatpool.members}", "x.x.x.x")        
            tmsh_delete = tmsh.get('tmsh', 'delete.ltm.snatpool').replace("${replace.snatpool.name}", "xx")
            tmsh_list.append(tmsh_create)
            tmsh_rollback_list.append(tmsh_delete)
        elif vs.vs_port != "0" and vs.snatpool is not None:
            snat_pool_obj = None
            for i in snatpool_list:
                if i.name == vs.snatpool:
                    snat_pool_obj = i
                    break
            if len(snat_pool_obj.members) < 4:
                notes_list =  SPEC_APP_SANT_SANTPOOL_LESS_FOUR 
                tmsh_member_add = tmsh.get('tmsh', 'modify.ltm.snatpool').replace("${replace.snatpool.name}", snat_pool_obj.name).replace("${replace.snatpool.members}", "x.x.x.x") 
                tmsh_member_del = tmsh.get('tmsh', 'modify.ltm.snatpool.rollback').replace("${replace.snatpool.name}", snat_pool_obj.name).replace("${replace.snatpool.members}", "x.x.x.x") 
                tmsh_list.append(tmsh_member_add)
                tmsh_rollback_list.append(tmsh_member_del)
        elif vs.vs_port != "0" and vs.snatpool is None and vs.snatType is None:
            notes_list =  SPEC_APP_SANT_NO_SANTPOOL_NO_AUTOMAP
            tmsh_create = tmsh.get('tmsh', 'create.ltm.snatpool').replace("${replace.snatpool.name}", "xx").replace("${replace.snatpool.members}", "x.x.x.x")          
            tmsh_delete = tmsh.get('tmsh', 'delete.ltm.snatpool').replace("${replace.snatpool.name}", "xx")
            tmsh_list.append(tmsh_create)
            tmsh_rollback_list.append(tmsh_delete)

    if len(tmsh_list) > 0:
        snat_validation_list.append((27, notes_list, SPEC_BASELINE_NO, tmsh_list, tmsh_rollback_list, True))
    else:
        snat_validation_list.append((27, "", SPEC_BASELINE_YES, [], [], True))
                
    return snat_validation_list



def sepc_http_rst_action_validation(data_all, vs_list):

    http_rst_validation_list = []

    http_profiles, fastl4_profiles = [], []
    fastl4_list = configParse.ltm_profile_fastl4(data_all)
    for i in fastl4_list:
        fastl4_profiles.append(i.name)
    fastl4_profiles.append("fastL4")

    http_list = configParse.ltm_profile_http(data_all)
    for i in http_list:
        http_profiles.append(i.name)
    http_profiles.append("http")

    notes_list, tmsh_list, tmsh_rollback_list = "", [], []
    for vs in vs_list:
        vs_profiles_list = vs.profiles
        fastL4NotExist = True
        httpExist = False
        for profile in vs_profiles_list:
            if profile in fastl4_profiles:
                fastL4NotExist = False
            elif profile in http_profiles:
                httpExist = True

        if fastL4NotExist and httpExist and vs.serviceDownReset is None:
            notes_list = SPEC_APP_HTTP_SERVICE_DOWN_REST
            tmsh_rst = tmsh.get('tmsh', 'modify.ltm.virtual.rst').replace("${replace.virtual.name}", vs.vs_name).replace("${replace.virtual.rst.action}", "reset")  
            tmsh_none = tmsh.get('tmsh', 'modify.ltm.virtual.rst').replace("${replace.virtual.name}", vs.vs_name).replace("${replace.virtual.rst.action}", "none")
            tmsh_list.append(tmsh_rst)
            tmsh_rollback_list.append(tmsh_none)  

    if len(tmsh_list) > 0:
        http_rst_validation_list.append((28, notes_list, SPEC_BASELINE_NO, tmsh_list, tmsh_rollback_list, True))
    else:
        http_rst_validation_list.append((28, notes_list, SPEC_BASELINE_YES, [], [], True))

    return http_rst_validation_list    



def sepc_monitor_configuration_validation(data_all, vs_list):

    monitor_validation_list = []

    isMonitorTCPTemplateExist = False
    tcp_monitors_list = configParse.ltm_monitor_tcp(data_all)
    tcp_monitors_notes = ""
    tcp_monitors_spec = SPEC_BASELINE_YES
    tcp_monitors_tmsh, tcp_monitors_tmsh_rollback = [], []
    for i in tcp_monitors_list:
        if i.name == "monitor_tcp_5s":
            isMonitorTCPTemplateExist = True
        if i.timeout != "16" or i.interval != "5":
            tcp_monitors_spec = SPEC_BASELINE_NO
            tcp_monitors_notes = SPEC_APP_MONITOR_INTERVAL_TIMEOUT
            tmsh_monitor = tmsh.get('tmsh', 'modify.ltm.monitor').replace("${replace.monitor.type}", "tcp").replace("${replace.monitor.name}", i.name).replace("${replace.monitor.interval}", "5").replace("${replace.monitor.timeout}", "16")
            tmsh_monitor_rollback = tmsh.get('tmsh', 'modify.ltm.monitor').replace("${replace.monitor.type}", "tcp").replace("${replace.monitor.name}", i.name).replace("${replace.monitor.interval}", i.interval).replace("${replace.monitor.timeout}", i.timeout)
            tcp_monitors_tmsh.append(tmsh_monitor)
            tcp_monitors_tmsh_rollback.append(tmsh_monitor_rollback)

    if isMonitorTCPTemplateExist == False:
        tcp_monitors_spec = SPEC_BASELINE_NO
        tcp_monitors_notes += SPEC_APP_MONITOR_TCP
        tmsh_monitor_create = tmsh.get('tmsh', 'create.ltm.monitor').replace("${replace.monitor.type}", "tcp").replace("${replace.monitor.name}", "monitor_tcp_5s").replace("${replace.monitor.interval}", "5").replace("${replace.monitor.timeout}", "16")
        tmsh_monitor_delete = tmsh.get('tmsh', 'delete.ltm.monitor').replace("${replace.monitor.type}", "tcp").replace("${replace.monitor.name}", "monitor_tcp_5s")
        tcp_monitors_tmsh.append(tmsh_monitor_create)
        tcp_monitors_tmsh_rollback.append(tmsh_monitor_delete)

    monitor_validation_list.append((29, tcp_monitors_notes, tcp_monitors_spec, tcp_monitors_tmsh, tcp_monitors_tmsh_rollback, True))


    udp_monitors_list = configParse.ltm_monitor_udp(data_all)
    udp_monitors_notes = ""
    udp_monitors_spec = SPEC_BASELINE_YES
    udp_monitors_tmsh, udp_monitors_tmsh_rollback = [], []
    for i in udp_monitors_list:
        if i.timeout != "16" or i.interval != "5":
            udp_monitors_notes = SPEC_APP_MONITOR_INTERVAL_TIMEOUT
            udp_monitors_spec = SPEC_BASELINE_NO
            tmsh_monitor = tmsh.get('tmsh', 'modify.ltm.monitor').replace("${replace.monitor.type}", "udp").replace("${replace.monitor.name}", i.name).replace("${replace.monitor.interval}", "5").replace("${replace.monitor.timeout}", "16")
            tmsh_monitor_rollback = tmsh.get('tmsh', 'modify.ltm.monitor').replace("${replace.monitor.type}", "udp").replace("${replace.monitor.name}", i.name).replace("${replace.monitor.interval}", i.interval).replace("${replace.monitor.timeout}", i.timeout)
            udp_monitors_tmsh.append(tmsh_monitor)
            udp_monitors_tmsh_rollback.append(tmsh_monitor_rollback)

    if len(udp_monitors_list) <= 0:
        udp_monitors_spec = SPEC_BASELINE_NO
        udp_monitors_notes += SPEC_APP_MONITOR_UDP
        tmsh_monitor_create = tmsh.get('tmsh', 'create.ltm.monitor').replace("${replace.monitor.type}", "udp").replace("${replace.monitor.name}", "monitor_udp_5s").replace("${replace.monitor.interval}", "5").replace("${replace.monitor.timeout}", "16")
        tmsh_monitor_delete = tmsh.get('tmsh', 'delete.ltm.monitor').replace("${replace.monitor.type}", "udp").replace("${replace.monitor.name}", "monitor_udp_5s")
        udp_monitors_tmsh.append(tmsh_monitor_create)
        udp_monitors_tmsh_rollback.append(tmsh_monitor_delete)
            
    monitor_validation_list.append((30, udp_monitors_notes, udp_monitors_spec, udp_monitors_tmsh, udp_monitors_tmsh_rollback, True))

    return monitor_validation_list



def sepc_persist_configuration_validation(data_all, vs_list):

    persist_validation_list = []

    persist_list = configParse.ltm_persistence_source_addr(data_all)
    persist_notes = ""
    persist_spec = SPEC_BASELINE_YES
    persist_tmsh, persist_tmsh_rollback = [], []
    for i in persist_list:
        if i.timeout != "300":
            persist_spec = SPEC_BASELINE_NO
            persist_notes = SPEC_APP_PERSIST_SOURCE_ADDR
            if i.timeout is not None:
                tmsh_modify = tmsh.get('tmsh', 'modify.ltm.persist').replace("${replace.persist.type}", "source-addr").replace("${replace.persist.name}", i.name).replace("${replace.persist.timeout}", "300")
                tmsh_rollback = tmsh.get('tmsh', 'modify.ltm.persist').replace("${replace.persist.type}", "source-addr").replace("${replace.persist.name}", i.name).replace("${replace.persist.timeout}", i.timeout)
                persist_tmsh.append(tmsh_modify)
                persist_tmsh_rollback.append(tmsh_rollback)

    if len(persist_list) <= 0:
        persist_spec = SPEC_BASELINE_NO
        persist_notes += SPEC_APP_PERSIST_SOURCE_ADDR_NONE
        tmsh_persist_create = tmsh.get('tmsh', 'create.ltm.persist').replace("${replace.persist.type}", "source-addr").replace("${replace.persist.name}", "src_addr_300s").replace("${replace.persist.timeout}", "300")
        tmsh_persist_delete = tmsh.get('tmsh', 'delete.ltm.persist').replace("${replace.persist.type}", "source-addr").replace("${replace.persist.name}", "src_addr_300s") 
        persist_tmsh.append(tmsh_persist_create)
        persist_tmsh_rollback.append(tmsh_persist_delete)

    persist_validation_list.append((31, persist_notes, persist_spec, persist_tmsh, persist_tmsh_rollback, True))

    return persist_validation_list



def sepc_pool_configuration_validation(data_all, vs_list):

    pool_validation_list = []

    pool_list = configParse.ltm_pool(data_all)
    pool_notes, pool_lb_notes = "", ""
    pool_spec, pool_lb_spec = SPEC_BASELINE_YES, SPEC_BASELINE_YES
    pool_tmsh, pool_tmsh_rollback, pool_lb_tmsh, pool_lb_tmsh_rollback = [], [], [], []
    for i in pool_list:
        if i.monitor is None or i.monitor != "tcp" or i.monitor != "monitor_tcp_5s":
            pool_notes = SPEC_POOL_MONITOR_NONE
            pool_spec = SPEC_BASELINE_NO
            tmsh_modify = tmsh.get('tmsh', 'modify.ltm.pool.monitor').replace("${replace.pool.name}", i.name).replace("${replace.monitor.name}", "monitor_tcp_5s")
            monitor_value = "none"
            if i.monitor is not None:
                monitor_value = i.monitor
            tmsh_rollback = tmsh.get('tmsh', 'modify.ltm.pool.monitor').replace("${replace.pool.name}", i.name).replace("${replace.monitor.name}", monitor_value)
            pool_tmsh.append(tmsh_modify)
            pool_tmsh_rollback.append(tmsh_rollback)
        elif i.lb_methods is not None or i.lb_methods == "round-robin":
            pool_lb_notes = SPEC_POOL_LB_NO_RR
            pool_lb_spec = SPEC_BASELINE_NO
            tmsh_lb_modify = tmsh.get('tmsh', 'modify.ltm.pool.lbmethods').replace("${replace.pool.name}", i.name).replace("${replace.pool.lbmethods}", "round-robin")
            tmsh_lb_rollback = tmsh.get('tmsh', 'modify.ltm.pool.lbmethods').replace("${replace.pool.name}", i.name).replace("${replace.pool.lbmethods}", i.lb_methods)
            pool_lb_tmsh.append(tmsh_lb_modify)
            pool_lb_tmsh_rollback.append(tmsh_lb_rollback)

    pool_validation_list.append((32, pool_notes, pool_spec, pool_tmsh, pool_tmsh_rollback, True))

    pool_validation_list.append((33, pool_lb_notes, pool_lb_spec, pool_lb_tmsh, pool_lb_tmsh_rollback, True))

    return pool_validation_list



def sepc_virtual_configuration_validation(data_all, vs_list):

    virtual_validation_list = []

    fastl4_list = configParse.ltm_profile_fastl4(data_all)
    fastl4_notes = ""
    fastl4_spec = SPEC_BASELINE_YES
    fastl4_tmsh, fastl4_tmsh_rollback = [], []
    for i in fastl4_list:
        if i.pva_acceleration is not None and i.pva_acceleration != "none":
            fastl4_notes = SPEC_VIRTUAL_FASTL4_PVA_ON
            fastl4_spec = SPEC_BASELINE_NO
            tmsh_pva_none = tmsh.get('tmsh', 'modify.ltm.profile.fastl4.pva').replace("${replace.profile.name}", i.name).replace("${replace.profile.pva}", "none")
            tmsh_pva_rollback = tmsh.get('tmsh', 'modify.ltm.profile.fastl4.pva').replace("${replace.profile.name}", i.name).replace("${replace.profile.pva}", i.pva_acceleration)
            tmsh_pva_none.append(tmsh_pva_none)
            tmsh_pva_rollback.append(tmsh_pva_rollback)

    virtual_validation_list.append((34, fastl4_notes, fastl4_spec, fastl4_tmsh, fastl4_tmsh_rollback, True))

    profiles_list = configParse.ltm_profile_web_acceleration(data_all)
    profiles_list.append("webacceleration")
    profiles_notes = ""
    profiles_spec = SPEC_BASELINE_YES
    profiles_tmsh, profiles_tmsh_rollback = [], []
    for i in vs_list:
        for j in i.profiles:
            if j in profiles_list:
                profiles_notes = SPEC_VIRTUAL_RAMCACHE
                profiles_spec = SPEC_BASELINE_NO
                tmsh_add = tmsh.get('tmsh', 'modify.ltm.virtual.profile.add').replace("${replace.virtual.name}", i.name).replace("${replace.virtual.profile}", j) 
                tmsh_del = tmsh.get('tmsh', 'modify.ltm.virtual.profile.del').replace("${replace.virtual.name}", i.name).replace("${replace.virtual.profile}", j) 
                profiles_tmsh.append(tmsh_del)
                profiles_tmsh_rollback.append(tmsh_del)

    virtual_validation_list.append((35, profiles_notes, profiles_spec, profiles_tmsh, profiles_tmsh_rollback, True))

    return virtual_validation_list




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
        wb = openpyxl.load_workbook(fileexcel)
        ws1 = wb.worksheets[0]
        ws2 = wb.worksheets[1]
        ws3 = wb.worksheets[2]
        ws2_start_id, ws3_start_id = 3, 3

        for i in range(3, 40):
            if ws2['B' + str(i)].value is None and ws2['C' + str(i)].value is None:
                ws2_start_id = i
                break

        for i in range(3, 40):
            if ws3['B' + str(i)].value is None and ws3['C' + str(i)].value is None:
                ws3_start_id = i
                break

        for item in self.spec_basic:
            cell_id = int(item[0]) + 1
            ws1['B' + str(cell_id)] = self.hostname
            ws1['C' + str(cell_id)] = self.management_ip 
            ws1['K' + str(cell_id)] = item[2]
            if item[2] == SPEC_BASELINE_YES:
                continue
            if item[5] == False:
                ws2['A' + str(ws2_start_id)] = item[0]
                ws2['B' + str(ws2_start_id)] = self.hostname
                ws2['C' + str(ws2_start_id)] = self.management_ip
                ws2['E' + str(ws2_start_id)] = configParse.convert_list_to_str_enter(item[3])
                ws2['F' + str(ws2_start_id)] = configParse.convert_list_to_str_enter(item[4])
                ws2['J' + str(ws2_start_id)] = item[1]
                ws2_start_id = ws2_start_id +1
            else:
                ws3['A' + str(ws3_start_id)] = item[0]
                ws3['B' + str(ws3_start_id)] = self.hostname
                ws3['C' + str(ws3_start_id)] = self.management_ip
                ws3['E' + str(ws3_start_id)] = configParse.convert_list_to_str_enter(item[3])
                ws3['F' + str(ws3_start_id)] = configParse.convert_list_to_str_enter(item[4])
                ws3['J' + str(ws3_start_id)] = item[1]
                ws3_start_id = ws3_start_id + 1
        wb.save(fileexcel)

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
    def parse(self):
        validation_results = spec_tcp_connection_configuration_validation(self.data, self.vs_list)
        self.spec_basic.extend(validation_results)

class SpecSNATConfiguration(SpecApp):
    def parse(self):
        validation_results = spec_snat_configuration_validation(self.data, self.vs_list)
        self.spec_basic.extend(validation_results) 

class SpecHTTPRstActionDownSetting(SpecApp):
    def parse(self):
        validation_results = sepc_http_rst_action_validation(self.data, self.vs_list)
        self.spec_basic.extend(validation_results)

class SpecMonitorConfiguration(SpecApp):
    def parse(self):
        validation_results = sepc_monitor_configuration_validation(self.data, self.vs_list)
        self.spec_basic.extend(validation_results)

class SpecPersistConfiguration(SpecApp):
    def parse(self):
        validation_results = sepc_persist_configuration_validation(self.data, self.vs_list)
        self.spec_basic.extend(validation_results)

class SpecPoolConfiguration(SpecApp):
    def parse(self):
        validation_results = sepc_pool_configuration_validation(self.data, self.vs_list)
        self.spec_basic.extend(validation_results)

class SpecVirtualConfiguration(SpecApp):
    def parse(self):
        validation_results = sepc_virtual_configuration_validation(self.data, self.vs_list)
        self.spec_basic.extend(validation_results)



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
fileexcel = sys.argv[2]


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
SPEC_ITEM_MONITOR_TIMEOUT = "健康检查时间"
SPEC_ITEM_PERSIT = "会话保持"
SPEC_ITEM_POOL = "POOL 配置检查"
SPEC_ITEM_VIRTUAL = "VIRTUAL 配置检查"


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
SPEC_NTP_SETTINGS_SERVERS_WRONG = "时区服务器数量不足"
SPEC_SECURE_ACL_ALLOWED_ADDR_ADD = "访问控制列表中允许登录的服务器地址小于 6"
SPEC_SECURE_ACL_ALLOWED_ADDR_DEL = "访问控制列表中允许登录的服务器地址大于 6"
SPEC_SECURE_ACL_ALLOWED_ADDR_NONE = "访问控制列表中允许登录的服务器地址为空"
SPEC_SNMP_COMMINITY_NOT_EXIST = "未配置只读SNMP community（psbc****）属性"
SPEC_SNMP_TRAP_NOT_EXIST = "未配置 Trap 网管服务器"
SPEC_SYSLOG_REMOTE_SERVER_NONE = "未配置SYSLOG服务器"
SPEC_INTERFACE_TRUNK_NONE = "未配置 trunk"
SPEC_INTERFACE_TRUNK_SINGLE_INTERFACE = "trunk绑定单链路接口 "
SPEC_INTERFACE_TRUNK_LACP = "trunk 启用LACP "
SEPC_INTERFACE_HA_TRUNK_SINGLE = "HA 线缆不满足至少两条且两条HA线配置及状态均正常"
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
SPEC_APP_MONITOR_INTERVAL_TIMEOUT = "探测超时时间超过16秒"
SPEC_APP_MONITOR_TCP = " 名称为monitor_tcp_5s的TCP健康检查模板不存在"
SPEC_APP_MONITOR_UDP = " 名称为monitor_udp_5s的TCP健康检查模板不存在"
SPEC_APP_PERSIST_SOURCE_ADDR = "源地址会话保持超时时间不是是300秒"
SPEC_APP_PERSIST_SOURCE_ADDR_NONE = " 源地址会话保持不存在"
SPEC_POOL_MONITOR_NONE = "Pool 上没有关联tcp健康检查"
SPEC_POOL_LB_NO_RR = "POOL池算法没有采用轮询算法"
SPEC_VIRTUAL_FASTL4_PVA_ON = "PVA 加速没有关闭"
SPEC_VIRTUAL_RAMCACHE = "RAMcache 没有关闭"

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
spec_validation_list.append(SpecMonitorConfiguration(SPEC_ITEM_MONITOR_TIMEOUT, device_info[0], device_info[1], device_info[2], bigip_running_config, vs_list_all))
spec_validation_list.append(SpecPersistConfiguration(SPEC_ITEM_PERSIT, device_info[0], device_info[1], device_info[2], bigip_running_config, vs_list_all))
spec_validation_list.append(SpecPoolConfiguration(SPEC_ITEM_POOL, device_info[0], device_info[1], device_info[2], bigip_running_config, vs_list_all))
spec_validation_list.append(SpecVirtualConfiguration(SPEC_ITEM_VIRTUAL, device_info[0], device_info[1], device_info[2], bigip_running_config, vs_list_all))


for spec in spec_validation_list:
    spec.write_to_excel()
