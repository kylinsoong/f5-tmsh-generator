#!/usr/bin/python3

import sys
import re
import ipaddress

from f5bigip import configParse
from f5bigip import tmsh


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
        user_create = tmsh.get('tmsh', 'create.auth.user').replace("${auth.user.name}", "psbc").replace("${auth.user.role}", "admin")
        user_config_tmsh.append(user_create)
        user_delete = tmsh.get('tmsh', 'delete.auth.user').replace("${auth.user.name}", "psbc")
        user_config_rollback_tmsh.append(user_delete)
    if "view" not in user_role_dict:
        user_config_note.append(SPEC_USER_MANAGEMENT_VIEW_NOT_EXIST)
        user_config_spec = SPEC_BASELINE_NO
        user_create = tmsh.get('tmsh', 'create.auth.user').replace("${auth.user.name}", "view").replace("${auth.user.role}", "auditor")
        user_config_tmsh.append(user_create)
        user_delete = tmsh.get('tmsh', 'delete.auth.user').replace("${auth.user.name}", "view")
        user_config_rollback_tmsh.append(user_delete)

    user_validation_list.append((1, user_config_note, user_config_spec, user_config_tmsh,user_config_rollback_tmsh,  False))

    default_user_note = ""
    default_user_spec = SPEC_BASELINE_YES
    default_user_tmsh = ""
    default_user_rollback_tmsh = ""
    if "admin" in user_role_dict:
        default_user_note = SPEC_USER_MANAGEMENT_ADMIN_NOT_DELETE
        default_user_spec = SPEC_BASELINE_NO
        default_user_tmsh = tmsh.get('tmsh', 'modify.sys.db.systemauth').replace("${auth.user.name}", "psbc")
        default_user_rollback_tmsh = tmsh.get('tmsh', 'modify.sys.db.systemauth').replace("${auth.user.name}", "admin")

    user_validation_list.append((2, default_user_note, default_user_spec, default_user_tmsh, default_user_rollback_tmsh, False))

    user_role_config_note = []
    user_role_config_spec = SPEC_BASELINE_YES
    user_role_config_tmsh = []
    user_role_config_rollback_tmsh = []
    if "psbc" in user_role_dict and user_role_dict['psbc'] != "admin":
        user_role_config_note.append(SPEC_USER_MANAGEMENT_PSBC_NO_EXPECT_RIGHT)
        user_role_config_spec = SPEC_BASELINE_NO
        user_modify = tmsh.get('tmsh', 'modify.auth.user').replace("${auth.user.name}", "psbc").replace("${auth.user.role}", "admin")
        user_role_config_tmsh.append(user_modify)
        user_modify_rollback = tmsh.get('tmsh', 'modify.auth.user').replace("${auth.user.name}", "psbc").replace("${auth.user.role}", user_role_dict['psbc'])
        user_role_config_rollback_tmsh.append(user_modify_rollback)

    if "view" in user_role_dict and user_role_dict['view'] != "auditor":
        user_role_config_note.append(SPEC_USER_MANAGEMENT_VIEW_NO_EXPECT_RIGHT)
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


    user_login_validation_list.append((4, self_allow_default_note, self_allow_default_spec, self_allow_default_tmsh, self_allow_default_rollback_tmsh, False))
    user_login_validation_list.append((5, self_allow_default_note, self_allow_default_spec, self_allow_default_tmsh, self_allow_default_rollback_tmsh, False))

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

    user_login_validation_list.append((6, timeout_validation_note, timeout_validation_spec, timeout_validation_tmsh, timeout_validation_rollback_tmsh, False))
    
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
    ntp_validation_list.append((7, timezone_validation_note, timezone_validation_spec, timezone_validation_tmsh, False))

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

    snmp_validation_list.append((9, "", SPEC_BASELINE_YES, [], [], False))
    snmp_validation_list.append((10, "", SPEC_BASELINE_YES, ["v2c"], [], False))

    if "psbcread" not in communities_name_list:
        tmsh_community_add = tmsh.get('tmsh', 'modify.sys.snmp.communities.add').replace("${sys.snmp.community}", "XX").replace("${sys.snmp.community.name}", "XX")
        tmsh_community_del = tmsh.get('tmsh', 'modify.sys.snmp.communities.del').replace("${sys.snmp.community}", "XX")
        snmp_validation_list.append((11, SPEC_SNMP_COMMINITY_NOT_EXIST, SPEC_BASELINE_NO, [tmsh_community_add], [tmsh_community_del], False))
    else:
        snmp_validation_list.append((11, "", SPEC_BASELINE_YES, [], [], False))

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

    syslog_validation_list.append((14, SPEC_SYSLOG_REMOTE_SERVER_NONE, SPEC_BASELINE_YES, [tmsh.get('tmsh', 'modify.sys.syslog.log.level')], [], False))

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
