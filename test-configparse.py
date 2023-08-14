#!/usr/bin/python3

import sys
import re

from f5bigip import configParse

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

if not sys.argv[1:]:
    print("Usage: test-configparse.py  [file]")
    sys.exit()

fileconfig = sys.argv[1]

running_config = load_bigip_running_config(fileconfig)
#results = configParse.ltm_persistence_cookie(running_config)
#results = configParse.cm_device(running_config)
#results = configParse.cm_device_group(running_config)
#results = configParse.net_self(running_config)
#results = configParse.net_vlan(running_config)


#print(len(results))

#for i in results:
#    print(i.name, i.fwd_mode, i.if_index, i.interfaces[0].name, i.interfaces[0].tag_mode, i.interfaces[0].tagged, i.sflow_poll_interval_global, i.sflow_sampling_rate_global, i.tag)
    #if "traffic-group-1" == i.trafficgroup:
    #print(i.name, i.address, i.allowservice, i.floating, i.trafficgroup, i.vlan, "---", i.floating)
    #print(i.name, i.autosync, i.devices, i.fullloadonsync, i.networkfailover, i.type)
    #print(i.configsync_ip, i.failover_state, i.hostname, i.management_ip, i.self_device, i.time_zone, i.unicast_address, i.unicast_port, i.version)

#print(configParse.find_ip_from_line("2001::125.http"))

#print(configParse.find_end_str(configParse.split_data_all(running_config)[1], "ltm virtual", configParse.f5_config_dict['ltm']))

#sys_sshd = configParse.sys_sshd(running_config)
#sys_httpd = configParse.sys_httpd(running_config)
#print(sys_sshd.allow, " - ", sys_sshd.inactivity_timeout)
#print(sys_httpd.allow, " - ", sys_httpd.auth_pam_idle_timeout)
ntp = configParse.sys_ntp(running_config)
print(ntp, ntp.servers, len(ntp.servers), ntp.timezone)
