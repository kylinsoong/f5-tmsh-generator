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

#results = configParse.sys_management_route(running_config)
#for i in results:
#    print(i.name, i.gateway, i.network)

#results = configParse.ltm_profile_web_acceleration(running_config)
#for i in results:
#    print(i.name, len(i.name), i.parent)

#results1 = configParse.ltm_monitor_http(running_config)
#results2 = configParse.ltm_monitor_tcp(running_config)
#results3 = configParse.ltm_monitor_udp(running_config)

#for i in results1:
#    print(i.type, i.name, i.interval, i.timeout)

#for i in results2:
#    print(i.type, i.name, i.interval, i.timeout)

#for i in results3:
#    print(i.type, i.name, i.interval, i.timeout)

profile_list = configParse.ltm_profile_fastl4(running_config)
for i in profile_list:
    print(i.name, i.parent, i.idle_timeout, i.tcp_handshake_timeout, i.pva_acceleration)
