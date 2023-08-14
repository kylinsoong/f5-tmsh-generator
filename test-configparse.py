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

results = configParse.net_route(running_config)
for i in results:
    print(i.name, i.gw, i.network)
