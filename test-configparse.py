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
ltm_pool_list = configParse.collect_ltm_pool(running_config)

print(len(ltm_pool_list))

