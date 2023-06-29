#!/usr/bin/python3

import re

def process(vs_data_detail):
    vs_pool_detail_list = re.findall(r'pool\s+(\S+)', vs_data_detail, re.I) 
    print(vs_pool_detail_list)


with open("clone-pools.txt", "r") as file:
    content = file.read()
    process(content)
