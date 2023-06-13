#!/usr/bin/python3

import sys
import re

def test_parse(vs_data_detail):

    vs_snatpool_name = ""
    snatpool_members_detail_list = []
    vs_pool_detail_list = re.search(r'pool\s+(\S+)', vs_data_detail, re.I)

    if vs_pool_detail_list:
        vs_pool_detail = vs_pool_detail_list.group(1)

        vs_snat_detail_list = re.search(r'source-address-translation\s+(\S+)', vs_data_detail, re.I)
        if vs_snat_detail_list:
            vs_snat_start = re.search(vs_snat_detail_list.group(), vs_data_detail, re.I).start()
            vs_snat_end = re.search("}", vs_data_detail[vs_snat_start:]).start()
            vs_snat_detail = vs_data_detail[vs_snat_start:][:vs_snat_end + 1]
            vs_snatpool_name_list = re.search(r'pool\s+(\S+)', vs_snat_detail, re.I)
            if vs_snatpool_name_list:
                vs_snatpool_name = vs_snatpool_name_list.group(1)
            else:
                vs_snatpool_name = ""
        else:
            vs_snatpool_name = ""

        if vs_pool_detail == vs_snatpool_name:
            
        else:
        print(vs_snatpool_name)

        print(vs_pool_detail)
        print(vs_pool_detail_list)
        print(vs_data_detail[229:][:254])
    else:
        print("VS not related with pool")

with open("../config/f5config.2.3", "r") as file:
    test_parse(file.read())
