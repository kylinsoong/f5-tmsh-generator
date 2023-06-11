#!/usr/bin/python3

import re, sys

def data_collect(filepath):
    info_list = []
    vs_list = []
    with open(filepath, 'r') as fo:
        data_all = fo.read()

    data_all = data_all.replace('[m','')
    data_all = data_all.replace('[K', '')
    error = re.findall(r'\[7m---\(less (\d+)',data_all)
    for i in error:
        error1 = '[7m---(less '+i
        data_all = data_all.replace(error1, '')
    fo.close()

    vs_name_data = re.findall(r'ltm virtual\s+\S+',data_all, re.I)
    for i in vs_name_data:
        vs_list.append(i)

    j=0
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

        vs_pool_detail_list = re.search(r'pool\s+(\S+)', vs_data_detail, re.I)
        if vs_pool_detail_list:
            vs_pool_detail = vs_pool_detail_list.group(1)
            pool_data_start = re.search(r'ltm pool\s+'+vs_pool_detail, data_all, re.I).start()
            pool_data_end = re.search(r'}\s+}', data_all[pool_data_start:]).start()
            pool_data_detail = data_all[pool_data_start:][:pool_data_end]

            pool_ip_port_detail_list = re.findall(r'(\d+\.\d+\.\d+\.\d+):(\S+)\s+{', pool_data_detail, re.I)
            if pool_ip_port_detail_list:
                for i,j in pool_ip_port_detail_list:
                    info_dict = {
                        'vsname': vs_name_detail,
                        'vsip': vs_ip_detail,
                        'vsport': vs_port_detail,
                        'poolmemberip': i,
                        'poolmemberport': j
                    }
                    info_list.append(info_dict)
        print(vs_data_detail)
        print("")
    return info_list                     



info_list = data_collect("f5config.2")

#print(info_list)
#for i in info_list:
#    print(i)
