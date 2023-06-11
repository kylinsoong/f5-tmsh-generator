#!/usr/bin/python3

import re, sys


def data_collect():
    info_list = []
    vs_list = []
    filepath = 'F5config'
    # filepath = sys.argv[1]
    with open(filepath, 'r') as fo:
        data_all = fo.read()
    print(data_all)

    input('press any key to continue')

    data_all = data_all.replace('[m','')
    data_all = data_all.replace('[K', '')
    error = re.findall(r'\[7m---\(less (\d+)',data_all)
    for i in error:
        #print(i)
        error1 = '[7m---(less '+i
        #print(error1)
        data_all = data_all.replace(error1, '')
    #data_all=data_all.replace('#slb policy setting topology','slb policy setting topology')
    #print(data_list)
    fo.close()
    # 取VS内容
    # vs_start = re.search(r'Virtual server state:', data_all, re.I).start()
    # # print(service_start)
    # vs_end = re.search(r'IDS group state:', data_all[vs_start:]).start()
    # vs_data = data_all[vs_start:][:vs_end]
    # # print('========================')
    # #print(vs_data)
    # # 取pool内容
    # pool_start = re.search(r'list slb pool all_properties', data_all, re.I).start()
    # # print(service_start)
    # #pool_end = re.search(r'list slb pool all_properties', data_all[vs_start:]).start()
    # pool_data = data_all[pool_start:]
    # #print(pool_data)
    # 取VS的名称
    vs_name_data = re.findall(r'ltm virtual\s+\S+',data_all, re.I)
    for i in vs_name_data:
        vs_list.append(i)
    #print(len(vs_list))
    #print(vs_list[1])
    #print(type(len(vs_list)))
    j = 0
    for i,num  in zip(vs_name_data,range(len(vs_name_data))):

        #print(i)
        # 截取每一个VS的内容
        if num < len(vs_list)-1:
            vs_data_start = re.search(i, data_all, re.I).start()
            vs_data_end = re.search(vs_list[num+1], data_all[vs_data_start:]).start()
            vs_data_detail = data_all[vs_data_start:][:vs_data_end]
        else:
            vs_data_start = re.search(i, data_all, re.I).start()
            vs_data_end = re.search(r'net interface', data_all[vs_data_start:]).start()
            vs_data_detail = data_all[vs_data_start:][:vs_data_end]
        # print('===================')
        # j = int(j) + 1

        #print(vs_data_detail)

        # 取VS的具体名称
        vs_name_detail_list = re.search(r'ltm virtual\s+(\S+)', vs_data_detail,re.I)
        vs_name_detail = vs_name_detail_list.group(1)
        #print(vs_name_detail)
        # 取VS的具体IP
        vs_ip_detail_list = re.search(r'destination\s+(\d+\.\d+\.\d+\.\d+)', vs_data_detail, re.I)
        vs_ip_detail = vs_ip_detail_list.group(1)
        #print(vs_ip_detail)
        # 取VS的具体端口
        vs_port_detail_list = re.search(r'destination\s+\d+\.\d+\.\d+\.\d+:(\S+)', vs_data_detail, re.I)
        vs_port_detail = vs_port_detail_list.group(1)
        #print(vs_port_detail)
        # 取VS的具体pool
        vs_pool_detail_list = re.search(r'pool\s+(\S+)', vs_data_detail, re.I)
        if vs_pool_detail_list:

            vs_pool_detail = vs_pool_detail_list.group(1)
            #print(vs_pool_detail)
            #
            # 截取每一个pool的内容
            pool_data_start = re.search(r'ltm pool\s+'+vs_pool_detail, data_all, re.I).start()
            pool_data_end = re.search(r'}\s+}', data_all[pool_data_start:]).start()
            pool_data_detail = data_all[pool_data_start:][:pool_data_end]
            # #print(pool_data_detail)
            # #print('----------------------')
            # 取VS的具体IP
            pool_ip_port_detail_list = re.findall(r'(\d+\.\d+\.\d+\.\d+):(\S+)\s+{', pool_data_detail, re.I)
            # print(pool_ip_detail_list)
            # pool_ip_detail = pool_ip_detail_list.group(1)
            # print(vs_ip_detail)
            # 取pool的具体端口
            #pool_port_detail_list = re.findall(r'"port":\s+(\S+),', pool_data_detail, re.I)
            # pool_port_detail = pool_port_detail_list.group(1)
            # print(pool_port_detail_list)
            # for i, j in zip(pool_ip_detail_list, pool_port_detail_list):
            #     # print(i,j)
            if pool_ip_port_detail_list:
                for i,j in pool_ip_port_detail_list:
                    #print(i,j)
                    # addresslist.append(vs_data_detail)
                    # 存在字典里面
                    info_dict = {
                        'vsname': vs_name_detail,
                        'vsip': vs_ip_detail,
                        'vsport': vs_port_detail,
                        'practicalip': i,
                        'practicalport': j
                    }
                    #print(info_dict)
                    info_list.append(info_dict)
    for i in info_list:
        print(i)
    print([{'table': 'IEAI_NETINFO_VS', 'detail': info_list}])

data_collect()
