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

        vs_snatpool_name = ""
        snatpool_members_detail_list = []
        vs_pool_detail_list = re.search(r'pool\s+(\S+)', vs_data_detail, re.I)
        if vs_pool_detail_list:
            vs_pool_detail = vs_pool_detail_list.group(1)
            pool_data_start = re.search(r'ltm pool\s+'+vs_pool_detail, data_all, re.I).start()
            pool_data_end = re.search(r'}\s+}', data_all[pool_data_start:]).start()
            pool_data_detail = data_all[pool_data_start:][:pool_data_end]

            vs_snat_detail_list = re.search(r'source-address-translation\s+(\S+)', vs_data_detail, re.I)
            if vs_snat_detail_list:
                vs_snat_start = re.search(vs_snat_detail_list.group(), vs_data_detail, re.I).start()
                vs_snat_end = re.search("}", vs_data_detail[vs_snat_start:]).start()
                vs_snat_detail = vs_data_detail[vs_snat_start:][:vs_snat_end + 1]
                vs_snatpool_name_list = re.search(r'pool\s+(\S+)', vs_snat_detail, re.I)
                if vs_snatpool_name_list:
                    vs_snatpool_name = vs_snatpool_name_list.group(1)
                    vs_snatpool_data_start = re.search(r'ltm snatpool\s+'+vs_snatpool_name, data_all, re.I).start()
                    vs_snatpool_data_end = re.search(r'}\s+}', data_all[vs_snatpool_data_start:]).start()
                    vs_snatpool_data_detail = data_all[vs_snatpool_data_start:][:vs_snatpool_data_end + 1]
                    snatpool_members_detail_list = re.findall(r'(\d+\.\d+\.\d+\.\d+)', vs_snatpool_data_detail, re.I)

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
                    if len(snatpool_members_detail_list) > 0:
                        info_dict['snatpoolname'] = vs_snatpool_name
                        info_dict['snatpool'] = snatpool_members_detail_list 
                    info_list.append(info_dict)

#        vs_snat_detail_list = re.search(r'source-address-translation\s+(\S+)', vs_data_detail, re.I)
 #       if vs_snat_detail_list:
  #          vs_snat_start = re.search(vs_snat_detail_list.group(), vs_data_detail, re.I).start()
   #        vs_snat_end = re.search("}", vs_data_detail[vs_snat_start:]).start()
    #        vs_snat_detail = vs_data_detail[vs_snat_start:][:vs_snat_end + 1]
#            vs_snatpool_name_list = re.search(r'pool\s+(\S+)', vs_snat_detail, re.I)
 #           if vs_snatpool_name_list:
  #              vs_snatpool_name = vs_snatpool_name_list.group(1)
   #             vs_snatpool_data_start = re.search(r'ltm snatpool\s+'+vs_snatpool_name, data_all, re.I).start()
    #            vs_snatpool_data_end = re.search(r'}\s+}', data_all[vs_snatpool_data_start:]).start()
     #           vs_snatpool_data_detail = data_all[vs_snatpool_data_start:][:vs_snatpool_data_end + 1]
      #          snatpool_members_detail_list = re.findall(r'(\d+\.\d+\.\d+\.\d+)', vs_snatpool_data_detail, re.I)
       #        if snatpool_members_detail_list:
        #            print(vs_snatpool_name)
     #               print(snatpool_members_detail_list)
      #          print()
            #snatpool_data_start = re.search(r'ltm pool\s+'+vs_pool_detail, data_all, re.I).start()
            #snatpool_data_end = re.search(r'}\s+}', data_all[pool_data_start:]).start()
            #print(vs_snat_detail)
            #print(vs_snat_start)
            #print(vs_snat_end)
            
    return info_list                     



info_list = data_collect("../config/f5config.1")

#print(info_list)
for i in info_list:
    print(i)
