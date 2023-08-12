#!/usr/bin/python3

import unittest
import os
import time

from configParse import *

def load_config_data(filename):
    current_directory = os.path.dirname(os.path.abspath(__file__))
    parent_folder = os.path.dirname(current_directory)
    file_path = os.path.join(parent_folder, "config", filename)
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            content = file.read()
            file.close()
            content = content.replace('[m','')
            content = content.replace('[K', '')
            error = re.findall(r'\[7m---\(less (\d+)', content)
            for i in error:
                error1 = '[7m---(less '+i
                content = content.replace(error1, '')
            return content
    else:
        return None



class TestConfigParse(unittest.TestCase):


    def test_f5_config_dict(self):
        self.assertEqual(len(f5_config_dict['header']), 14)
        self.assertEqual(len(f5_config_dict['ltm']), 15)
        self.assertEqual(len(f5_config_dict['net']), 18)
        self.assertEqual(len(f5_config_dict['tail']), 35)

    def test_f5_services_dict(self):
        services = f5_services_dict.keys()
        services_list = list(services)
        self.assertEqual(len(services_list), 5878)

    def test_str_split(self):
        var = "ltm node {test} ltm node {test} ltm node {test}"
        array = var.split("ltm node")
        self.assertEqual(0, len(array[0])) 
        self.assertEqual(4, len(array))
        new_array = array[1:]
        for i in new_array:
            self.assertTrue("test" in i) 

    def test_data_search(self):
        data = load_config_data("bigip-v15.running-config")
        if data is not None: 
            re_results =  split_content_to_list_pattern(data, r'ltm pool\s+(\S+)', "ltm rule")
            str_results = split_content_to_list_split(data, "ltm pool", "ltm rule")
            self.assertEqual(len(re_results), len(str_results))

    def test_ltm_pool(self):
        configs = ["bigip-v15.running-config", "bigip-v13.running-config", "bigip-v11.running-config", "bigip-v10.running-config", "bigip-v13-config-clone-pool.1.running-config", "bigip-v13-config-clone-pool.2.running-config", "bigip-v13-f5config.1.running-config", "bigip-v13-f5config.2.running-config", "bigip-v13-f5config.3.running-config", "f5config.3", "f5config.2", "f5config.1", "f5config.0"]
        for i in configs:
            count = None
            if i == "bigip-v15.running-config":
                count = 8
            elif i == "bigip-v13.running-config":
                count = 221
            elif i == "bigip-v11.running-config":
                count = 272
            elif i == "bigip-v10.running-config":
                count = 15
            elif i == "bigip-v13-config-clone-pool.1.running-config":
                count = 133
            elif i == "bigip-v13-config-clone-pool.2.running-config":
                count = 37
            elif i == "bigip-v13-f5config.1.running-config":
                count = 18
            elif i == "bigip-v13-f5config.2.running-config":
                count = 171
            elif i == "bigip-v13-f5config.3.running-config":
                count = 18
            elif i == "f5config.3":
                count = 5
            elif i == "f5config.2":
                count = 2
            elif i == "f5config.1":
                count = 3
            elif i == "f5config.0":
                count = 3

            data = load_config_data(i)
            if data is not None:
                pool_list = ltm_pool(data)
                self.assertEqual(len(pool_list), count)
                for pool in pool_list:
                    for m in pool.members:
                        results = split_destination(m.member)
                        self.assertTrue(is_valid_ip_network(results[0]))
                        self.assertTrue(int(results[1]) >= 0 and int(results[1]) < 65535)


    def test_ltm_pool_lb_monitor(self):
        data = load_config_data("unittest.pool")
        pool_list = ltm_pool(data)
        self.assertEqual(len(pool_list), 1)
        name, lb_methods, members, monitor = pool_list[0].name, pool_list[0].lb_methods, pool_list[0].members, pool_list[0].monitor
        self.assertEqual(name, "pool_NGinx")
        self.assertEqual(lb_methods, "least-connections-member")
        self.assertEqual(len(members), 2)
        self.assertTrue("gateway_icmp" in monitor)
        self.assertTrue("http" in monitor)
        self.assertTrue("tcp" in monitor)
        member1, member2 = "192.168.6.11:80", "192.168.80.40:8080"
        member_list = []
        for m in members:
            member, address, port, session, state, connectionlimit = m.member, m.address, m.port, m.session, m.state, m.connectionlimit
            member_list.append(member)
            if member == member1:
                self.assertEqual(address, "192.168.6.11")
                self.assertEqual(port, "80")
                self.assertEqual(session, "monitor-enabled")
                self.assertEqual(state, "up")
                self.assertEqual(connectionlimit, "4")
            elif member == member2:
                self.assertEqual(address, "192.168.80.40")
                self.assertEqual(port, "8080")
                self.assertEqual(session, "user-disabled")
                self.assertEqual(state, "down")
        self.assertTrue(member1 in member_list)
        self.assertTrue(member2 in member_list)


    def test_ltm_pool_mess(self):
        data = load_config_data("unittest.pool.mess")
        pool_list = ltm_pool(data)
        self.assertEqual(len(pool_list), 3)
        name_a, name_b, name_c = "C_LianJiFuWu_duinei_6_pool", "C_LianJiFuWu_duinei_8_pool", "C_LianJiFuWu_duinei_10_pool"
        names_list = []
        for i in pool_list:
            name, lb_methods, members, monitor = i.name, i.lb_methods, i.members, i.monitor
            names_list.append(name)
            self.assertEqual(monitor, "gateway_icmp")
            self.assertEqual(len(members), 1)
            self.assertEqual(lb_methods, None)
            if name == name_a:
                self.assertEqual(members[0].member, "11.109.17.6:0")
                self.assertEqual(members[0].address, "11.109.17.6")
            elif name == name_b:
                self.assertEqual(members[0].member, "11.109.17.8:0")
                self.assertEqual(members[0].address, "11.109.17.8")
            elif name == name_c:
                self.assertEqual(members[0].member, "11.109.17.10:0")
                self.assertEqual(members[0].address, "11.109.17.10")
            self.assertEqual(members[0].port, "0")
            self.assertEqual(members[0].state, "up")


    def test_ltm_node(self):
        configs = ["bigip-v15.running-config", "bigip-v13.running-config", "bigip-v11.running-config", "bigip-v10.running-config", "bigip-v13-config-clone-pool.1.running-config", "bigip-v13-config-clone-pool.2.running-config", "bigip-v13-f5config.1.running-config", "bigip-v13-f5config.2.running-config", "bigip-v13-f5config.3.running-config", "f5config.3", "f5config.2", "f5config.1", "f5config.0"]
        for i in configs:
            count = None
            if i == "bigip-v15.running-config":
                count = 15
            elif i == "bigip-v13.running-config":
                count = 206
            elif i == "bigip-v11.running-config":
                count = 311
            elif i == "bigip-v10.running-config":
                count = 8
            elif i == "bigip-v13-config-clone-pool.1.running-config":
                count = 368
            elif i == "bigip-v13-config-clone-pool.2.running-config":
                count = 131
            elif i == "bigip-v13-f5config.1.running-config":
                count = 224
            elif i == "bigip-v13-f5config.2.running-config":
                count = 256
            elif i == "bigip-v13-f5config.3.running-config":
                count = 224
            elif i == "f5config.3":
                count = 14
            elif i == "f5config.2":
                count = 7
            elif i == "f5config.1":
                count = 13
            elif i == "f5config.0":
                count = 13

            data = load_config_data(i)
            if data is not None:
                node_list = ltm_node(data) 
                self.assertEqual(len(node_list), count)
                for n in node_list:
                    self.assertTrue(is_valid_ip_network(n.name))
                    if n.address is not None:
                        self.assertTrue(is_valid_ip_network(n.address))


    def test_ltm_snatpool(self):
        configs = ["bigip-v15.running-config", "bigip-v13.running-config", "bigip-v11.running-config", "bigip-v13-config-clone-pool.1.running-config", "bigip-v13-config-clone-pool.2.running-config", "bigip-v13-f5config.1.running-config", "bigip-v13-f5config.2.running-config", "bigip-v13-f5config.3.running-config", "f5config.3"]
        for i in configs:
            count = 0
            if i == "bigip-v15.running-config":
                count = 1
            elif i == "bigip-v13.running-config":
                count = 33
            elif i == "bigip-v11.running-config":
                count = 0
            elif i == "bigip-v13-config-clone-pool.1.running-config":
                count = 0
            elif i == "bigip-v13-config-clone-pool.2.running-config":
                count = 2
            elif i == "bigip-v13-f5config.1.running-config":
                count = 0
            elif i == "bigip-v13-f5config.2.running-config":
                count = 0
            elif i == "bigip-v13-f5config.3.running-config":
                count = 0
            elif i == "f5config.3":
                count = 3

            data = load_config_data(i)
            if data is not None:
                snatpool_list = ltm_snatpool(data)
                self.assertEqual(len(snatpool_list), count)
                for snat in snatpool_list:
                    for ip in snat.members:
                        self.assertTrue(is_valid_ip_network(ip))


    def test_ltm_snatpool_parse_with_mess(self):
        data = load_config_data("unittest.snatpool")
        snatpool_list = ltm_snatpool(data)
        self.assertEqual(len(snatpool_list), 2)
        name1, name2 = "snatpool_11.0.70.0", "weixinyinhangshangyun_yizhuang_snat"
        snatpool_names = []
        for snat in snatpool_list:
            snatpool_names.append(snat.name)
            snatpool_members = snat.members
            if name1 == snat.name:
                self.assertEqual(len(snatpool_members), 248)
                self.assertTrue("11.0.70.2" not in snatpool_members)
                self.assertTrue("11.0.70.3" in snatpool_members)
                self.assertTrue("11.0.70.4" in snatpool_members)
            elif name2 == snat.name:
                self.assertEqual(len(snatpool_members), 19)
                self.assertTrue("192.168.129.41" not in snatpool_members)
                self.assertTrue("192.168.129.42" in snatpool_members)
                self.assertTrue("192.168.129.43" in snatpool_members)
            for ip in snatpool_members:
                self.assertTrue(is_valid_ip_network(ip))
        self.assertTrue(name1 in snatpool_names)
        self.assertTrue(name2 in snatpool_names)


    def test_find_ip_from_line(self):
        ip1 = find_ip_from_line("IP addresses 192.168.1.1")
        ip2 = find_ip_from_line("and 2001:0db8:85a3:0000:0000:8a2e:0370:7334.")
        ip3 = find_ip_from_line("0.0.0.0:0")
        ip4 = find_ip_from_line("IP addresses 1920.168.1.1")
        ip5 = find_ip_from_line("and 2001:0db8:85a3:0000:0000:8a2e:0370:733g.")
        self.assertEqual(ip1, "192.168.1.1")
        self.assertEqual(ip2, "2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        self.assertEqual(ip3, "0.0.0.0")
        self.assertEqual(ip4, None)
        self.assertEqual(ip5, None)


    def test_data_search_performance(self):
        data = load_config_data("bigip-v11.running-config")
        total_time_pattern = 0 
        if data is not None:
            for number in range(1, 6):
                start_time = time.time()
                re_results =  split_content_to_list_pattern(data, r'ltm pool\s+(\S+)', "ltm rule")
                end_time = time.time()
                total_time = end_time - start_time
                total_time_pattern += total_time
                self.assertTrue(total_time > 0)

        total_time_split = 0
        if data is not None:
            for number in range(1, 6):
                start_time = time.time()
                re_results =  split_content_to_list_split(data, "ltm pool", "ltm rule")
                end_time = time.time()
                total_time = end_time - start_time
                self.assertTrue(total_time > 0)
                total_time_split += total_time

        self.assertTrue(total_time_pattern > total_time_split)
        self.assertTrue(total_time_pattern/ total_time_split > 100) # split search has better performance, 100 times than search with re pattern

    def test_ltm_virtual(self):
        data = load_config_data("f5config.3")
        vs_list = ltm_virtual(data)
        self.assertEqual(len(vs_list), 4)
        n1, n2, n3, n4 = "ydbg_10.1.10.11_80_vs", "sjyh_10.1.10.12_80_vs", "qywx_10.1.10.13_80_vs", "qywy_10.1.10.14_80_vs"
        vs_name_list = []
        for i in vs_list:
            vs_name_list.append(i.vs_name)
            self.assertEqual(i.vs_port, "80")
            self.assertEqual(i.vs_mask, "255.255.255.255")
            self.assertEqual(i.ip_protocol, "tcp")
            self.assertTrue("http" in i.profiles)
            self.assertTrue("tcp" in i.profiles)
            if i.vs_name == n1:
                self.assertEqual(i.vs_ip, "10.1.10.11")
                self.assertEqual(i.pool, "ydbg_10.1.10.11_80_pool")
                self.assertEqual(i.snatpool, "ydbg_10.1.10.11_snat")
                self.assertEqual(i.snatType, "snat")
            elif i.vs_name == n2:
                self.assertEqual(i.vs_ip, "10.1.10.12")
                self.assertEqual(i.pool, "sjyh_10.1.10.12_80_pool")
                self.assertEqual(i.snatpool, None)
                self.assertEqual(i.snatType, "automap")
                self.assertTrue("clientssl" in i.profiles)
                self.assertTrue("serverssl" in i.profiles)
                self.assertTrue("irules_clone" in i.rules)
                self.assertTrue("reset" in i.serviceDownReset)
            elif i.vs_name == n3:
                self.assertEqual(i.vs_ip, "10.1.10.13")
                self.assertEqual(i.pool, None)
                self.assertEqual(i.snatpool, "qywx_10.1.10.13_snat")
                self.assertEqual(i.snatType, "snat")
                self.assertTrue("clientssl" in i.profiles)
                self.assertTrue("serverssl" in i.profiles)
                self.assertTrue("irules_clone" in i.rules)
                self.assertTrue("reset" in i.serviceDownReset)
            elif i.vs_name == n4:
                self.assertEqual(i.vs_ip, "10.1.10.14")
                self.assertEqual(i.pool, None)
        self.assertTrue(n1 in vs_name_list and n2 in vs_name_list and n3 in vs_name_list and n4 in vs_name_list)



    def test_ltm_virtual_vlans(self):
        data = load_config_data("unittest.virtual.vlans")
        vs_list = ltm_virtual(data)
        self.assertEqual(len(vs_list), 2)
        n1, n2 = "MB_forwarding_11.19.8.102_vs", "MB_forwarding_vs"
        vs_name_list = []
        for i in vs_list:
            vs_name_list.append(i.vs_name)
            self.assertTrue("fastL4" in i.profiles)
            self.assertEqual(i.vs_port, "0")
            if i.vs_name == n1:
                self.assertEqual(i.vs_ip, "11.19.8.102")
                self.assertTrue("MB_forwarding_11.19.8.40_irules" in i.rules)
                self.assertTrue("vlan223_external" in i.vlans)
                self.assertTrue("vlan246_internal" in i.vlans)
            elif i.vs_name == n2:
                self.assertEqual(i.vs_ip, "0.0.0.0")
                self.assertTrue("forwarding-rules" in i.rules)
                self.assertTrue("vlan112_internal" in i.vlans)
                self.assertTrue("vlan246_internal" in i.vlans)
                self.assertTrue("vlan248_internal" in i.vlans)
        self.assertTrue(n1 in vs_name_list and n2 in vs_name_list)


    def test_ltm_virtual_persist(self):
        data = load_config_data("unittest.virtual.persist")
        vs_list = ltm_virtual(data)
        self.assertEqual(len(vs_list), 2)
        n1, n2 = "test_http", "DSFZF-YZ-tcp-8080-vs"
        vs_name_list = []
        for i in vs_list:
            vs_name_list.append(i.vs_name)
            if i.vs_name == n1:
                self.assertEqual(i.vs_ip, "192.168.6.125")
                self.assertEqual(i.vs_port, "8081")
                self.assertEqual(i.persist, "cookie")
                self.assertTrue("decommpress" in i.profiles and "http" in i.profiles and "tcp" in i.profiles and "serverssl" in i.profiles)
            elif i.vs_name == n2:
                self.assertEqual(i.vs_ip, "11.6.81.103")
                self.assertEqual(i.vs_port, "8080")
                self.assertEqual(i.persist, "source_addr_10M")
                self.assertTrue("fastL4" in i.profiles)
        self.assertTrue(n1 in vs_name_list and n2 in vs_name_list)        


    def test_ltm_viarual_ipv6(self):
        data = load_config_data("unittest.virtual.ipv6")
        vs_list = ltm_virtual(data)
        self.assertEqual(len(vs_list), 1)
        self.assertTrue(is_valid_ip_network(vs_list[0].vs_ip))


    def test_ltm_viarual_all(self):
        configs = ["bigip-v15.running-config", "bigip-v13.running-config", "bigip-v11.running-config", "bigip-v10.running-config", "bigip-v13-config-clone-pool.1.running-config", "bigip-v13-config-clone-pool.2.running-config", "bigip-v13-f5config.1.running-config", "bigip-v13-f5config.2.running-config", "bigip-v13-f5config.3.running-config", "f5config.3", "f5config.2", "f5config.1", "f5config.0"]
        for i in configs:
            count = None
            if i == "bigip-v15.running-config":
                count = 11
            elif i == "bigip-v13.running-config":
                count = 151
            elif i == "bigip-v11.running-config":
                count = 269
            elif i == "bigip-v10.running-config":
                count = 7
            elif i == "bigip-v13-config-clone-pool.1.running-config":
                count = 99
            elif i == "bigip-v13-config-clone-pool.2.running-config":
                count = 29
            elif i == "bigip-v13-f5config.1.running-config":
                count = 15
            elif i == "bigip-v13-f5config.2.running-config":
                count = 167
            elif i == "bigip-v13-f5config.3.running-config":
                count = 15
            elif i == "f5config.3":
                count = 4
            elif i == "f5config.2":
                count = 4
            elif i == "f5config.1":
                count = 3
            elif i == "f5config.0":
                count = 3

            data = load_config_data(i)
            if data is not None:
                vs_list = ltm_virtual(data)
                self.assertEqual(len(vs_list), count)
                for v in vs_list:
                    self.assertTrue(is_valid_ip_network(v.vs_ip))
                

if __name__ == '__main__':
    unittest.main()
