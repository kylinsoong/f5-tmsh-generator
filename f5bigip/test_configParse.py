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
        self.assertEqual(len(f5_config_dict['net']), 16)
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
                        print(i, ip, len(ip), type(ip))
                        self.assertTrue(is_valid_ip_network(ip))



if __name__ == '__main__':
    unittest.main()
is_valid_ip_network
