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


class TestConfigParseValidation(unittest.TestCase):

    def test_data_search(self):
        filename = "BH-BF3M2-HX-L3600-1A.com_22.241.40.27_show#running-config_20230925050005.cfg.txt"
        file_running_config = "/Users/k.song/Downloads/psbc_running_config/" + filename
        data = load_bigip_running_config(file_running_config)
        if data is not None: 
            cm_device_list = cm_device(data)
            for i in cm_device_list:
                print(filename, i.hostname, i.management_ip, i.version)
            #print(cm_device_list)
            #self.assertEqual(len(net_route_list), 2)




if __name__ == '__main__':
    unittest.main()
