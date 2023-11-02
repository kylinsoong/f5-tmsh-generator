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


class TestConfigParseValidation(unittest.TestCase):

    def test_data_search(self):
        data = load_config_data("-BH-BF2M1-HLW_APP-L2000-1B.com_11.16.160.28.running-config")
        if data is not None: 
            net_route_list = net_route(data)
            self.assertEqual(len(net_route_list), 2)

    def test_net_route(self):
        data = load_config_data("test.net.route")
        net_route_list = net_route(data)
        self.assertEqual(len(net_route_list), 1)


if __name__ == '__main__':
    unittest.main()
