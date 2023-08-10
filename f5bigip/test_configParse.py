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
        data = load_config_data("bigip-v11.running-config")
        if data is not None: 
            start_time = time.time()
            re_results =  split_content_to_list_pattern(data, r'ltm pool\s+(\S+)', "ltm rule")
            middle_time = time.time()
            str_results = split_content_to_list_split(data, "ltm pool", "ltm rule")
            self.assertEqual(len(re_results), len(str_results))
            end_time = time.time()

    def test_data_search_performance_pattern(self):
        data = load_config_data("bigip-v11.running-config")
        print("search performance pattern:")
        if data is not None:
            for number in range(1, 6):
                start_time = time.time()
                re_results =  split_content_to_list_pattern(data, r'ltm pool\s+(\S+)', "ltm rule")
                end_time = time.time()
                total_time = end_time - start_time
                self.assertTrue(total_time > 0)
                print(number, total_time)            

    def test_data_search_performance_split(self):
        data = load_config_data("bigip-v11.running-config")
        print("search performance split:")
        if data is not None:
            for number in range(1, 6):
                start_time = time.time()
                re_results =  split_content_to_list_split(data, "ltm pool", "ltm rule")
                end_time = time.time()
                total_time = end_time - start_time
                self.assertTrue(total_time > 0)
                print(number,  total_time)


if __name__ == '__main__':
    unittest.main()

