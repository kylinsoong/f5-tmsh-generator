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

