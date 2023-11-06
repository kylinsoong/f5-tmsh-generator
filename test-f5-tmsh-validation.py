#!/usr/bin/python3

import unittest
import sys
import re
import os
from f5bigip import configParse


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

def data_collect_system_extract_hostname(data_all):
    devices = configParse.cm_device(data_all)
    return (devices[0].hostname, devices[0].management_ip, devices[0].version)

class TestF5TMSHValidation(unittest.TestCase):

    def test_running_config_validation(self):
        directory = '/Users/k.song/Downloads/psbc_running_config'
        files = os.listdir(directory)
        file_paths = [os.path.join(directory, file) for file in files]
        cusor = 1
        for file_path in file_paths:
            bigip_running_config = load_bigip_running_config(file_path)
            results = data_collect_system_extract_hostname(bigip_running_config)
            if results[0] is None or results[1] is None or results[2] is None:
                print(cusor, os.path.basename(file_path), results)
                cusor += 1

        self.assertEqual(14, 14)

if __name__ == '__main__':
    unittest.main()
