#!/usr/bin/python3

import unittest
import sys
import re


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

class TestF5TMSHValidation(unittest.TestCase):

    def test_running_config_validation(self):
        bigip_running_config = load_bigip_running_config("config/BH-BF2M1-HLW_APP-L3600-2A.com_11.16.176.91.running-config")
        print(len(bigip_running_config), bigip_running_config)
        self.assertEqual(14, 14)

if __name__ == '__main__':
    unittest.main()
