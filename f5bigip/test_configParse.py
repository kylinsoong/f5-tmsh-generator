#!/usr/bin/python3

import unittest

from configParse import *


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


if __name__ == '__main__':
    unittest.main()

