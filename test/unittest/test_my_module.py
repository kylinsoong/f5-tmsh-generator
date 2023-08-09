#!/usr/bin/python3

import unittest

from my_module import add

class TestAddFunction(unittest.TestCase):

    def test_add_positive_numbers(self):
        result = add(3, 5)
        self.assertEqual(result, 8)

    def test_add_negative_numbers(self):
        result = add(-3, -5)
        self.assertEqual(result, -8)

if __name__ == '__main__':
    unittest.main()
