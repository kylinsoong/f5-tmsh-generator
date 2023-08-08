#!/usr/bin/python3

import configparser
import os

def newInstance():
    current_directory = os.path.dirname(os.path.abspath(__file__))
    properties_file_path = os.path.join(current_directory,  'tmsh.ini')
    instance = configparser.ConfigParser()
    instance.read(properties_file_path)
    return instance

config = newInstance()

def get(category, key):
    return config.get(category, key)

