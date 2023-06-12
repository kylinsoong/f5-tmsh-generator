#!/usr/bin/python3

import sys
import ast
import re
import socket

def manually_mapping(input):
    if input == 'any':
        return '0'
    else:
        print(input)
        return '0'

def convert_servicename_to_port(input):
    result = "";
    if isinstance(input, str):
        if input.isdigit():
            return input
        try:
            result = socket.getservbyname(input)
        except OSError:
            return manually_mapping(input)
    else:
        result = input
    return str(result)

def convert_servicename_to_port_f5(input):
    all_dict = {}
    with open("f5-services") as myfile:
        for line in myfile:
            name, var = line.partition(" ")[::2]
            all_dict[name.strip()] = var.strip()

    if input in all_dict:
        return all_dict[input]
    else:
        return convert_servicename_to_port(input)
    




if not sys.argv[1:]:
    print("Usage: extract-port-from-service-name.py [file]")
    sys.exit()

fileconfig = sys.argv[1]

with open(fileconfig, "r") as file:
    for line in file:
        convert_servicename_to_port_f5(line.replace('\n', ''))
