#!/usr/bin/python3

import sys
import ast
import re
import socket

def manually_mapping(input):
    if input == 'any':
        return '0'
#    elif input == 'tproxy':
#        return '8081' 
    else:
        print(input)

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



if not sys.argv[1:]:
    print("Usage: extract-port-from-service-name.py [file]")
    sys.exit()

fileconfig = sys.argv[1]

with open(fileconfig, "r") as file:
    for line in file:
        convert_servicename_to_port(line.replace('\n', ''))
