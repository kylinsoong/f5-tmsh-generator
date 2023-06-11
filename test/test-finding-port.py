#!/usr/bin/python3

import socket

def convert_servicename_to_port(input):
    result = "";
    if isinstance(input, str):
        if input.isdigit():
            return input
        result = socket.getservbyname(input)
    else:
        result = input
    return str(result)

ports = ['http', 'http-alt', 'https', 'pcsync-https']

for i in ports:
    result = convert_servicename_to_port(i)
    print(result)
    print(type(result))

result = convert_servicename_to_port("5300")
print(result)
print(type(result))

#protocolname = 'tcp' 
#print ("Port: %s => service name: %s" %(80, socket.getservbyport(80, protocolname))) 
#print ("Port: %s => service name: %s" %(8080, socket.getservbyport(8080, protocolname))) 
#print ("Port: %s => service name: %s" %(443, socket.getservbyport(443, protocolname))) 
#print ("Port: %s => service name: %s" %(8443, socket.getservbyport(8443, protocolname))) 

#value = socket.getservbyname('http')

#print(value)
#print(type(value))

