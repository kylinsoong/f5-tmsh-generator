#!/usr/bin/python

with open("request.txt", "r") as file:
    for l in file:
        print(type(l))
        print(l.split(","))
