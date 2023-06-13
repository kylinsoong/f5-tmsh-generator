#!/usr/bin/python3

x = "TEST"

print(x)
print(type(x))

x = None

print(x)
print(type(x))

if x is not None:
    print(x)

y = ['a','b','c']

print(y)
print(type(y))

y = None

print(y)
print(type(y))

if y is not None and len(y) > 0:
    print(y)

