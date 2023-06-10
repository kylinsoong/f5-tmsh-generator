#!/usr/bin/python3

from pypinyin import pinyin, Style

def listToString(s):
    result = ""
    for l in s:
        result += l[0]
    return result
        

name = "一体化运维平台"

result = ""
a = pinyin(name, style=Style.FIRST_LETTER)


print(a)
print(listToString(a))
print(type(a))
