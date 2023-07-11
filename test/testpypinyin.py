#!/usr/bin/python3

from pypinyin import pinyin, Style

def listToString(s):
    result = ""
    for l in s:
        item = l[0]
        item = item[0].upper() + item[1:]
        result += item
    return result
        

name = "一体化运维平台"

result = pinyin(name, style=Style.NORMAL)

print(result)
print(listToString(result))

#result = [word[0].upper() + word[1:] for word in result]

#print(' '.join(result)) 

#result = ""
#a = pinyin(name, style=Style.FIRST_LETTER)


#print(a)
#print(listToString(a))
#print(type(a))
