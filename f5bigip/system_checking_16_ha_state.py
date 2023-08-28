#!/usr/bin/python3

import sys

def system_checking(data_str):

    results = []

    return results

def checking(filePath):

    data_str = ""
    with open(filePath, 'r',encoding='UTF-8') as  f:
        data_str = f.read()
    f.close

    datas = system_checking(data_str)

    if len(datas) == 0:
        datas.append({"key": "检查双机状态", "value": "取当前设备是主是备错误"})

    return datas
