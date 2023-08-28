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
        datas.append({"key": "检查接口物理状态", "value": "没有取到每个接口状态"})

    return datas
