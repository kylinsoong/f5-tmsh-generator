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
        datas.append({"key": "检查吞吐量", "value": "检查吞吐量错误"})

    return datas
