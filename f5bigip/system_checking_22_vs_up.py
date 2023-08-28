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
        datas.append({"key": "检查当前所有 VS 运行状态是否为 UP", "value": "检查当前所有 VS 运行状态是否为 UP 错误"})

    return datas
