#!/usr/bin/python3

import sys

def system_checking(data_str):

    results = []

    if "failsafe enabled" in data_str and "failsafe-timeout" in data_str:
        results.append({"key": "检查是否配置心跳检测", "value": "是"})    

    return results

def checking(filePath):

    data_str = ""
    with open(filePath, 'r',encoding='UTF-8') as  f:
        data_str = f.read()
    f.close

    datas = system_checking(data_str)

    if len(datas) == 0:
        datas.append({"key": "检查是否配置心跳检测", "value": "检查是否配置心跳检测错误"})

    return datas
