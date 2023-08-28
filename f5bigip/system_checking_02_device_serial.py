#!/usr/bin/python3

import sys

from f5bigip import configParse as p

def system_checking(data_str):

    results = []

    data = p.find_content_from_start_end(data_str, "System Information", None)
    line = p.find_line_content_from_start_str(data, "Chassis Serial")
    val = p.trip_prefix(line, None)
    if len(val) > 6:
        results.append({"key": "设备序列号", "value": val})

    return results

def checking(filePath):

    data_str = ""
    with open(filePath, 'r',encoding='UTF-8') as  f:
        data_str = f.read()
    f.close

    datas = system_checking(data_str)

    if len(datas) == 0:
        datas.append({"key": "检查序列号是否变化", "value": "没有取到设备序列号"})

    return datas
