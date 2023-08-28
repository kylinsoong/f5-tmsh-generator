#!/usr/bin/python3

import sys

from f5bigip import configParse as p

def system_checking(data_str):

    results = []

    data = p.find_content_from_start_end(data_str, "Platform", "System Information")
    line = p.find_line_content_from_start_str(data, "Name")
    val = p.trip_prefix(line, None)
    if len(val) > 6:
        results.append({"key": "设备型号", "value": val})

    return results

def checking(filePath):

    data_str = ""
    with open(filePath, 'r',encoding='UTF-8') as  f:
        data_str = f.read()
    f.close

    datas = system_checking(data_str)

    if len(datas) == 0:
        datas.append({"key": "检查与 CMDB 型号是否一致", "value": "没有取到设备型号"})

    return datas
