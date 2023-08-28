#!/usr/bin/python3

import sys

from f5bigip import configParse as p

def system_checking(data_str):

    results = []

    data = p.find_content_from_start_end(data_str, "CPU Status", "Hardware Version Information")
    data = p.trip_prefix(data, None)
    lines = data.splitlines()
    for l in lines:
        line = p.trip_prefix(l, None)
        if "Temp" not in line and "Status" not in line and len(line) > 0:
            raws = line.split(" ")
            cpu_list = [i.strip() for i in raws if len(p.trip_prefix(i, None)) > 0]
            key = "CPU " + cpu_list[0] + " 温度"
            val = cpu_list[1]
            results.append({"key": key, "value": val})

    return results

def checking(filePath):

    data_str = ""
    with open(filePath, 'r',encoding='UTF-8') as  f:
        data_str = f.read()
    f.close

    datas = system_checking(data_str)

    if len(datas) == 0:
        datas.append({"key": "检查温度是否正常", "value": "没有取到状态或数值"})

    return datas
