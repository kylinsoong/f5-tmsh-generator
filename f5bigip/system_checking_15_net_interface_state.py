#!/usr/bin/python3

import sys

def trip_prefix(line, prefix):
    if len(line) > 0 and prefix is not None and prefix in line:
        return line.strip().lstrip(prefix).strip()
    else:
        return line.strip()

def system_checking(data_str):

    results = []

    data = trip_prefix(data_str, None)
    lines = data.splitlines()
    for l in lines:
        line = trip_prefix(l, None)
        if line[0].isdigit() or "mgmt" in line:
            raws = line.split(" ")
            inter_list = [i.strip() for i in raws if len(trip_prefix(i, None)) > 0]
            key = "接口 " + inter_list[0] + " 状态"
            val = inter_list[1]
            results.append({"key": key, "value": val})

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
