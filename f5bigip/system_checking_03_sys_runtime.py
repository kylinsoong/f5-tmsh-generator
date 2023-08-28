#!/usr/bin/python3

import sys

def trip_prefix(line, prefix):
    if len(line) > 0 and prefix is not None and prefix in line:
        return line.strip().lstrip(prefix).strip()
    else:
        return line.strip()

def system_checking(data_str):

    results = []

    lines = trip_prefix(data_str, None).splitlines()
    for l in lines:
        line = trip_prefix(l, None)
        if line.startswith("available"):
            raws = trip_prefix(line, "available")
            day_list = [i.strip() for i in raws if len(trip_prefix(i, None)) > 0]
            if day_list[1].startswith("days"):
                results.append({"key": "系统运行时间", "value": day_list[0] + " 天"})       

    return results

def checking(filePath):

    data_str = ""
    with open(filePath, 'r',encoding='UTF-8') as  f:
        data_str = f.read()
    f.close

    datas = system_checking(data_str)

    if len(datas) == 0:
        datas.append({"key": "检查运行时间是否超过52周", "value": "系统运行时间小于 1 天"})

    return datas
