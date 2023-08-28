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
        if "BIG-IP" in line and "yes" in line:
            raws = line.split(" ")
            version_list = [i.strip() for i in raws if len(trip_prefix(i, None)) > 0]
            key = "软件版本"
            val = version_list[2]
            results.append({"key": key, "value": val})

    return results

def checking(filePath):

    data_str = ""
    with open(filePath, 'r',encoding='UTF-8') as  f:
        data_str = f.read()
    f.close

    datas = system_checking(data_str)

    if len(datas) == 0:
        datas.append({"key": "检查设备加载版本信息（下次启动版本与当前一致）", "value": "没有取到设备当前运行版本"})

    return datas
