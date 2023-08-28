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
        if line.startswith("License End Date"):
            val = trip_prefix(line, "License End Date")
            results.append({"key": "设备 linense 到期时间", "value": val})

    return results

def checking(filePath):

    data_str = ""
    with open(filePath, 'r',encoding='UTF-8') as  f:
        data_str = f.read()
    f.close

    datas = system_checking(data_str)

    if len(datas) == 0:
        datas.append({"key": "检查授权时间是否到期(linense)", "value": "没有取到设备linense到期时间，离设备到期时间"})

    return datas
