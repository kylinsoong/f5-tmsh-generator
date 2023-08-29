#!/usr/bin/python3

import sys

def convert_to_list(line):
    raws = line.split(" ")
    val_list = [i.strip() for i in raws if len(trip_prefix(i, None)) > 0]
    return val_list

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
        val_list = convert_to_list(l)
        if val_list[5] == "/config" or val_list[5] == "/shared" or val_list[5] == "/var" or val_list[5] == "/var/log" or val_list[5] == "/appdata":
            results.append({"key": val_list[5] + " 存储空间使用率", "value": val_list[4]})

    return results

def checking(filePath):

    data_str = ""
    with open(filePath, 'r',encoding='UTF-8') as  f:
        data_str = f.read()
    f.close

    datas = system_checking(data_str)

    if len(datas) == 0:
        datas.append({"key": "检查设备存储空间使用率", "value": "没有取到利用率数值"})

    return datas
