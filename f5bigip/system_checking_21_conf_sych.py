#!/usr/bin/python3

import sys

def trip_prefix(line, prefix):
    if len(line) > 0 and prefix is not None and prefix in line:
        return line.strip().lstrip(prefix).strip()
    else:
        return line.strip()

def find_line_content_from_start_str(data, prefix):
    lines = data.splitlines()
    for l in lines:
        line = l.strip()
        if line.startswith(prefix):
            return trip_prefix(line, prefix.strip())
    return None

def system_checking(data_str):

    results = []

    status = find_line_content_from_start_str(data_str, "Status")

    results.append({"key": "检查主备是否同步", "value": status})

    return results

def checking(filePath):

    data_str = ""
    with open(filePath, 'r',encoding='UTF-8') as  f:
        data_str = f.read()
    f.close

    datas = system_checking(data_str)

    if len(datas) == 0:
        datas.append({"key": "检查主备是否同步", "value": "检查主备是否同步错误"})

    return datas
