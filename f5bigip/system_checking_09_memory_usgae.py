#!/usr/bin/python3

import sys
import re

def find_content_from_start_end(data, start_str, end_str):

    if start_str not in data:
        return ""

    data_start = re.search(start_str, data, re.I).start()
    if end_str is None:
        return data[data_start:]
    data_end = re.search(end_str, data, re.I).start()
    return data[data_start:data_end]

def find_line_content_from_start_str(data, prefix):
    lines = data.splitlines()
    for l in lines:
        line = l.strip()
        if line.startswith(prefix):
            return trip_prefix(line, prefix.strip())
    return None

def trip_prefix(line, prefix):
    if len(line) > 0 and prefix is not None and prefix in line:
        return line.strip().lstrip(prefix).strip()
    else:
        return line.strip()

def find_str_item(line, cur):
    raws = line.split(" ")
    val_list = [i.strip() for i in raws if len(trip_prefix(i, None)) > 0]
    return val_list[cur]

def system_checking(data_str):

    results = []

    data = find_content_from_start_end(data_str, "Sys::System Memory Information", "Sys::Host Memory")
    val1_raw = find_line_content_from_start_str(data, "TMM Memory Used")
    val2_raw = find_line_content_from_start_str(data, "Other Memory Used")
    val1 = find_str_item(val1_raw, 0) + "%"
    val2 = find_str_item(val2_raw, 0) + "%"
    
    results.append({"key": "数据平面内存利用", "value": val1})
    results.append({"key": "管理平面内存利用", "value": val2})

    return results


def checking(filePath):

    data_str = ""
    with open(filePath, 'r',encoding='UTF-8') as  f:
        data_str = f.read()
    f.close

    datas = system_checking(data_str)

    if len(datas) == 0:
        datas.append({"key": "检查内存利用率", "value": "没有取到利用率数值"})

    return datas
