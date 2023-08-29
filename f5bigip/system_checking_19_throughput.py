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

def find_current_connections(data, prefix):
    connections = find_line_content_from_start_str(data, prefix)
    raws = connections.split(" ")
    val_list = [i.strip() for i in raws if len(trip_prefix(i, None)) > 0]
    return val_list

def system_checking(data_str):

    results = []

    data = find_content_from_start_end(data_str, "Sys::Performance Throughput", "SSL Transactions")
    in_val_list = find_current_connections(data, "In")
    out_val_list = find_current_connections(data, "Out")
    results.append({"key": "吞吐量 In", "value": "current: " + in_val_list[0] + ", avg: " + in_val_list[1] + ", max: " + in_val_list[2]})
    results.append({"key": "吞吐量 Out", "value": "current: " + out_val_list[0] + ", avg: " + out_val_list[1] + ", max: " + out_val_list[2]})

    return results

def checking(filePath):

    data_str = ""
    with open(filePath, 'r',encoding='UTF-8') as  f:
        data_str = f.read()
    f.close

    datas = system_checking(data_str)

    if len(datas) == 0:
        datas.append({"key": "检查吞吐量", "value": "检查吞吐量错误"})

    return datas
