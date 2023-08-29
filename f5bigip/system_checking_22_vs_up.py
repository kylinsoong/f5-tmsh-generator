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


def split_content_to_list_split(data_all, start_str, end_str):
    data = find_content_from_start_end(data_all, start_str, end_str)
    data_list = data.split(start_str)
    return data_list[1:]


def find_first_line(data_all):
    first_line_end = data_all.find('\n')
    if first_line_end != -1:
        return data_all[:first_line_end]
    else:
        return data_all

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

def system_checking(data_str):

    results = []

    vs_list = split_content_to_list_split(data_str, "Ltm::Virtual Server", None)
    for vs in vs_list:
        name = find_first_line(vs)
        status = find_line_content_from_start_str(vs, "Availability")
        key = trip_prefix(name, ":") + " 运行状态"
        val = trip_prefix(status, ":")
        results.append({"key": key, "value": val})


    return results

def checking(filePath):

    data_str = ""
    with open(filePath, 'r',encoding='UTF-8') as  f:
        data_str = f.read()
    f.close

    datas = system_checking(data_str)

    if len(datas) == 0:
        datas.append({"key": "检查当前所有 VS 运行状态是否为 UP", "value": "检查当前所有 VS 运行状态是否为 UP 错误"})

    return datas
