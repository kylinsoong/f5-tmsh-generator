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

def trip_prefix(line, prefix):
    if len(line) > 0 and prefix is not None and prefix in line:
        return line.strip().lstrip(prefix).strip()
    else:
        return line.strip()


def system_checking(data_str):

    results = []

    data = find_content_from_start_end(data_str, "Chassis Fan Status", "Chassis Information")
    data = trip_prefix(data, None)
    lines = data.splitlines()
    for l in lines:
        line = trip_prefix(l, None)
        if "Chassis" not in line and "Status" not in line and len(line) > 0:
            raws = line.split(" ")
            fan_list = [i.strip() for i in raws if len(trip_prefix(i, None)) > 0]
            key = "风扇 " + fan_list[0] + " 状态"
            val = "status: " + fan_list[1] + ", Fan Speed(rpm): " + fan_list[3]
            results.append({"key": key, "value": val})

    return results



def checking(filePath):

    data_str = ""
    with open(filePath, 'r',encoding='UTF-8') as  f:
        data_str = f.read()
    f.close

    datas = system_checking(data_str)

    if len(datas) == 0:
        datas.append({"key": "检查设备风扇（正常状态）", "value": "没有取到状态"})

    return datas
