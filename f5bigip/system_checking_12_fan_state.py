#!/usr/bin/python3

import sys

from f5bigip import configParse as p

def system_checking(data_str):

    results = []

    data = p.find_content_from_start_end(data_str, "Chassis Fan Status", "Chassis Information")
    data = p.trip_prefix(data, None)
    lines = data.splitlines()
    for l in lines:
        line = p.trip_prefix(l, None)
        if "Chassis" not in line and "Status" not in line and len(line) > 0:
            raws = line.split(" ")
            fan_list = [i.strip() for i in raws if len(p.trip_prefix(i, None)) > 0]
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
