#!/usr/bin/python3

import sys
import datetime

def trip_prefix(line, prefix):
    if len(line) > 0 and prefix is not None and prefix in line:
        return line.strip().lstrip(prefix).strip()
    else:
        return line.strip()

def replace_with_patterns(data, patterns):
    for pattern in patterns:
        data = data.replace(pattern, "")
    return trip_prefix(data, None)

def system_checking(data_str):

    results = []

    data = replace_with_patterns(data_str, ["Sys::Clock", "-"])
    date_format = "%a %b %d %H:%M:%S %Z %Y"
    date_format_without_tz = '%a %b %d %H:%M:%S'
    
    sys_datetime = None
    try:
        sys_datetime = datetime.datetime.strptime(data, date_format)
    except ValueError:
        sys_datetime = datetime.datetime.strptime(data[:-9], date_format_without_tz)

    year_str = data[-4:]
    sys_datetime = sys_datetime.replace(year=int(year_str))
    current_time = datetime.datetime.now()
    val_delta = current_time - sys_datetime
    val_hours = val_delta.days * 24 + val_delta.seconds // 3600
    val = str(val_hours) + " 小时"
    results.append({"key": "当前时间与服务器时间差值", "value": val})

    return results

def checking(filePath):

    data_str = ""
    with open(filePath, 'r',encoding='UTF-8') as  f:
        data_str = f.read()
    f.close

    datas = system_checking(data_str)

    if len(datas) == 0:
        datas.append({"key": "检查系统时间与当前是否一致", "value": "没有取到设备当前时间与服务器时间差值"})

    return datas
