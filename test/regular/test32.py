# -*- coding: UTF-8 -*-
import re, sys, json


def data_check():
    # filePath = sys.argv[1]
    # 传入文件路径
    filePath = r'test'

    # 读文件存储
    with open(filePath, 'r',encoding='UTF-8') as  f:
        data_str = f.read()

    # 定义结果返回列表
    datas = []

    # 使用正则查看网络设备板卡信息
    temp = re.findall(r'(\d+)\s+\d+\s+(\S+)\s+\d+', data_str, re.I)

    # 判断正则读取内容是否存在
    if temp:

        # 对读取的板卡信息做提取处置
        for device_name, device_state in temp:
            # 对读取的板卡信息存储到列表中的字典中
            datas.append({"value": device_state, "key": "网络设备板卡"+device_name+"状态检查"})


    # 判断列表中是否有值，有值则直接打印输出

    if datas != []:
        # datas = json.dumps(datas, encoding='utf-8', ensure_ascii=False)
        print(datas)
    # 判断列表中是否有值，没有值则输出没检查到设备相关状态
    else:
        datas.append({"value": "未检查到设备板卡信息", "key": "网络设备板卡状态检查"})
     # datas = json.dumps(datas, encoding='utf-8', ensure_ascii=False)
        print(datas)
    return datas


data_check()
# -*- coding: UTF-8 -*-
# import re, sys, json
#
#
# def data_check():
#     # filePath = sys.argv[1]
#     # 传入文件路径
#     filePath = r'test'
#
#     # 读文件存储
#     with open(filePath, 'r',encoding='UTF-8') as  f:
#         data_str = f.read()
#
#     # 定义结果返回列表
#     result = ''
#
#     # 定义匹配型号号码的正则表达式
#     # pattern = r'Version \d+\.\d+ \((.*?)\)'
#     pattern = r'Version [\d.]+ \((.*?) '
#     match = re.search(pattern, data_str)
#     datas = []
#     # 判断正则读取内容是否存在
#     if match:
#         version = match.group(1)
#         result = version
#         print(version)
#         datas.append({"value": result, "key": "网络设备型号检查" })
#     else:
#         datas.append({"value": "未检查到设备板卡信息", "key": "网络设备板卡状态检查"})
#     return result
#
#
# data_check()
