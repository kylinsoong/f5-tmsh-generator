#!/usr/bin/python3

import sys
import os
import subprocess
import shutil

source_file = 'config/test.xlsx'
output = '/Users/k.song/Downloads/output'
directory = '/Users/k.song/Downloads/psbc_running_config'
files = os.listdir(directory)
cusor = 1
note = "\033[91m失败\033[0m"
for file in files:
    file_path = os.path.join(directory, file)
    excel_name = file.replace("cfg.txt", "xlsx")
    excel_path = os.path.join(output, excel_name)
    shutil.copy(source_file, excel_path)
    result = subprocess.run(['/Users/k.song/src/f5-tmsh-generator/f5-tmsh-validation.py', file_path, excel_path])
    if result.returncode == 0:
        note = "\033[92m成功\033[0m"
    print("\033[94m" + str(cusor) + "\033[0m", "\033[93m基线检测\033[0m", "\033[90m" + file + "\033[0m", note)
    cusor += 1
    note = "\033[91m失败\033[0m"
