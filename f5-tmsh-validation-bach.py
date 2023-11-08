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
for file in files:
    file_path = os.path.join(directory, file)
    excel_name = file.replace("cfg.txt", "xlsx")
    excel_path = os.path.join(output, excel_name)
    shutil.copy(source_file, excel_path)
    result = subprocess.run(['/Users/k.song/src/f5-tmsh-generator/f5-tmsh-validation.py', file_path, excel_path])
    print(cusor, file, result.returncode)
    cusor += 1
