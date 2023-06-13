#!/usr/bin/python3

import subprocess

subprocess.Popen(f"ssh root@10.1.1.133 tmsh -q show running-config", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()



