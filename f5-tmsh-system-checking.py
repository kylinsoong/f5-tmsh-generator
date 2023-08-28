#!/usr/bin/python3

import sys

from f5bigip import system_checking_01_device_model as checking01
from f5bigip import system_checking_02_device_serial as checking02
from f5bigip import system_checking_03_sys_runtime as checking03
from f5bigip import system_checking_04_sys_software_version as checking04
from f5bigip import system_checking_06_sys_time_current_time_diff as checking06
from f5bigip import system_checking_07_sys_license_expire as checking07
from f5bigip import system_checking_08_cpu_usage as checking08
from f5bigip import system_checking_09_memory_usgae as checking09
from f5bigip import system_checking_11_cpu_temparature as checking11
from f5bigip import system_checking_12_fan_state as checking12
from f5bigip import system_checking_13_power_state as checking13
from f5bigip import system_checking_14_storage_usage as checking14
from f5bigip import system_checking_15_net_interface_state as checking15
from f5bigip import system_checking_16_ha_state as checking16
from f5bigip import system_checking_17_concurrent_connection as checking17
from f5bigip import system_checking_18_new_connection as checking18
from f5bigip import system_checking_19_throughput as checking19
from f5bigip import system_checking_20_failsafe as checking20
from f5bigip import system_checking_21_conf_sych as checking21
from f5bigip import system_checking_22_vs_up as checking22
from f5bigip import system_checking_23_interface_tafffic as checking23

results = []

results.extend(checking01.checking("config/sys-hardware"))
results.extend(checking02.checking("config/sys-hardware"))
results.extend(checking03.checking("config/sys-hardware"))
results.extend(checking04.checking("config/sys-hardware"))
results.extend(checking06.checking("config/sys-hardware"))
results.extend(checking07.checking("config/sys-hardware"))
results.extend(checking08.checking("config/sys-hardware"))
results.extend(checking09.checking("config/sys-hardware"))
results.extend(checking11.checking("config/sys-hardware"))
results.extend(checking12.checking("config/sys-hardware"))
results.extend(checking13.checking("config/sys-hardware"))
results.extend(checking14.checking("config/sys-hardware"))
results.extend(checking15.checking("config/sys-hardware"))
results.extend(checking16.checking("config/sys-hardware"))
results.extend(checking17.checking("config/sys-hardware"))
results.extend(checking18.checking("config/sys-hardware"))
results.extend(checking19.checking("config/sys-hardware"))
results.extend(checking20.checking("config/sys-hardware"))
results.extend(checking21.checking("config/sys-hardware"))
results.extend(checking22.checking("config/sys-hardware"))
results.extend(checking23.checking("config/sys-hardware"))

for i in results:
    print(i)


