#!/usr/bin/python3

import datetime
import pytz

# Linux date output string
#linux_date_string = "Mon Aug 28 07:22:21 PDT 2023"
#linux_date_string = "Mon Aug 28 07:22:21 CST 2023"
data = "Mon Aug 28 22:39:42 PDT 2023"

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
time_diff = current_time - sys_datetime
print(time_diff, type(time_diff))
