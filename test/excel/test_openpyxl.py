#!/usr/bin/python3

import sys
import openpyxl

if not sys.argv[1:]:
    print("Usage: test.py [file]")
    sys.exit()

xlsx_name = sys.argv[1]

wb = openpyxl.load_workbook(xlsx_name)
ws1 = wb.worksheets[0]
ws2 = wb.worksheets[1]
ws3 = wb.worksheets[2]

#print(xlsx_name, wb, ws1, ws2, ws3)

#for i in range(2, 36):
#    #print(ws1['A' + str(i)].value, ws1['B' + str(i)].value, ws1['C' + str(i)].value)
#    if isinstance(ws1['B' + str(i)], openpyxl.cell.cell.MergedCell):
#        print("----")
#    print(i, type(ws1['B' + str(i)]))

ws1['B2'] = "test.com"
ws1['B29'] = "test.com"
ws1['B30'] = "test.com"
#ws1['B31'] = "test.com"
#ws1['B32'] = "test.com"

for i in range(2, 36):
    if isinstance(ws1['B' + str(i)], openpyxl.cell.cell.MergedCell) or isinstance(ws1['C' + str(i)], openpyxl.cell.cell.MergedCell) or isinstance(ws1['K' + str(i)], openpyxl.cell.cell.MergedCell):
        continue
    ws1['B' + str(i)] = "test.com"
    ws1['C' + str(i)] = "1.1.1.1"
    ws1['K' + str(i)] = "是"

wb.save(xlsx_name)

ws2_start_id, ws3_start_id = 3, 3
for i in range(3, 40):
    if ws2['B' + str(i)].value is None and ws2['C' + str(i)].value is None:
        ws2_start_id = i 
        break

for i in range(3, 40):
    if ws3['B' + str(i)].value is None and ws3['C' + str(i)].value is None:
        ws3_start_id = i
        break

print(ws2_start_id, ws3_start_id)

"""
for i in range(3, 10):
    ws2['A' + str(i)] = str(i)
    ws2['B' + str(i)] = "test.com"
    ws2['C' + str(i)] = "1.1.1.1"
    ws2['E' + str(i)] = "tmsh create"
    ws2['F' + str(i)] = "tmsh delete"
    ws2['J' + str(i)] = "HAHA"

wb.save(xlsx_name)

for i in range(3, 10):
    ws3['A' + str(i)] = str(i)
    ws3['B' + str(i)] = "test.com"
    ws3['C' + str(i)] = "1.1.1.1"    

wb.save(xlsx_name)
"""

#wb.save(xlsx_name)
