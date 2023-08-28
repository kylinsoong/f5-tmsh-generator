#!/usr/bin/python3

lines = []

with open("tmsh.txt", "r") as file:
    lines = file.readlines()

filtered_lines = [item.strip() for item in lines if "v9" not in item]
unique_list = list(set(filtered_lines))
print(len(unique_list))
for line in unique_list:
    print(line)
