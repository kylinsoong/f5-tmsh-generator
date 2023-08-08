#!/usr/bin/python3


from f5bigip import tmsh

vs = tmsh.get('tmsh', 'ltm.create.virtual')
vs = vs.replace("REPLACE_VS_NAME", "test_vs")

print(vs)

