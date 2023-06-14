tmsh create ltm pool ydbg_10.1.10.11_80_pool members add {10.1.20.11:8081 10.1.20.12:8081 10.1.20.23:8081} monitor http
tmsh create ltm snatpool ydbg_10.1.10.11_snat members add {10.1.10.101 10.1.10.102}
tmsh create ltm virtual ydbg_10.1.10.11_80_vs destination 10.1.10.11:80 pool ydbg_10.1.10.11_80_pool ip-protocol tcp profiles add { http { } } source-address-translation { type snat pool ydbg_10.1.10.11_snat }

tmsh create ltm pool sjyh_10.1.10.12_80_pool members add {10.1.20.13:8081 10.1.20.14:8081 10.1.20.15:8081} monitor http
tmsh create ltm virtual sjyh_10.1.10.12_80_vs destination 10.1.10.12:80 pool sjyh_10.1.10.12_80_pool ip-protocol tcp profiles add { http { } } 

tmsh create ltm snatpool qywx_10.1.10.13_snat members add {10.1.10.104 10.1.10.105}
tmsh create ltm virtual qywx_10.1.10.13_80_vs destination 10.1.10.13:80 ip-protocol tcp profiles add { http { } } source-address-translation { type snat pool qywx_10.1.10.13_snat }

tmsh create ltm virtual qywy_10.1.10.14_80_vs destination 10.1.10.14:80 ip-protocol tcp profiles add { http { } }

