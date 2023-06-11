tmsh create net vlan external interfaces add { 1.1 { untagged } }
tmsh create net vlan internal interfaces add { 1.2 { untagged } }
tmsh create net self 10.1.10.240 address 10.1.10.240/24 vlan external allow-service default
tmsh create net self 10.1.20.240 address 10.1.20.240/24 vlan internal allow-service default
tmsh create net route Default_Gateway network 0.0.0.0/0 gw 10.1.10.2
tmsh modify sys dns name-servers add { 10.1.10.2 }
tmsh modify sys ntp timezone Asia/Shanghai
tmsh save sys config
