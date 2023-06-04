
def find_last_index(str, substr):
    last_index = -1
    while True:
        index = str.find(substr, last_index + 1)
        if index == -1:
            return last_index
        last_index = index

def format_ip_addr(ip):
    list = []
    if("-" in ip) :
        ips = ip.split("-")
        list.insert(0, ips[0])
        lastdot = find_last_index(list[0], ".")
        prefix = list[0][:(lastdot + 1)]
        start = list[0][(lastdot + 1):]
        last = ips[1]
        for i in range(int(last) - int(start)):
            num = int(start) + i
            list.insert(i + 1, prefix + str(num))
    else:
        list.insert(0, ip)
    return list

def poolGenerator(name, serlist, serport):
    pool = "tmsh create ltm pool " + name + " members add {"
    for ip in serlist:
        member = " " + ip + ":" + str(serport) + " { address " + ip + " }"
        pool += member
    pool += " } monitor http"
    print(pool)

def snatGenerator(name, snatlist):
    snat = "tmsh create ltm snatpool " + name + " {"
    for ip in snatlist:
        member = " members add { " + ip + " }"
        snat += member
    snat += " }"
    print(snat)

def vsGenerator(vs_name, pool_name, snat_name, addr, port, protocol):
    vs = "tmsh create ltm virtual " + vs_name + " destination " + addr + ":" + str(port) + " pool " + pool_name + " ip-protocol " + protocol + " source-address-translation { type snat " + snat_name + " }"
    print(vs)  

def vsGeneratorSnatOnly(vs_name, snat_name, addr, port, protocol):
    vs = "tmsh create ltm virtual " + vs_name + " destination " + addr + ":" + str(port) + " ip-protocol " + protocol + " source-address-translation { type snat " + snat_name + " }"
    print(vs)

def vsGeneratorPoolOnly(vs_name, pool_name, addr, port, protocol):
    vs = "tmsh create ltm virtual " + vs_name + " destination " + addr + ":" + str(port) + " ip-protocol " + protocol + " pool " + pool_name
    print(vs)

def vsGeneratorVSOnly(vs_name, addr, port, protocol):
    vs = "tmsh create ltm virtual " + vs_name + " destination " + addr + ":" + str(port) + " ip-protocol " + protocol
    print(vs)


'''
Generate tmsh for create vs/pool/snat/profile/health/monitor via a dictionary

The dictionary should contains the following key:

  ip       - VS ip
  port     - VS port
  protocol - VS Protocol
  
The following keys are optional:

  serverlist   - The list of server ip address
  serverport   - server port
  snatpoollist - The list if snat pool ip address
'''
def generateNewVirtualServer(dict):
    prefix = "yw" + "_" + dict['ip'] + "_" + str(dict['port']) + "_"
    vs_name = prefix + "vs"
    pool_name = prefix + "pool"
    snat_name = prefix + "snat"

    isPoolCreated = False
    isSnatCreated = False

    if("serverlist" in dict and "serverport" in dict):
        poolGenerator(pool_name, dict['serverlist'], dict['serverport'])
        isPoolCreated = True

    if("snatpoollist" in dict):
        snatGenerator(snat_name, dict['snatpoollist'])
        isSnatCreated = True    

    if(isPoolCreated and isSnatCreated):
        vsGenerator(vs_name, pool_name, snat_name, dict['ip'], dict['port'], dict['protocol'])
    elif(isPoolCreated and ~isSnatCreated):
        vsGeneratorPoolOnly(vs_name, pool_name, dict['ip'], dict['port'], dict['protocol'])
    elif(~isPoolCreated and isSnatCreated):
        vsGeneratorSnatOnly(vs_name, snat_name, dict['ip'], dict['port'], dict['protocol'])
    else:
        vsGeneratorVSOnly(vs_name, dict['ip'], dict['port'], dict['protocol'])
    
