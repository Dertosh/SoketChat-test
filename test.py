
from scapy.all import *

PORT = 50000
IN_PORT = 60000 
TEST_NUMBER = 39
IFACE = ''
list_ids = [] # id пакетов для игнора

def pkt_callback(pkt):
    global TEST_NUMBER
    global PORT
    pkt.show()  # debug statement
    print("msg")
    #print(pkt)
    if(not ("Raw" in pkt) or len(pkt.load) < 1):
        return
    if(TEST_NUMBER >= len(pkt.load)):
        TEST_NUMBER -= len(pkt.load)

    print(pkt.load)
    print(pkt.load[TEST_NUMBER])
    
    send_port = 0
    if(pkt[UDP].dport == PORT):
        send_port = 60000
    else:
        send_port = PORT
    
    iterator = 18
    pkt_list = []
    print("moding start")
    while(iterator<len(pkt.load)):

        arr = bytearray(pkt.load)
        arr[iterator] = pkt.load[iterator] ^ int('1010', 2)
        #print(arr[TEST_NUMBER])

        out_packet = IP(src=pkt[IP].src, dst=pkt[IP].dst, flags=pkt[IP].flags, ttl=pkt[IP].ttl, id=pkt[IP].id)/UDP(dport=send_port, sport=send_port)/bytes(arr)
        list_ids.append(pkt[IP].id)
        pkt_list.append(out_packet)
        iterator+=1
    #print("\nout_packet")
    #out_packet.show2()
    print("test = ", send(pkt_list, return_packets=True))

    
    #send(pkt)

device = [x[4] for x in scapy.all.conf.route.routes if x[2] != '0.0.0.0']
print(device)
local_ip = device[0]
print(local_ip)
conf.checkIPaddr = False
#print(IFACES)
''' if (len(IFACE)<1 ):
    if(conf.iface is None or len(conf.iface)< 1):
        for x in get_windows_if_list():
            if(len(x.get('mac')) > 0 ):
                print(x)
                IFACE = conf.iface = IFACES.dev_from_index(x.get('win_index'))
                break
    #if(conf.iface is None or len(conf.iface) < 1):
    
        for x in get_if_list():
            print(x)
            if(len(x.get('mac')) > 0 ):
                IFACE = conf.iface = x.get('name')
                break
    if (len(IFACE) < 1 ):
        print("Невозможно найти интерфейс! Укажите название интерфейса в настройках.")  '''

#print(IFACE)

print("Прехват стартовал")
#sendp(Ether(dst='targetMAC')/ARP(op='is-at',
#                                 psrc='gatewayIP', pdst='targetIP', hwsrc='attackerMAC'))

#параметры отлова пакетов
def build_lfilter(r): return ((UDP in r) and (
    r[UDP].sport in [IN_PORT, PORT]) and (r[IP].dst == "192.168.1.255") and (not (r[IP].id in list_ids)))

sniff(prn=pkt_callback, lfilter=build_lfilter, store=0)

