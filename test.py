from scapy.all import *

PORT = "50000"
TEST_NUMBER = 38

def pkt_callback(pkt):
    global TEST_NUMBER
    global PORT
    pkt.show()  # debug statement
    ls(pkt)
    #msg = raw(pkt)
    print("msg")
    if(TEST_NUMBER > len(pkt.load)):
        TEST_NUMBER -= len(pkt.load)
    print(pkt.load)
    print(pkt.load[TEST_NUMBER])
    arr = bytearray(pkt.load)
    arr[TEST_NUMBER] = pkt.load[TEST_NUMBER] ^ int('1000', 2)
    #pkt.load = bytes(arr)
    print(pkt.load[TEST_NUMBER])
    print(pkt.__dict__)
    
    send(pkt)


sniff(prn=pkt_callback, filter="udp and (port "+PORT +
      ")", store=0)
