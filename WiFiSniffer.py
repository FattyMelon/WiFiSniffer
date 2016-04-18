#-*- coding: utf-8 -*-
from scapy.all import *
import requests
import json
import datetime

PROBE_REQUEST_TYPE=0
PROBE_REQUEST_SUBTYPE=4

interface = "wlan0"

#input your server API
url = ""
#a test API address
#url = "http://httpbin.org/post"

L = []

def PacketHandler(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type==PROBE_REQUEST_TYPE and pkt.subtype==PROBE_REQUEST_SUBTYPE:
            PrintPacket(pkt)

def PrintPacket(pkt):
    deviceID = "abcdef"
    global L
    print "Probe Request Captured:"
    try:
        extra = pkt.notdecoded
    except:
        extra = None
    if extra!=None:
        signal_strength = -(256-ord(extra[-4:-3]))
    else:
        signal_strength = -100
        print "No signal strength found" 
    #time
    ts = time.time()
    st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
  
    #post
    send = {'time':st,'rssi':signal_strength,'mac':pkt.addr2,'id':deviceID}
    print send
    L.append(send)

    try:
        if len(L) >= 50:
            r = requests.post(url,data=json.dumps({'data':L}),timeout = 5)
            #clear list L
            L = []
            print 'success'
    except:    
        print "fail"
        return 0
    return 0

def main():
    print "Scanning for wireless probe requests:"
    sniff(iface=interface,prn=PacketHandler,store=0) 

if __name__=="__main__":
    main()
