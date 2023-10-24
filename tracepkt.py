#!/usr/bin/env python
# coding: utf-8

import sys
from socket import inet_ntop, AF_INET
from bcc import BPF
import ctypes as ct
from struct import pack

IFNAMSIZ = 16 # uapi/linux/if.h
XT_TABLE_MAXNAMELEN = 32 # uapi/linux/netfilter/x_tables.h

final_verdict = -1

# uapi/linux/netfilter.h
NF_VERDICT_NAME = [
    'DROP',
    'ACCEPT',
    'STOLEN',
    'QUEUE',
    'REPEAT',
    'STOP',
]

# uapi/linux/netfilter.h
# net/ipv4/netfilter/ip_tables.c
HOOKNAMES = [
    "PREROUTING",
    "INPUT",
    "FORWARD",
    "OUTPUT",
    "POSTROUTING",
]

ROUTE_EVT_IF = 1
ROUTE_EVT_IPTABLE = 2

class TestEvt(ct.Structure):
    _fields_ = [
        # Content flags
        ("flags",   ct.c_ulonglong),

        # Routing information
        ("ifname",  ct.c_char * IFNAMSIZ),
        ("netns",   ct.c_ulonglong),

        # Packet type (IPv4 or IPv6) and address
        ("ip_version",  ct.c_ulonglong),
        ("icmptype",    ct.c_ulonglong),
        ("icmpid",      ct.c_ulonglong),
        ("icmpseq",     ct.c_ulonglong),
        ("saddr",       ct.c_ulonglong * 2),
        ("daddr",       ct.c_ulonglong * 2),

        # Iptables trace
        ("hook",        ct.c_ulonglong),
        ("verdict",     ct.c_ulonglong),
        ("tablename",   ct.c_char * XT_TABLE_MAXNAMELEN),
    ]


def _get(l, index, default):
    '''
    Get element at index in l or return the default
    '''
    if index < len(l):
        return l[index]
    return default

def is_reachable(cpu, data, size):
    # Decode event
    event = ct.cast(data, ct.POINTER(TestEvt)).contents
    # Make sure this is an interface event
    if event.flags & ROUTE_EVT_IF != ROUTE_EVT_IF:
        return


    if event.ip_version == 4:
        saddr = inet_ntop(AF_INET, pack("=I", event.saddr[0]))
        daddr = inet_ntop(AF_INET, pack("=I", event.daddr[0]))
    else:
        return
    
    # Decoded flow var
    flow = ""

    # IP tables decode
    verdict = ""
    hook = ""
    iptables = ""
    if event.flags & ROUTE_EVT_IPTABLE == ROUTE_EVT_IPTABLE:
        verdict = _get(NF_VERDICT_NAME, event.verdict, "~UNK~")
        hook = _get(HOOKNAMES, event.hook, "~UNK~")
        iptables = " %7s.%-12s:%s" % (event.tablename.decode("UTF-8"), hook, verdict)

    # Print event
    flow_print = True
    if(f'{saddr}' == SOURCE and f'{daddr}' == TARGET and hook):
        if(hook == 'OUTPUT'):
            flow_print = False
            #flow = "%s \033[34m<-\033[0m %s" % (saddr, daddr)
        elif(hook == 'INPUT'):
            flow = "%s \033[34m->\033[0m %s" % (saddr, daddr)
            
        if(flow_print):            
            print("+---------------------------+------------------+-------------+")
            if(verdict == 'DROP'):
                print("| %7s  | %12s     | \033[31m%8s\033[0m    |" % (flow, hook, verdict))
            else:
                print("| %7s  | %12s     | \033[32m%8s\033[0m    |" % (flow, hook, verdict))
            print("+---------------------------+------------------+-------------+")

#region Main

if __name__ == "__main__":
    # Get arguments
    if len(sys.argv) == 3:
        SOURCE = sys.argv[1]
        TARGET = sys.argv[2]
    else:
        print ("Usage: %s [TARGET_IP]" % (sys.argv[0]))
        sys.exit(1)

    # Build probe and open event buffer
    b = BPF(src_file='tracepkt.c')
    b["route_evt"].open_perf_buffer(is_reachable)

    print("--------------------------------------------------------------")
    print ("|%14s             |%14s    |%10s   |" % ('FLOW', 'IPTABLES', 'VERBOSE'))

    while True:
        b.kprobe_poll()

#endregion