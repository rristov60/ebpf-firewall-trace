#!/usr/bin/env python
# coding: utf-8

import sys
from socket import inet_ntop, AF_INET
from bcc import BPF
import ctypes as ct
from struct import pack
import subprocess
import threading
import time
import ipaddress

IFNAMSIZ = 16 # uapi/linux/if.h
XT_TABLE_MAXNAMELEN = 32 # uapi/linux/netfilter/x_tables.h

# Global variable which holds the final verdict
final_verdict = None

# Stop threads flag
stop_flag = threading.Event()

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

#region Ebpf
def _get(l, index, default):
    '''
    Get element at index in l or return the default
    '''
    if index < len(l):
        return l[index]
    return default

# Global vars used to measure performance
start_time = None
end_time = None

# Function that checks wether destination is reachable or not from the source
def is_reachable(cpu, data, size):
    # Decode event
    event = ct.cast(data, ct.POINTER(TestEvt)).contents
    # Make sure this is an interface event
    if event.flags & ROUTE_EVT_IF != ROUTE_EVT_IF:
        return
    
    # IP check and parsing
    if event.ip_version == 4:
        saddr = inet_ntop(AF_INET, pack("=I", event.saddr[0]))
        daddr = inet_ntop(AF_INET, pack("=I", event.daddr[0]))
    else:
        return
    
    # IP tables decode
    verdict = ""
    hook = ""
    if event.flags & ROUTE_EVT_IPTABLE == ROUTE_EVT_IPTABLE:
        verdict = _get(NF_VERDICT_NAME, event.verdict, "~UNK~")
        hook = _get(HOOKNAMES, event.hook, "~UNK~")

    # Update global var final_verdict
    if(f'{saddr}' == BPF_SOURCE and f'{daddr}' == BPF_TARGET and hook):
        if(hook == 'INPUT'):
            global final_verdict
            if(verdict == 'DROP'):
                final_verdict = False
            else:
                final_verdict = True
#endregion

#region Checks

# Check if given IP is valid IPv4 address or not
def is_valid_ipv4(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False
    
# Curl packages source -> destination
def curl_pkt_gen(source, destination):
    while not stop_flag.is_set():
        # Build curl test command
        command = ["curl", "--interface", source, destination, "-m", "1"]
        # Run the command running subproccess
        subprocess.run(command, capture_output=True, text=True)
        # Sleep for 1 second
        time.sleep(1)

# Initial test to make sure every interface is reachable
def initial_test(source, destination):
    # Build the check curl command
    command = ["curl", "--interface", source, destination, "-m", "1"]
    
    # Run curl as subprocess
    init_curl_result = subprocess.run(command, capture_output=True, text=True)
    if init_curl_result.returncode != 0 and init_curl_result.returncode != 28:
        print(f"\033[31m[ERROR]\033[0m Failed interface bind!")
        sys.exit(1)
#endregion

#region Main
if __name__ == "__main__":
    # Get arguments
    if len(sys.argv) == 3:
        SOURCE = sys.argv[1]
        TARGET = sys.argv[2]
    else:
        print ("Usage: %s [SOURCE_IP] [TARGET_IP<:PORT>]" % (sys.argv[0]))
        sys.exit(1)
    
    # Check if the source is IP only
    if ":" in SOURCE:
        print ("Usage: %s [SOURCE_IP] [TARGET_IP<:PORT>]" % (sys.argv[0]))
        sys.exit(1)

    # BPF_SOURCE used in the eBPF program
    BPF_SOURCE = SOURCE
    
    # Check if the string contains a colon
    if ":" in TARGET:
        # If it does, extract the IP address before the colon
        BPF_TARGET = TARGET.split(":")[0]
    else:
        BPF_TARGET = TARGET
        
    
    # BPF_SOURCE IPv4 validity check
    if not is_valid_ipv4(BPF_SOURCE):
        print(f"\033[31m[ERROR]\033[0m Source IP {BPF_SOURCE} is not valid IPv4 address")
        sys.exit(1)
    
    # BPF_TARGET IPv4 validity check    
    if not is_valid_ipv4(BPF_TARGET):
        print(f"\033[31m[ERROR]\033[0m Target IP {BPF_TARGET} is not valid IPv4 address")
        sys.exit(1)

    # Performing initial startup test
    print(f"\033[34m[INFO]\033[0m Doing startup checks")
    initial_test(SOURCE, TARGET)

    print(f"\033[34m[INFO]\033[0m Please wait, testing firewall policy {SOURCE} -> {TARGET}")

    
    # Create thread for the curl package generator
    curl_thread = threading.Thread(target=curl_pkt_gen, args=(SOURCE, TARGET))
    
    try:
        curl_thread.start()
    except Exception:
        print(f"\033[31m[ERROR]\033[0m An error occured!")
        sys.exit(1)    
        
    # Start time of decision making
    start_time = time.time()
    
    # Build probe and open event buffer
    b = BPF(src_file='tracepkt.c')
    b["route_evt"].open_perf_buffer(is_reachable)

    # eBPF policy test and probe poll
    # until the packages are processed
    while final_verdict == None:
        b.kprobe_poll()
    
    # End time of decision making
    end_time = time.time()

    # Stop the curl_pkt_gen thread    
    stop_flag.set()
    curl_thread.join()
    
    # Calculate the execution time in microseconds
    execution_time = (end_time - start_time) * 1e6
    
    # Print final results
    print("----------------------------------------- RESULT -----------------------------------------")
    if final_verdict is False:
        print(f"\033[34m[INFO]\033[0m Destination {TARGET} from {SOURCE} is \033[31mUNREACHABLE\033[0m")
    elif final_verdict is True:
        print(f"\033[34m[INFO]\033[0m Destination {TARGET} from {SOURCE} is \033[32mREACHABLE\033[0m")
    else:
        print(f"\033[31m[ERROR]\033[0m Unknown error occured!")
    print("-------------------------------------- EXECUTION TIME --------------------------------------")
    print(f"\033[34m[INFO]\033[0m Finished in: {round(execution_time, 4)} µs")
    

#endregion