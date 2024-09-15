#!/usr/bin/env python3

# Import all the modules required
from scapy.all import sr
from argparse import ArgumentParser
import sys

# Main Scan Function
def scan(src_ip = None, src_port = None, dest_ip, dest_port):
    
    # Create IP and TCP packet based on args.
    if not src_ip:
        ip_packet = IP(dst=dest_ip)
    else:
        ip_packet = IP(src=src_ip, dst=dest_ip)

    if not src_port:
        tcp_packet = TCP(sport=RandShort(), dport=dest_port, flags="S")
    else:
        tcp_packet = TCP(sport=src_port, dport=dest_port, flags="S")

    answered, unanswered = sr(ip_packet / tcp_packet, timeout=1, verbose=False)

    # Check if it is filtered
    for packet in unanswered:
        return (packet.dst, packet.dport, "Filtered")

    # Check for open or Closed or Filtered
    for (send, recv) in answered:
        if(recv.haslayer(TCP)):
            flags = recv.getlayer(TCP).sprintf("%flags%")
            if(flags == "SA"):
                tcp_packet.flags = "R"
                send_rst = sr(ip_packet / tcp_packet, timeout=1, verbose=True)
                return (dest_ip, dest_port, "Open")

            elif (flags=="RA" or flags=="R"):
                return (dest_ip, dest_port, "Closed")

        elif(recv.haslayer(ICMP)):
            if(recv.getlayer(ICMP).type==3 and recv.getlayer(ICMP).code in [3,1,2,13]):
                return (dest_ip, dest_port, "Filtered")
        
        else:
            return (dest_ip, dest_port, "check")

# Main Function
def main():
    parser = ArgumentParser(
            prog = "python3 probeX.py",
            description = "CLI tool to scan exactly 1 port at 1 host. Comes with spoofing",
            epilog = "Thanks for using probeX. check https://github.com/hmMythreya/probeX")

    if(len(sys.argv)==1):
        print("")
