#!/usr/bin/env python3

# Import all the modules required
from scapy.all import sr
from scapy.all import IP
from scapy.all import TCP
from scapy.all import ICMP
from scapy.all import RandShort
from argparse import ArgumentParser
from terminalPrinter import terminalPrinter as printc
from colorama import Fore
import sys
import time

# Main Scan Function
def scan(dest_ip, dest_port, src_ip):
    
    # Create IP and TCP packet based on args.
    if not src_ip:
        ip_packet = IP(dst=dest_ip)
    else:
        ip_packet = IP(src=src_ip, dst=dest_ip)

    s_port = RandShort()
    tcp_packet = TCP(sport=s_port, dport=dest_port, flags="S")

    answered, unanswered = sr(ip_packet / tcp_packet, timeout=1, verbose=0)

    # Check if it is filtered
    for packet in unanswered:
        return (packet.dst, packet.dport, "Filtered")

    # Check for open or Closed or Filtered
    for (send, recv) in answered:
        if(recv.haslayer(TCP)):
            flags = recv.getlayer(TCP).sprintf("%flags%")
            if(flags == "SA"):
                tcp_packet.flags = "R"
                send_rst = sr(ip_packet / tcp_packet, timeout=1, verbose=False)
                return (dest_ip, dest_port, "Open")

            elif (flags=="RA" or flags=="R"):
                return (dest_ip, dest_port, "Closed")

        elif(recv.haslayer(ICMP)):
            if(recv.getlayer(ICMP).type==3 and recv.getlayer(ICMP).code in [3,1,2,13]):
                return (dest_ip, dest_port, "Filtered")
        
        else:
            return (dest_ip, dest_port, "check")

# Main Function
if __name__ == "__main__":
    printc(["#","-"*52,"#\n"],[Fore.BLUE,Fore.BLUE,Fore.BLUE])
    printc(["#"," "*5,"Welcome to Mythreya's Port Scanner: probeX"," "*5,"#\n"],[Fore.BLUE,Fore.WHITE,Fore.YELLOW,Fore.WHITE,Fore.BLUE])
    printc(["#","-"*52,"#\n"],[Fore.BLUE,Fore.BLUE,Fore.BLUE])
    
    parser = ArgumentParser(
            prog = "python3 probeX.py",
            description = "CLI tool to scan exactly 1 port at 1 host. Comes with spoofing",
            epilog = "Thanks for using probeX. check https://github.com/hmMythreya/probeX")

    if(len(sys.argv)==1):
        printc(["Please Enter", " IP", " to scan: "], [Fore.WHITE, Fore.GREEN, Fore.WHITE])
        ip = input()
        printc(["Please Enter", " port", " to scan: "], [Fore.WHITE, Fore.GREEN, Fore.WHITE])
        port = int(input())
        src = None

    else:
        parser.add_argument("-ip","--ip",type=str,action="store",required=True,metavar="Target IP to be scanned",nargs=1)
        parser.add_argument("-p","--port",type=int,action="store",required=True,metavar="Target port to be scanned",nargs=1)
        parser.add_argument("-s","--spoof",action="store_true")
        parser.add_argument("spoof_ip",type=str,action="store",nargs=1)
        args = parser.parse_args()

        if(args.spoof):
            if not args.spoof_ip:
                printc("No source IP entered. Exiting...")
                exit()

            printc("\nWARNING: SPOOFING SOURCE IP MAYBE ILLEGAL AND THE AUTHOR OF THIS TOOL IS NOT RESPONSIBLE FOR IT'S MISUSE. MAKE SURE YOU KNOW WHAT YOU ARE DOING",Fore.RED)
            printc("\n\nAre you sure you want to continue (type iamsure): ",Fore.WHITE)
            cont = input()
            if cont != "iamsure":
                exit()
        
        ip = args.ip
        port = args.port
        src = args.spoof_ip

    printc(["Scanning Destination IP: ", str(ip), " Port: ", str(port)],[Fore.WHITE,Fore.GREEN,Fore.WHITE,Fore.GREEN])
    print()
    start = time.process_time()
    result = scan(ip, port, src)
    end = time.process_time()

    printc(["Port ",str(port), " at IP ",str(ip)," is ", result[2]],[Fore.WHITE,Fore.GREEN,Fore.WHITE,Fore.GREEN,Fore.WHITE,Fore.YELLOW])
    printc(["\nTotal time taken: ",str(round(end-start,3)),"s"],[Fore.WHITE,Fore.YELLOW,Fore.YELLOW])
    print()
