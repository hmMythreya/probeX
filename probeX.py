#!/usr/bin/env python3

# Import all the modules required
from scapy.all import sr
from scapy.all import IP
from scapy.all import TCP
from scapy.all import ICMP
from argparse import ArgumentParser
from terminalPrinter import terminalPrinter as printc
from colorama import Fore
import sys

# Main Scan Function
def scan(dest_ip, dest_port, src_ip):
    
    # Create IP and TCP packet based on args.
    if not src_ip:
        ip_packet = IP(dst=dest_ip)
    else:
        ip_packet = IP(src=src_ip, dst=dest_ip)

    tcp_packet = TCP(sport=RandShort(), dport=dest_port, flags="S")

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
if __name__ == "__main__":
    parser = ArgumentParser(
            prog = "python3 probeX.py",
            description = "CLI tool to scan exactly 1 port at 1 host. Comes with spoofing",
            epilog = "Thanks for using probeX. check https://github.com/hmMythreya/probeX")

    if(len(sys.argv)==1):
        printc(["Please Enter", " IP", " to scan: "], [Fore.WHITE, Fore.RED, Fore.WHITE])
        ip = input()
        printc(["Please Enter", " port", " to scan: "], [Fore.WHITE, Fore.RED, Fore.WHITE])
        port = input()
        src = None

    else:
        parser.add_argument("-ip","--ip",type=str,action="store",required=True,metavar="Target IP to be scanned",nargs=1)
        parser.add_argument("-p","--port",type=str,action="store",required=True,metavar="Target port to be scanned",nargs=1)
        parser.add_argument("-s","--spoof",action="store_true")
        parser.add_argument("spoof_ip",type=str,action="store",required=False,nargs=1)
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

    printc(["Scanning Destination IP: ", str(ip), " Port: ", str(port)],[Fore.GREEN,Fore.RED,Fore.GREEN,Fore.RED])

    result = scan(ip, port, src)
        
    print()
    printc(["Port ",str(port), " at IP ",str(ip)," is ", str(result[2])],[Fore.GREEN,Fore.RED,Fore.GREEN,Fore.RED,Fore.YELLOW])
