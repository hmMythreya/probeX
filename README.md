# Simple CLI port scanner tool written in python that scans only 1 port on 1 host

# Installation:

git clone https://github.com/hmMythreya/probeX.git

cd probeX

pip install -r requirements.txt

# To run:

sudo python3 probeX.py

NOTE: sudo is required

# Usage:

sudo python3 probeX.py by default enters into interactive mode, follow the instructions shown on screen. 

In order to use this tool without interactive mode, you need to pass in command line arguments, check the help page

python3 probeX.py [--help | -h] prints the help page

The tool takes in 2 arguments:

  \[dest_ip]
  \[dest_port]

ex usage:

sudo python3 probeX.py 192.168.1.164 22

The Tool also comes with a source ip spoof (NOTE: THIS MIGHT BE ILLEGAL. MAKE SURE YOU HAVE PERMISSION TO DO IT IN YOUR NETWORK. I AM NOT RESPONSIBLE FOR IT's MISUSE)

the -s or --spoof flag can be used to use a spoof ip. The usage is as follows:

sudo python3 probeX.py -s \[dest_ip] \[dest_port] \[spoofed_src_ip]
