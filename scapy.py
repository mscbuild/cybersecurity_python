from scapy.all import *

# Send a SYN packet to port 80 on a remote host
ip = IP(dst="www.example.com")
syn = TCP(dport=80, flags="S")
pkt = ip/syn
response = sr1(pkt, timeout=1)

# Print the response
if response:
    response.show()
else:
    print("No response received")
