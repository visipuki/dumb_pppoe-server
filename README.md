# dumb pppoe server
pppoe server to listen PAP creds from wifi routers on WAN.
Python 3.11
scapy 2.6.1
MacBook Air M1

NIC harcoded in PPPOE_IFACE = "en5"
Catch creds in logs or tcpdump output.
sudo tcpdump -i en5 -n -vvv 'ether proto 0x8863 or ether proto 0x8864'
