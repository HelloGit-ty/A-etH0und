import scapy.all as scapy
import socket
import time
import pathlib
from bs4 import BeautifulSoup
print("Welcome to A$$etH0und, the asset tracker for any network. \nThis will help you identify devices on the host-ile network.")
#print("Enter the ip range of your network in start end format")
#ip_range = str(sys.argv[1]) #sys.argv[position of the user input in the terminal. starts from 1.] - takes input from terminal

helph = input("Type hh or h to display a HELP menu and exit. Use no to skip help!-->")
if helph == "hh" or helph == "h":
    print("--silent - to go in stealth mode\n--hostnamae - to print hostname of an asset(if internal DNS or name resolution protocol is setup\n-intf - to select a particular emission interface\n-o - specify output path for the file to save the output\n --active - perform active OS footprinting")
    exit(0)
ip_start = input("Enter the start IP -->")
ip_addrs = []
ipees = []
out_put = []
ip_end = input("Enter the End IP -->")
lazy = input("--silent? (use no if not)--> ")
hostzz = input("--hostnamae? (use no if not)--> ")
infc = input("-intf? (use no if not)--> ")
act_os = input("Perform active OS scan? (use no if not)--> ")
if infc == "-intf":
    intf = input('Enter the name of the interface you want to use (use no if default works for you)--> ')
out1 = input("Use -o for saving file? (use no if not)--> ")
if out1 == "-o":
    out = input("Enter the complete path of the output file-->")
if lazy == "--silent":
    wait_time = int(input("Enter the wait interval in sec(s)"))

def input_chk():
    str2 = ""
    i = len(ip_start) - 1
    while ip_start[i] != ".":
        str2 = ip_start[i] + str2
        i = i - 1
    final_len = len(ip_start) - (len(str2) + 1)
    str3 = ""
    i = len(ip_end) - 1
    while ip_start[i] != ".":
        str3 = ip_end[i] + str3
        i = i - 1
    final_len1 = len(ip_end) - (len(str3) + 1)
    i = 0
    str5 = ""
    while i < final_len:
        str5 = str5 + ip_start[i]
        i = i + 1
    i = 0
    str6 = ""
    while i < final_len1:
        str6 = str6 + ip_end[i]
        i = i + 1
    if str5 == str6:
        ip_range(str5)
        arping(ip_addrs)
        if hostzz == "--hostnamae":
            hostname()
        if act_os == "--active":
            active()
        if out1 == "-o":
            out_save()
    else:
        print("You may have messed up the network ID. You cannot scan for devices on different networks at the same time because ARP is a layer 2 protocol and cannot overcome layer 3 segregation!\nExiting...")
        exit(1)

def ip_range(str5):
    str1 = ""
    ip_addrs.append(ip_start)
    i = len(ip_start) - 1
    while ip_start[i] != ".":
        str1 = ip_start[i] + str1
        i = i - 1
    #print(str1)
    str4 = ""
    i = len(ip_end) - 1
    while ip_start[i] != ".":
        str4 = ip_end[i] + str4
        i = i - 1
    i = int(str1)
    while i < int(str4):
        each_ip = str5 + "." + str(int(i) + 1)
        #print(each_ip)
        ip_addrs.append(each_ip)
        i = i + 1
    #print(ip_addrs)

def arping(ip_addrs):
    tab = []
    try:
        i = 0
        while i < len(ip_addrs):
            arp_packet = scapy.ARP(pdst=ip_addrs[i])
            arp_packet.op = 1
            frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            final_frame = frame/arp_packet
            a = 0
            b = 0
            if lazy == "--silent":
                time.sleep(wait_time)
                if infc == "-intf":
                    reply = scapy.srp(final_frame, timeout=4, iface=intf)[0]  #the p at the end of the sr() func means scapy will use L2 instead of L3 to send/receive packets.
                else:
                    reply = scapy.srp(final_frame, timeout=4)[0]
                try:
                    trial = str(reply[0][1].psrc)
                    a = 1
                except:
                    b = 1
                # print(reply[0][1].show)
                # print(a, b)
                if a == 1:
                    tab.append((str(reply[0][1].psrc), str(reply[0][1].hwsrc)))
                    # print(tab)
                    i = i + 1
                elif b == 1:
                    print("There was no reply to the ARP request hence continuing to the next IP...")
                    i = i + 1
            elif lazy == "No" or lazy == "no" or lazy == "NO":
                if infc == "-intf":
                    reply = scapy.srp(final_frame, timeout=4, iface=intf)[0]
                else:
                    reply = scapy.srp(final_frame, timeout=4)[0]
                try:
                    trial = str(reply[0][1].psrc)
                    a = 1
                except:
                    b = 1
                # print(reply[0][1].show)
                #print(a, b)
                if a == 1:
                    tab.append((str(reply[0][1].psrc), str(reply[0][1].hwsrc)))
                    # print(tab)
                    i = i + 1
                elif b == 1:
                    print("There was no reply to the ARP request hence continuing to the next IP...")
                    i = i + 1
        #print(tab)
    except:
        print("There has been some error.\nExiting with status code -1")
        exit(-1)
    x = 0
    oui = open("OUI.txt", "r")
    for mac in tab:
        hw_addr = mac[1]
        mac_addr = hw_addr[0] + hw_addr[1] + hw_addr[2] + hw_addr[3] + hw_addr[4] + hw_addr[5] + hw_addr[6] + hw_addr[7]
        ipees.append(mac[0])
        #print(mac_addr)
        for lines in oui.readlines():
            #print(lines)
            parse = lines[0]+lines[1]+":"+lines[2]+lines[3]+":"+lines[4]+lines[5]
            #print(parse)
            if parse == mac_addr.upper():
                s1 = slice(7, len(lines)-1, 1) #slice(start(is ignored),stop,step)
                output_tab = "MAC-->" + hw_addr + "| IP-->" + mac[0] + "| Vendor-->" + lines[s1]
                print(output_tab)
                if out1 == "-o":
                    out_put.append(output_tab)
                x = 1
                break
            else:
                continue
        if x == 0:
            output_tab = "MAC-->" + hw_addr + "| IP-->" + mac[0] + "| Vendor--> Unknown"
            print(output_tab)
            if out1 == "-o":
                out_put.append(output_tab)
            continue
        else:
            continue
    oui.close()

def hostname():
    k = 0
    #print(ipees)
    while k < len(ipees):
        try:
            hostna_wa = socket.gethostbyaddr(ipees[k])[0]
            print("IP-->", ipees[k], " | Hostname-->", hostna_wa)
            if out1 == "-o":
                out_put.append(hostna_wa)
        except socket.herror as err:
            if err.errno == 1:
                print('IP address', ipees[k], 'has no DNS record')
            elif err.errno == 2:
                print('DNS server is temporarily unavailable. You need an internal DNS server to find hostnames of your assets which speak IP!')
                exit(-1)
            else:
                print('Unknown error')
                #exit(-1)
        k = k+1

def active():
    j = 0
    fx = open("ICMP_scan.xml", "r")
    contents = fx.read()
    soup = BeautifulSoup(contents, 'lxml')
    while j < len(ipees):
        try:
            pack = scapy.IP(dst=ipees[j]) / scapy.ICMP(id=100)  # the id has to be set because scapy by default uses a null value which some firewall blocks (see ICMP null id block on juniper fw)
            if infc == "-intf":
                resp = scapy.sr1(pack, timeout=2, iface=intf)[0]  # may use srloop to provide count for multiple echo
            else:
                resp = scapy.sr1(pack, timeout=2)[0]
            #print(resp[0])
            ttl = resp.getlayer('IP').ttl
            icmp_type = resp.getlayer('ICMP').type
            code = resp.getlayer('ICMP').code
            checksum = resp.getlayer('ICMP').chksum
            icmpid = resp.getlayer('ICMP').id
            icmpseq = resp.getlayer('ICMP').seq
            find1 = soup.find('test', {'icmptype':icmp_type, "icmpcode":code, "icmpid":icmpid, "icmpseq":icmpseq, "icmpchecksum":checksum, "icmpttl":ttl})
            if find1 is None:
                print("There are no similar/exact matches for", ipees[j], "\nOS fingerprinting unsuccessful!")
            else:
                par = find1.find_parent('fingerprint')
                pars = "OS name- "+par['os_name'] + "|" + "Vendor- "+par['os_vendor'] + "|" + "device type- "+par['device_type']
                print(pars, "\n These matches are guesses based on careful and exact correlation of data.")
                if out1 == "-o":
                    out_put.append(pars)
        except scapy.select_error as err:
            print("There has been some error--> ", err)
        j = j+1
        fx.close()

def out_save():
    p = pathlib.Path(out)
    if p.exists():
        with open(out, 'w') as f:
            f.writelines(i+"\n" for i in out_put) #using list comprehension to add newlines at the end of each string element since writelines doesn't add newlines.
    elif p.is_file():
        print("The mentioned file is not an file! Check the extensions as well!")
    else:
        print("The path", out, " doesn't exist!\nCheck the syntax of the path provided.\nFile paths are OS dependent.")

def main():
    if 8 <= len(ip_start) <= 15:
        if 8 <= len(ip_end) <= 15:
            input_chk()
        else:
            print("Enter the right IP address format!")
            exit(-1)
    else:
        print("Enter the correct ip format!")
        exit(-1)
if __name__ == "__main__":
    main()
