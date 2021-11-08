# A$$etH0und

**Abstract** – With my focus on offensive security I have developed
this little tool A$$etH0und. Now this tool’s best part is that with a little tweak it can be used
easily in blue teaming (asset monitoring) but the current version of this tool is made by
keeping red teaming ops in mind. A$$etH0und is an asset tracking tool for any corporate
network that has assets which speaks IPv4 (which is pretty much any corp network). It can
be an android, IOS, laptop, PC, servers or domain controllers, it doesn’t matter. This tool can
track those assets and show you a list of all assets present in that network, their hostname,
mac addresses, vendor of an asset’s NIC(Network Interface Card), private IPs, Domain
names as well as the OS version running on them. A$$etH0und will work correctly given that
there are no MITM packet manipulating tools in the network. Since it is a command line
tool, this tool can be used remotely over SSH as well.

**Technical details** – A$$etH0und is written completely using python3 and XML. The tool has
been written to avoid any form of stack/heap based buffer overflows or the presence of
BOILs (Buffer overflow inducing loops). There are no form of Binary vulnerabilities as per my
testing. (Further testing can be done if required).

**Packages used** -> Scapy, Pathlib, Sys, BeautifulSoup(bs4), sockets and time.

Now this tool uses scapy to craft packets, to scan the network for assets using ARP in L2. It
then uses the OUI of those mac addresses and matches them with another file containing a
list of OUIs and their related vendor and then responds with the correct vendor of that
particular asset’s NIC.

If the user wants, he can opt for the hostname option to find the hostname of an asset
provided there is an internal DNS server to resolve the queries. The tools uses the IPv4
addresses and performs a reverse lookup to find the hostname of the assets(using the
socket module).

There is a stealth option to increase the gap between packet emissions/scans to not trigger
any firewalls or NMS (network monitoring systems)(using the time module).
There is also an option for selecting the network interface of user’s choice. The tool will use
that interface to emit the scan packets.

For convenience, there is an output option where the user can provide a file path and the
tool will save the output into that file after checking the validity of the path provided(using
pathlib module).

Now there is also a help menu to help the user better understand how to use the various
options.

Coming to the OS fingerprinting option finally, it uses active OS fingerprinting using ICMP
echo to guess the OS of the asset. It uses ICMP because in a corporate network pings or
ICMP type 13 packets are always allowed for network troubleshooting. Hence it will not
arouse suspicion and also TCP packets are not allowed by system firewalls in an inbound
direction and hence tcp scans won’t work. Same with UDP. Using those scans on member
servers may be a noisy scan to do hence the quietest scan to do is the ICMP in the active
fingerprinting methodology. It sends ICMP echo packets to all the assets on the host
network and then it parses and analyses the response packets and then it matches those
details with an xml file containing the packet structure of an icmp response for different
OS’s networking kernel/ IP stack.

The xml file is parsed using beautifulsoup and lxml and it can be increased externally by the
user to include more details for a better OS fingerprinting capability.

**Problems faced while in development phase – so there were 2 parts which were mainly
problematic.**

1. The tool needs sudo/root permissions to open L2/L3 sockets and work properly. In
case of windows, you may grant administrative rights while running the tool from an
admin command prompt (in case you have a filtered token).

2. The parsing of the xml file was a bit difficult due to the usage of nested tags. Also the
find_all() method of bs4 doesn’t allow reverse lookup to obtain the parent tag’s
attribute values using the child tag’s attribute values. Hence I had to use find() but
find does not return a list of all the matches found in the xml file based on the tag
name provided. It finds the first one. Hence this is a shortcoming in the tool :( .
