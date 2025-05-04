# if you use tool in windows download the : https://npcap.com/dist/npcap-1.82.exe 
# install and use tool for windows if you use linux not download it just run tool and enjoi
# use = network_scaner.py -r 192.168.1.1/24 

import scapy.all as scapy
import optparse 

def logo():
	logo = """
░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░        insragram : oma_rpsy
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░       Youtube   : @omarsecurity
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░       
░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░  
                                         
                                         
	"""
	print (logo)
logo()

def get_argements():
	parser = optparse.OptionParser()
	parser.add_option('-r' , '--range' , dest="network_ip" , help="Tap Your range ip")
	options , argements = parser.parse_args()
	return options 
def scan(network_ip):
	arp_request = scapy.ARP(pdst=network_ip)
	arp_prodcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_prodcast = arp_prodcast/arp_request 
	answered = scapy.srp(arp_request_prodcast, timeout=1, verbose=False)[0]
	clinet_list = []
	for ans in answered:
		clint_dict = {"ip": ans[1].psrc, "mac" :ans[1].hwsrc}
		clinet_list.append(clint_dict)
	return clinet_list 

def display_clinet(clinets):
	print ("IP Address\t     MAC Address")
	print ('-'*40)
	for clinet in  clinet_list:
		print("{:<20} {:<20}".format(clinet["ip"], clinet["mac"]))


option =  get_argements()
clinet_list = scan(option.network_ip)
display_clinet(clinet_list)
