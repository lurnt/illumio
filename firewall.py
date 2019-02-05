import csv
# from collections import defaultdict
import bisect
import ipaddress

class Range:
	def __init__(self, port, ip):
		port_ind = port.find('-')
		if port_ind == -1:
			self.port_lower = self.port_upper = int(port)
		else:
			self.port_lower = int(port[:port_ind])
			self.port_upper = int(port[port_ind+1:])
		ip_ind = ip.find('-')
		if ip_ind == -1:
			self.ip_lower = self.ip_upper = ipaddress.IPv4Address(ip)
		else:
			self.ip_lower = ipaddress.IPv4Address(ip[:ip_ind])
			self.ip_upper = ipaddress.IPv4Address(ip[ip_ind+1:])

	def __repr__(self):
		return 'port: %d-%d || ip: %s-%s' %(self.port_lower, self.port_upper, self.ip_lower, self.ip_upper)

	def __lt__(self, other):
		return self.port_lower < other.port_lower

	def in_range(self, port):
		return self.port_lower <= port and port <= self.port_upper

	def match(self, port, ip):
		ip_obj = ipaddress.IPv4Address(ip)
		return self.in_range(port) and self.ip_lower <= ip_obj and ip_obj <= self.ip_upper

class Firewall:
	def __init__(self, csv_path):
		# Main data structure: 
		# maps from (direction,protocol) to entry of protocol/ip ranges
		keys = [
			('inbound','tcp'), 
			('inbound','udp'), 
			('outbound','tcp'),
			('outbound','udp')
		]
		self.rule_data = {}
		for key in keys:
			self.rule_data[key]=[]
		with open(csv_path, newline='') as csv_file:
			csv_reader = csv.reader(csv_file, delimiter=',')
			for data in csv_reader: 
				self.add_rule(data)
				
	def add_rule(self, data):
		direction, protocol, port, ip = data
		new_range = Range(port, ip)
		row = self.rule_data[(direction, protocol)]
		bisect.insort(row, new_range)
		
	def debug(self):
		for key,ranges in self.rule_data.items():
			print(key)
			for item in ranges:
				print(item)

	def accept_packet(self, direction, protocol, port, ip_adr):
		rule_list = self.rule_data[(direction,protocol)]
		find_range = Range(str(port), ip_adr)
		curr = bisect.bisect_right(rule_list, find_range)-1
		while curr >= 0:
			if rule_list[curr].match(port,ip_adr):
				return True
			curr-=1
		return False

def test_given():
	fw = Firewall('data/input1.csv')
	print(fw.accept_packet("inbound","tcp",80,"192.168.1.2"))  # True
	print(fw.accept_packet("inbound","udp",53,"192.168.2.1"))  # True
	print(fw.accept_packet("outbound","tcp",10234,"192.168.10.11")) # True
	print(fw.accept_packet("inbound","tcp",81,"192.168.1.2")) # False
	print(fw.accept_packet("inbound","udp",24,"52.12.48.92")) # False
	# fw.debug()

def test_edge():
	fw = Firewall('data/input2.csv')
	print(fw.accept_packet("inbound","tcp",80,"192.168.1.3"))  
	print(fw.accept_packet('inbound','tcp',70,'192.168.1.3'))
	print(fw.accept_packet('inbound','tcp',90,'192.168.1.3'))
	print(fw.accept_packet('inbound','tcp',90,'192.168.1.4'))
	print(fw.accept_packet('inbound','tcp',60,'192.168.1.20'))
	print(fw.accept_packet('inbound','tcp',60,'192.168.1.21')) # should be false; upper limit 192.168.1.21
	print(fw.accept_packet('outbound','tcp',2,'1.1.1.1'))
	print(fw.accept_packet('outbound','tcp',24353,'231.145.12.100')) # silly number since every possible value included
	# fw.debug()

if __name__ == '__main__':
	test_given()
	test_edge()