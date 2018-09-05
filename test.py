from Firewall import Firewall


fw = Firewall("Rules.csv")

#given in PDF
print "Default given"
print(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2"))
print(fw.accept_packet("inbound", "udp", 53, "192.168.2.1"))
print(fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11"))
print(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"))
print(fw.accept_packet("inbound", "udp", 24, "52.12.48.92"))
print "\n"

#tests for poorly formed packets
print "Poorly formed packets:"
print(fw.accept_packet("inboun", "tcp", 11111, "192.168.1.2"))
print(fw.accept_packet("inbound", "tc", 11111, "192.168.1.2"))
print "\n"

#Checks bounds of ports
print "Bounds of ports"
print(fw.accept_packet("outbound", "tcp", 10000, "192.168.10.11"))
print(fw.accept_packet("outbound", "tcp", 20000, "192.168.10.11"))
print(fw.accept_packet("outbound", "tcp", 9999, "192.168.10.11"))
print(fw.accept_packet("outbound", "tcp", 20001, "192.168.10.11"))
print "\n"

#Checks bounds of addresses
print "Bounds of addreses"
print(fw.accept_packet("inbound", "udp", 53, "192.168.1.1"))
print(fw.accept_packet("inbound", "udp", 53, "192.168.2.5"))
print(fw.accept_packet("inbound", "udp", 53, "192.168.1.0"))
print(fw.accept_packet("inbound", "udp", 53, "192.168.2.6"))
print "\n"

#multiple ports -> addresses mappings
print "Multiple ports to addresses"
print(fw.accept_packet("inbound", "tcp", 250, "192.169.1.5"))
print(fw.accept_packet("inbound", "tcp", 750, "192.169.1.5"))
print(fw.accept_packet("inbound", "tcp", 750, "192.175.2.0"))
print "\n"


print len(fw.rules["inbound"]["udp"])
print len(fw.rules["inbound"]["tcp"])
print len(fw.rules["outbound"]["udp"])
print len(fw.rules["outbound"]["tcp"])
