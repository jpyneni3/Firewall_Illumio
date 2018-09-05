import csv
import ipaddress


class Firewall(object):#Firewall class that will learn certain rules and then implement a method to determine whether or not a packet is accepted
    def __init__(self, rules_csv):
        self.fw_rules = rules_csv
        self.rules = {} #dictionary with all the rules, maybe use dataframe?
        # self.rules_inbound_tcp = {}
        # self.rules_inbound_udp = {}
        # self.rules_outbound_tcp = {}
        # self.rules_outbound_udp = {}
        # I was going to have four different dictionaries^^, one per direction_protocol but decided agaisnt it as that would mean an extra step in the accept_packet() function
        # to decide which dictionary to use. instead, I used one nested dictionary
        self.rules["inbound"] = {}
        self.rules["outbound"] = {}
        self.rules["inbound"]["tcp"] = {}
        self.rules["inbound"]["udp"] = {}
        self.rules["outbound"]["tcp"] = {}
        self.rules["outbound"]["udp"] = {}
        with open(rules_csv, 'r') as rules:
            for rule in rules:
                if rule[-1] == "\n": #if theres a newline character at the end, take it off
                    rule = rule[:-1]
                direction, protocol, port, ip_address = rule.split(',') #split on comma to unpack the rule
                port_ranges = port.split('-')
                address_ranges = ip_address.split('-')

                if len(port_ranges) > 1 and len(address_ranges) > 1 : #ranges given for port and ranges given for addresses
                    port_ranges = range(int(port_ranges[0]), int(port_ranges[1])+1) #list of all ports in that range
                    beginning = ipaddress.ip_address(unicode(address_ranges[0]))
                    ending = ipaddress.ip_address(unicode(address_ranges[1]))
                    address_ranges = range(beginning, ending+1) #list of all addresses in the given range
                    for port in port_ranges: #per port
                        for address in address_ranges:
                            if port in self.rules[direction][protocol]:
                                a = ipaddress.ip_address(address)
                                self.rules[direction][protocol][port].add(a)
                            else:
                                a = ipaddress.ip_address(address)
                                self.rules[direction][protocol][port] = set([a])
                    #handle
                if len(port_ranges) > 1: #multiple ports, one address
                    port_ranges = range(int(port_ranges[0]), int(port_ranges[1])+1) #list of all ports in that range
                    for port in port_ranges:
                        if port in self.rules[direction][protocol]:
                            self.rules[direction][protocol][port].add(ipaddress.ip_address(address_ranges[0]))
                        else:
                            self.rules[direction][protocol][port] = set([ipaddress.ip_address(unicode(address_ranges[0]))])
                elif len(address_ranges) > 1: #one port, mupltiple adresses
                    beginning = ipaddress.ip_address(unicode(address_ranges[0]))
                    ending = ipaddress.ip_address(unicode(address_ranges[1]))
                    address_ranges = range(beginning, ending+1)
                    for address in address_ranges:
                        if int(port_ranges[0]) in self.rules[direction][protocol]:
                            a = ipaddress.ip_address(address)
                            self.rules[direction][protocol][int(port_ranges[0])].add(a)
                        else:
                            a = ipaddress.ip_address(address)
                            self.rules[direction][protocol][int(port_ranges[0])] = set([a])

                else: #one port, one address
                    if int(port_ranges[0]) in self.rules[direction][protocol]:
                        self.rules[direction][protocol][int(port_ranges[0])].add(ipaddress.ip_address(unicode(address_ranges[0])))
                    else:
                        a = ipaddress.ip_address(unicode(address_ranges[0]))
                        self.rules[direction][protocol][int(port_ranges[0])] = set([a])


    def accept_packet(self, direction, protocol, port, ip_address):
        if direction not in self.rules:
            return False
        elif protocol not in self.rules[direction]:
            return False

        ports = self.rules[direction][protocol]
        address_check = ipaddress.ip_address(unicode(ip_address))
        if port in ports and address_check in self.rules[direction][protocol][port]:
            return True
        else:
            return False
