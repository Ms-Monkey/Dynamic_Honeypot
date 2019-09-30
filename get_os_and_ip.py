import os
import re
import sys
import json
import click
import pprint
import random
import datetime
import ipaddress
import subprocess
import xml.etree.ElementTree as etree
from beautifultable import BeautifulTable

HONEYPOT_DICTS = {}

#TODO: Output the config dict as a json file or something

@click.command()
@click.option("--nmap_file", default=None, help="An xml file created by an nmap scan of the destination network")
@click.option("--subnet", required=True, help="The subnet range the honeypots will be deployed in")
@click.option("--quick_scan", default=False, help="Decide nmap timeout, true means 10s timeout, false is 2m")
def main(subnet, nmap_file=None, quick_scan=False):
    global HONEYPOT_DICTS
    HONEYPOT_DICTS = {}

    if not nmap_file:
        xml = scan_network(subnet, quick_scan)
    else:
        xml = etree.parse(nmap_file)
    root = xml.getroot()
    hosts_list, ip_list = parse_xml(root)

    network = ipaddress.IPv4Network(unicode("192.168.1.0/24", 'utf-8'))

    free_ips = get_free_ipv4_addresses(ip_list, network)

    # Prints out network stats
    print_network(hosts_list, free_ips)

    #print available_ips and config types to json file
    json_dict = {'configs': HONEYPOT_DICTS, 'ips': free_ips}
    with open('/etc/honeypot/honeypot_configs.json', 'w') as json_file:
        json.dump(json_dict, json_file)


# When OS is found, try to match it. If no match add all details
# if match, add any unadded ports
def parse_os(root):
    global HONEYPOT_DICTS
    ports = {}
    os = ""

    if root == None:
        return

    for x in root:
        if x.tag == 'portused':
            ports[x.get('portid')] = x.get('proto')
        elif x.tag == 'osmatch':
            os = x.get('name')

    if not os:
        os = 'Unknown'

    if os in HONEYPOT_DICTS:
        for port in ports:
            if port not in HONEYPOT_DICTS[os]:
                HONEYPOT_DICTS[os][port] = ports[port]

    else:
        HONEYPOT_DICTS[os] = ports


#TODO: Use a library or something to call nmap
def scan_network(subnet, quick_scan):
    hour_minute = datetime.datetime.now().strftime("%H%M_%d%m%y")
    filepath = ("/tmp/%s_nmap" % hour_minute)

    if quick_scan:
        os.system("nmap 192.168.1.1/24 -O -oX %s host-timeout 5m" % filepath)
    else:
        os.system("nmap 192.168.1.0/30 -O osscan-guess -oX %s host-timeout 10s" % filepath)

    return etree.parse(filepath)


def get_free_ipv4_addresses(ip_list, network):
    # This finds all the free IP addresses in a given network
    free_ips = []

    for addr in network:
        if addr not in ip_list:
            free_ips.append(str(addr))

    return free_ips


def calculate_honeypots(hosts_list, free_ips, network, filepath):
    config_file = open("/home/monkey/Desktop/honeyd_conf.conf", "w")
    config_file.write(DEFAULT)

    count = 1
    hosts = len(hosts_list)
    os_dist = []

    # Determines OS distribution of honeypots
    for x in hosts_list:
        if x["os"] is not "unknown":
            os_dist.append(x["os"])

    # Create OS distro for hosts with unknown OS
    for y in range(hosts - len(os_dist)):
        # Pick existing OS, add it to os_dist
        random_os = random.randint(0, len(os_dist)-1)
        os_dist.append(os_dist[random_os])

    # If less than half hosts, creates honeypots to match current hosts
    if hosts < (254 - hosts):
        for x in range(hosts):
            address = create_address(free_ips, network)
            os = os_dist[x]
            #print("Creating honeypot at address %s with OS %s" % (address, os))
            create_honeypot(address, network, os, filepath, config_file, hosts_list, count)
            count = count+1


def create_address(free_ips, network):
    # This create a random address, trying to add one in the
    # lowest range with no collisions with existing ones
    address = None

    while address not in free_ips:
        if len(free_ips) < 10:
            rng_ip = random.randint(0, len(free_ips))
        else:
            rng_ip = random.randint(0, 10)
        address = free_ips[rng_ip]

    free_ips.remove(address)
    return address


def parse_xml(root):
    hosts_list = []
    host_dict = {}
    ip_list = []
    os_type = ""
    host_counter = 0
    regex_linux = ".*(linux).*:(\d{1,2})(.?\d?).*"

    for host in root:
        port_list = []
        # This just gets the host info, which holds OS and IP address
        if host.tag == "host":
            host_dict["host_number"] = host_counter

            for y in host:
                if y.tag == "address":
                    address_type = y.get("addrtype")
                    address = y.get("addr")

                    if address_type == "mac":
                        mac_address = address
                        host_dict["mac_address"] = address

                    elif address_type == "ipv4":
                        ip = ipaddress.ip_address(unicode(address,"utf-8"))
                        host_dict["ipv4_address"] = address
                        ip_list.append(ip)

                    elif address_type == "ipv6":
                        ip = ipaddress.ip_address(unicode(address,"utf-8"))
                        host_dict["ipv6_address"] = address
                        ip_list.append(ip)

                elif y.tag == "os":
                    parse_os(y)
#                    for z in y:
#                            if z.tag == "osmatch":
#                                for a in z:
#                                    for b in a:
#                                        search = re.search(regex_linux, b.text)
#                                        if search:
#                                            test = ("%s %s%s" % (search.group(1), search.group(2), search.group(3)))
#                                            os_type = test
#                                            host_dict["os"] = os_type'''
                elif y.tag == "ports":
                    for z in y:
                        ports = {}
                        ports["PORTID"] = z.get("portid")
                        ports["PROTOCOL"] = z.get("protocol")
                        if ports["PORTID"] is not None and ports["PROTOCOL"] is not None:
                            port_list.append(ports)
                            host_dict["ports"] = port_list

            # this will be the host creation
            host_counter += 1
            if host_dict is False:
                continue

            if "os" not in host_dict:
                host_dict["os"] = "unknown"
            if "mac_address" not in host_dict:
                host_dict["mac_address"] = "unknown"
            if "ports" not in host_dict:
                host_dict["ports"] = "Unknown"

            hosts_list.append(host_dict)
            #Create map of OS -> array of ports
            host_dict = {}
    return (hosts_list, ip_list)


def print_network(hosts_list, free_ips):
    print("Subnet: \t/24")
    print("Used IP's: \t%s" % len(hosts_list))
    print("Free IP's: \t%s" % len(free_ips))
    percentage_free = 100 * float(len(free_ips))/float(255)
    print("Percent Free: \t%d%%" % percentage_free)

    table = BeautifulTable()
    table.column_headers=["IP Address", "OS", "Port", "Protocol"]
    last_row = ''

    for x in hosts_list:
        if x['ports'] is "Unknown":
            table.append_row([x['ipv4_address'], x['os'], 'Unknown', 'Unknown'])
        else:
            for port in x['ports']:
                if last_row != x['ipv4_address']:
                    table.append_row([x['ipv4_address'], x['os'], port['PORTID'], port['PROTOCOL']])
                    last_row = x['ipv4_address']
                else:
                    table.append_row(["", "", port['PORTID'], port['PROTOCOL']])

    print(table)


def get_os_types():
    regex = (["*+"])
    os_types = open("/home/monkey/Desktop/os_types", "a")
    x = open("/etc/honeypot/xprobe2.conf", "r")
    for y in x:
        if "OS_ID" in y:
            os_types.write(y)



if __name__ == "__main__":
    main()
