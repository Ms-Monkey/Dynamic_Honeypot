import os
import pickle
import random
import datetime
import ipaddress
import xml.etree.ElementTree as etree
import click
from beautifultable import BeautifulTable

HONEYPOT_DICTS = {}

@click.command()
@click.option("--nmap_file", default=None, help="An xml file created by an nmap scan of the destination network")
@click.option("--subnet", required=True, help="The subnet range the honeypots will be deployed in")
@click.option("--quick_scan", default=False, help="Decide nmap timeout, true means 10s timeout, false is 2m")
def main(subnet, nmap_file=None, quick_scan=False):
    global HONEYPOT_DICTS
    HONEYPOT_DICTS = []

    if not nmap_file:
        xml = scan_network(subnet, quick_scan)
    else:
        xml = etree.parse(nmap_file)
    root = xml.getroot()
    ip_list = parse_xml(root)

    network = ipaddress.IPv4Network(unicode("192.168.1.0/24", 'utf-8'))

    free_ips = get_free_ipv4_addresses(ip_list, network)

    print_network_stats(free_ips)
    output_dict = {'configs': HONEYPOT_DICTS, 'ips': free_ips}
    with open("/tmp/network_config.pkl", "wb") as pkl:
         pickle.dump(output_dict, pkl)


def parse_os(root, ip, port_list):
    global HONEYPOT_DICTS
    os_dict = {}
    os = ""

    if root == None:
        return

    for x in root:
         if x.tag == 'osmatch':
            os = x.get('name')

    if not os:
        os = 'Unknown'

    for os_type in HONEYPOT_DICTS:
        if os_type == os:
            os_type["ports"].append(port_list)
            break

    else:
            os_dict = {
                "os": os, 
                "ports": port_list,
                "ip": ip
            }
            HONEYPOT_DICTS.append(os_dict)


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
    host_dict = {}
    port_list = []
    ip_list = []
    host_counter = 0
    ip = ""

    for host in root:
        port_list = []
        # This just gets the host info, which holds OS and IP address
        if host.tag == "host":
            host_dict["host_number"] = host_counter

            for y in host:
                if y.tag == "address":
                    address_type = y.get("addrtype")
                    address = y.get("addr")

                    if address_type == "ipv4":
                        ip = ipaddress.ip_address(unicode(address,"utf-8"))
                        host_dict["ipv4_address"] = address
                        ip_list.append(ip)

                    elif address_type == "ipv6":
                        ip = ipaddress.ip_address(unicode(address,"utf-8"))
                        host_dict["ipv6_address"] = address
                        ip_list.append(ip)
                elif y.tag == "ports":
                    for z in y:
                        ports = {}
                        ports["PORTID"] = z.get("portid")
                        ports["PROTOCOL"] = z.get("protocol")
                        if ports["PORTID"] is not None and ports["PROTOCOL"] is not None:
                            port_list.append(ports)

                elif y.tag == "os":
                    parse_os(y, ip, port_list)

    return (ip_list)


def print_network_stats(free_ips):
    print("Subnet: \t/24")
    print("Used IP's: \t%s" % len(HONEYPOT_DICTS))
    print("Free IP's: \t%s" % len(free_ips))
    percentage_free = 100 * float(len(free_ips))/float(255)
    print("Percent Free: \t%d%%" % percentage_free)

    table = BeautifulTable()
    table.column_headers=["IP Address", "OS", "Port", "Protocol"]

    for _os in HONEYPOT_DICTS:
        first_row = True
        port_list = _os['ports']
        for port in port_list:
            if first_row:
                first_row = False
                table.append_row([_os['ip'], _os['os'], port['PORTID'], port['PROTOCOL']])
            else:
                table.append_row(["", "", port['PORTID'], port['PROTOCOL']])

    print(table)



if __name__ == "__main__":
    main()
