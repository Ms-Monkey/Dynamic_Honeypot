import os
import re
import sys
import json
#import click
import pprint
import random
import datetime
import ipaddress
import subprocess
import xml.etree.ElementTree as etree

HONEYPOT_DICTS = []


#@click.command()
#@click.option("--user-defined", default=None, help="User defined honeypot creation system")
def main():
    '''
    For optimal results praise the Omnissiah and honour your devices machine spirit before executing this program
    '''
    global HONEYPOT_DICTS
    HONEYPOT_DICTS = []
    #TODO: Create list of OS's when user creates own honeypots
    #TODO: Does nmap.assoc actually do anything? Aggregate OS distro's?
    #TODO: Add more OS's

    #TODO: Add check if port is open when parsing xml
    #TODO: Add BETTER regex to determine OS type linux/osx/windows


    #Ask the user to create a honeypot
#    user_created_honeypots(hosts_list, free_ips, network, filepath)

    # Creates the honeypots
    new_hosts_list = calculate_honeypots(hosts_list, free_ips, network, filepath)

    # Create an accessible log file, initialise HoneyD
    honeylog = "honeylog%s.txt" % hour_minute
    if not os.path.exists("/etc/honeypot/honeylog/"):
        os.makedirs("/etc/honeypot/honeylog/")
    file = open("/etc/honeypot/honeylog/%s" % honeylog, "w+")
    file.write("")
    file.close()
    os.system("sudo chmod 777 /etc/honeypot/honeylog/%s" % honeylog)
    os.system("sudo honeyd -d -l /etc/honeypot/honeylog/%s -f /home/monkey/Desktop/honeyd_conf.conf" % honeylog)
    create_json()

def create_json():
    global HONEYPOT_DICTS
    file_path = "/home/monkey/Desktop/json_test.json"

    with open(file_path, 'w') as f:
        for x in HONEYPOT_DICTS:
            json.dump(x, f, indent=2)


def user_created_honeypots(hosts_list, free_ips, network, filepath):
    regx = "\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}"
    honeypot_dict = {}
    honeypot_dict["IP_ADDRESS"] = "192.168.1.87"
    # Query the user for honeypot IP
    while(True):
        print("Please enter the IP you wish to assign or press the enter key to auto configure one")
        x = input()

        if not x:
            ip_address = create_address(free_ips, network)
            break
        elif re.match(regx, x):
            if x in free_ips:
                ip_address = x
                break
            print("IP address not available")

    # Query for OS
    # TODO: Use regexes for this? More or less elegant?
    while(True):
        print("Please choose operating system (Windows, Linux, OSX) or hit enter to auto configure one")
        y = input()
        if not y:
            OS = "linux 2"
            break
        elif "windows" in y or "Windows" in y:
            if "7" in y:
                OS = "windows 7"
                break
            elif "XP" in y or "xp" in y:
                OS = "Windows XP"
                break
        elif "linux" in y or "Linux" in y:
            OS = "linux 2.4"
            break
        elif "osx" in y or "OSX" in y:
            OS = "OSX"
            break
        print("Did not recognise OS entered, please try again")

    config_file = open("/home/monkey/Desktop/honeyd_conf.conf", "w")
    config_file.write(DEFAULT)
    create_honeypot(ip_address, network, OS, filepath, config_file, hosts_list, 1)


def create_honeypot(ip_address, network, OS, filepath, config_file, hosts_list, count, dict=None):
    global HONEYPOT_DICTS
    #TODO: Just give this a dict, rather than all specific values
    honeypot = "Honeypot%s" % count
    honeypot_dict = {}
    honeypot_dict["HONEYPOT"] = honeypot

    if not dict:
        honeypot_dict["IP_ADDRESS"] = str(ip_address)
        honeypot_dict["UPTIME"] =  random.randint(20000, 200000)
        honeypot_dict["MAC"] = generate_MAC()
    else:
        honeypot_dict = dict

    if "linux" in OS:
        honeypot_dict["PERSONALITY"] = "Linux 2.4.20"
        honeypot_dict["New_OS"] = "Linux 2.4"
    elif "windows" in OS or "Windows" in OS:
        if "xp" in OS or "XP" in OS:
            honeypot_dict["PERSONALITY"] = "Microsoft Windows XP Professional"
            honeypot_dict["New_OS"] = "Windows XP"
        if "7" in OS:
            honeypot_dict["PERSONALITY"] = "Windows_7"

    # Add values to the template
    test = HOST_TEMPLATE.format_map(honeypot_dict)
    config_file.write(test)

    first = True
    #for loop through port array
    for host in hosts_list:
        if host["os"] == OS:
            for port in host["ports"]:
                if first:
                    print("| " + honeypot + "\t|   " +  honeypot_dict["New_OS"] + "\t| " + str(ip_address) + "\t|  " + port["PORTID"] + "\t|     " + port["PROTOCOL"] + "\t|")
                    first = False
                else:
                     print("|\t\t|        -\t|        -\t|  " + port["PORTID"] + "\t|     " + port["PROTOCOL"] + "\t|")

                temp_port = port
                temp_port["HONEYPOT"] = honeypot
                port_conf = PORT.format_map(temp_port)
                config_file.write(port_conf)

    test2 = IP_ADDRESS.format_map(honeypot_dict)
    config_file.write(test2)
    # Write out to file
    HONEYPOT_DICTS.append(honeypot_dict)

ROUTES = """
route entry 10.0.0.1
route 10.0.0.1 link 10.2.0.0/24
route 10.0.0.1 add net 10.3.0.0/16 10.3.0.1 latency {LATENCY1}ms bandwidth 10Mbps
route 10.3.0.1 link 10.3.0.0/24
route 10.3.0.1 add net 10.3.1.0/24 10.3.1.1 latency {LATENCY2}ms loss 0.5
route 10.3.1.1 link 10.3.1.0/24
"""

HOST_TEMPLATE = """
create {HONEYPOT}
set {HONEYPOT} personality "{PERSONALITY}"
set {HONEYPOT} uptime {UPTIME}
set {HONEYPOT} maxfds 35
add {HONEYPOT} tcp port 135 open
"""

IP_ADDRESS = """

set {HONEYPOT} ethernet "{MAC}"
bind {IP_ADDRESS} {HONEYPOT}
#dhcp template on eth0
#dhcp template on enp1s0
"""

PORT = """
add {HONEYPOT} {PROTOCOL} port {PORTID} open"""

DEFAULT = """
create default
set default default tcp action block
set default default udp action block
set default default icmp action block
"""

ROUTER = """
create router
set router personality "{{ ROUTER_TYPE }}"
set router default tcp action reset
add router tcp port 22 "/usr/share/honeyd/scripts/test.sh"
add router tcp port 23 "/usr/share/honeyd/scripts/router-telnet.pl"
"""


def generate_MAC():
    MAC = "00:00:00:%02x:%02x:%02x" % (random.randint(0,255), random.randint(0,255), random.randint(0,255))
    return MAC


if __name__ == "__main__":
    main()

