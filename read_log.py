import os
import re
import json
import pprint
import click
import whois

from beautifultable import BeautifulTable
from geopy.geocoders import Nominatim
import random
import pygeoip
import ipaddress
import subprocess

import gmplot
import numpy as np
#import mpl_toolkits
#mpl_toolkits.__path__.append('/usr/lib/pymodules/python2.7/mpl_toolkits/')
from mpl_toolkits.basemap import Basemap
#import mpl_toolkits.basemap
import matplotlib.pyplot as plt

#TODO: ICMP connections
#TODO: Top ten ports
# MIcrosoft RDP port, VNC, UPnP
# ICMP by port
#Bro firewall, dynamic firewall open source, allows all traffic and filters by what the traffic does
# Multicast is 224.x.x.x

@click.command()
@click.option("--file", default=None, help="path and file to be read")
@click.option("--output", default=None, help="output directory")
def main(file=None, output=None):
    ip_address_dict = {}
    protocol_dict = {}
    country_dict = {}
    subnet_dict = {}
    port_dict = {}
    total_attacks = 0

#    log_dicts = []

    gi = pygeoip.GeoIP('GeoIP.dat')

    if file:
        log = open(file, "r")
    else:
        log = open("/tmp/honeyd_log/honeylog0847_110719.txt", "r")

    if output:
        output_directory = output
    else:
        output_directory = "/home/monkey/Desktop/"

    contents = log.readlines()

    regex = "(\d{4})-(\d{1,2})-(\d{1,2})-(\d{2}):(\d{2}):(\d{2}).(\d{0,4}) (\w*)\((\d{1,5})\).+ (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}) (\d{1,5}) (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}) (\d{1,5}).+(\d{0,6})"
    regex_country = "GeoIP Country Edition: (\w{2}), (.*)"
    regex_subnet = "(\d{1,3}.\d{1,3}.\d{1,3}).+"
    regex_newline = "^\s*$"

    count = 0
    for x in contents:
        if count == 0:
            count = count + 1
            continue
        test = re.match(regex, x)

        if test is None:
            continue

        total_attacks += 1

#        date = ("%s/%s/%s" % (test.group(3), test.group(2), test.group(1)))
#        time = ("%s:%s:%s" % (test.group(4), test.group(5), test.group(6)))

        connection = test.group(8)
        connect = test.group(9)
        ip_sender = test.group(10)
        port_receiver = test.group(11)
        ip_receiver = test.group(12)
        port_sender = test.group(13)
#        unknown = test.group(14)
        subnet = re.match(regex_subnet, ip_sender).group(1) + '.xx'

        if not ip_address_dict.get(ip_sender):
            ip_address_dict[ip_sender] = 1
        else:
            ip_address_dict[ip_sender] = ip_address_dict[ip_sender] + 1


        if not subnet_dict.get(subnet) and subnet != None:
            subnet_dict[subnet] = 1
        elif subnet != None:
            subnet_dict[subnet] = subnet_dict[subnet] + 1


        if not protocol_dict.get(connection):
            protocol_dict[connection] = 1
        else:
            protocol_dict[connection] = protocol_dict[connection] + 1


        if not port_dict.get(port_receiver):
            port_dict[port_receiver] = 1
        else:
            port_dict[port_receiver] = port_dict[port_receiver] + 1

        if ip_sender.startswith('255') or ip_sender.startswith('239') or ip_sender.startswith('130.195') or ip_sender.startswith('224'):
            #Ignore broadcast and ssdp
            continue

        ctry = subprocess.check_output("geoiplookup %s" % ip_sender, shell=True)
        y = re.match(regex_country, ctry)

        if not y:
            country = "Local Network"
        else:
            country = y.group(2)

        if not country_dict.get(country) and country != "Local Network":
            country_dict[country] = 1
        elif country != 'Local Network':
            country_dict[country] = country_dict[country] + 1

#        dict_ = store_logs(date, time, connection, country, ip_sender, port_sender, ip_receiver, port_receiver, log_dicts)
#        log_dicts.append(dict_)

    country_dict_alt = country_dict.copy()
    print_countries(country_dict_alt)
    print_ips(ip_address_dict, "IP Address")
    print_ips(subnet_dict, "Subnet")
    print_ips(port_dict, "Port")
    print_protocols(protocol_dict)
#    export_json(log_dicts, output_directory)
    draw_map(country_dict, total_attacks)


def print_protocols(protocol_dict):
    table = BeautifulTable()
    table.column_headers = ["Protocol", "Connections"]
    highest = ""
    highest_count = 0

    for x in range(len(protocol_dict)):
        for y in protocol_dict:
            if protocol_dict[y] > highest_count:
                highest = y
                highest_count = protocol_dict[y]
        table.append_row([highest, highest_count])
        highest_count = 0
        protocol_dict.pop(highest)

    print(table)


def print_ips(ip_dict, title):
    table = BeautifulTable()
    table.column_headers = [title, 'Connections']
    highest = ""
    highest_count = 0

    for x in range(10):
        for y in ip_dict:
            if ip_dict[y] > highest_count:
                highest = y
                highest_count = ip_dict[y]
#        registrar = whois.whois(highest)
        table.append_row([highest, highest_count])
        highest_count = 0
        ip_dict.pop(highest)

    print(table)
    print("")


def print_countries(country_dict):
    table = BeautifulTable()
    table.column_headers = ['Country', 'Connections']

    highest = ""
    highest_count = 0
    for x in range(10):
        for y in country_dict:
            if country_dict[y] > highest_count:
                highest = y
                highest_count = country_dict[y]
        table.append_row([highest, highest_count])
        highest_count = 0
        country_dict.pop(highest)

    print(table)
    print("")


def draw_map(country_dict, total_attacks):
    #TODO: Print number of connections by country
    m = Basemap(projection='cyl',llcrnrlat=-90,urcrnrlat=90,
            llcrnrlon=-180,urcrnrlon=180,resolution='c')
    m.drawcoastlines()
    m.shadedrelief(scale=0.2)
#    m.fillcontinents(color='green', lake_color='aqua')
#    #draw parallels and meridians.
#    m.drawparallels(np.arange(-90.,91.,30.))
#    m.drawmeridians(np.arange(-180.,181.,60.))
#    m.drawmapboundary(fill_color='aqua')
    m.drawcountries()
#    x, y = m(-122.3, 47.6)
#    plt.plot(x, y, 'ok', markersize=5)
#    plt.text(x, y, ' Seattle', fontsize=12);

    for country in country_dict:
        geolocation = Nominatim(user_agent="ua", timeout=3)
        location = geolocation.geocode(country)

        if country_dict[country] > total_attacks/10:
            plt.plot(location.longitude, location.latitude, 'ok', markersize=9, color='red')
        elif country_dict[country] > total_attacks/20:
            plt.plot(location.longitude, location.latitude, 'ok', markersize=8, color='orange')
        else:
            plt.plot(location.longitude, location.latitude, 'ok', markersize=7, color='yellow')

    plt.title("Honeypot Attack Source Countries")
    plt.show()


def store_logs(date, time, connection, country, ip_sender, port_sender, ip_receiver, port_receiver, unknown, log_dicts):
    sender_dict = {
        "ip_address": ip_sender.strip(),
        "port": port_sender.strip()
    }

    receiver_dict = {
        "ip_address": ip_receiver.strip(),
        "port": port_receiver.strip()
    }

    connection_dict = {
        "date": date.strip(),
        "time": time.strip(),
        "country": country.strip(),
        "connection": connection.strip(),
        "unknown": unknown.strip(),
        "sender": sender_dict,
        "receiver": receiver_dict
    }

    final_dict = {
        "Connection": connection_dict
    }
    return final_dict


def export_json(log_dicts, output_directory):
    with open("%sjson_output.json" % output_directory, 'w') as f:
        for x in log_dicts:
            json.dump(x, f, indent=2)


if __name__ == "__main__":
    main()
