#!/usr/bin/env python3
'''
REFERENCES:
    https://vnetman.github.io/pcap/python/pyshark/scapy/libpcap/2018/10/25/analyzing-packet-captures-with-python-part-1.html
'''

import sys
import os
import csv
import argparse
import json
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR
from ipaddress import ip_address

# For debugging
from pprint import pprint

# Custom global data structures
import globals
globals.init()


def output_to_json(output_directory):
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    for device in globals.DEVICES.keys():
        json_file = os.path.join(output_directory, globals.DEVICES[device]["Name"] + ".json")
        with open(json_file, 'w') as fp:
            json.dump(globals.DEVICES[device], fp)


def extract_IPs(ether_pkt):
    source_mac = ether_pkt.src
    dest_ip = ether_pkt[IP].dst

    # Is the packet from a device we care about?
    if source_mac in globals.DEVICES.keys():
        # Is the destination IP globally routable (i.e. not a private address)?
        if ip_address(dest_ip).is_global:
            if dest_ip not in globals.DEVICES[source_mac]["IPs"].keys():
                globals.DEVICES[source_mac]["IPs"][dest_ip] = {"count": 1}
            else:
                globals.DEVICES[source_mac]["IPs"][dest_ip]["count"] += 1


def extract_dns(ether_pkt):
    source_mac = ether_pkt.src
    # Is the packet from a device we care about?
    if source_mac in globals.DEVICES.keys():
        if ether_pkt[DNS].qr == 0: # DNS request
            # Build DNSQR structure to extract name, convert from bytes to str
            qname = DNSQR(ether_pkt[DNS].qd).qname.decode()
            if qname in globals.DEVICES[source_mac]["DNS"].keys():
                globals.DEVICES[source_mac]["DNS"][qname]["count"] += 1
            else:
                globals.DEVICES[source_mac]["DNS"][qname] = {"count": 1}


def analyze_pcap(pcap_name):
    try:
        p = RawPcapReader(pcap_name)
    except:
        print(f"Error opening file: {pcap_name}", file=sys.stderr)
        return
    
    for (pkt_data, *_) in p:
        ether_pkt = Ether(pkt_data)

        if ether_pkt.haslayer(DNS):
            # DNS queries are often sent to the local router, so 
            # we extract them first (extract_IPs ignores packets
            # sent to private addresses)
            extract_dns(ether_pkt)
        # TODO: Before defaulting to IP layer, maybe check for other
        # data we could get (e.g. http requests w/URLs?)
        elif ether_pkt.haslayer(IP):
            extract_IPs(ether_pkt)


def create_device_dict(input_file):
    with open(input_file) as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader: 
            globals.DEVICES[row["MAC"]] = {}
            globals.DEVICES[row["MAC"]]["Name"] = row["Name"]
            globals.DEVICES[row["MAC"]]["IPs"] = {}
            globals.DEVICES[row["MAC"]]["DNS"] = {}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse PCAP files for external device dependencies.")
    parser.add_argument("-m", dest="device_map", type=str, help="CSV file mapping device MAC addresses to names", default="./device_map.txt")
    parser.add_argument("-p", dest="pcap_list", type=str, help="List of PCAP files to parse", default="./pcap_list.txt")
    parser.add_argument("-o", dest="output_dir", type=str, help="Directory to output JSON results", default="./data/")
    args = parser.parse_args()

    create_device_dict(args.device_map)

    with open(args.pcap_list) as f:
        for line in f.readlines():
            analyze_pcap(line.strip())
    
    output_to_json(args.output_dir)

