#!/usr/bin/env python3
'''
REFERENCES:
    https://vnetman.github.io/pcap/python/pyshark/scapy/libpcap/2018/10/25/analyzing-packet-captures-with-python-part-1.html
'''

import csv
import argparse
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from ipaddress import ip_address

# For debugging
from pprint import pprint

# Custom global data structures
import globals
globals.init()

# Debug function i guess
def pcap_stats(pcap_name):
    total_packets = 0
    relevant_packets = 0
    layer_list = []
    print(f"Opening: {pcap_name}")

    for (pkt_data, pkt_metadata) in RawPcapReader(pcap_name):
        ether_pkt = Ether(pkt_data)

        for layer in ether_pkt.layers():
            if layer not in layer_list:
                layer_list.append(layer)

        if ether_pkt.src in globals.DEVICES.keys():
            if ether_pkt.haslayer(IP) and ip_address(ether_pkt[IP].dst).is_global:
                relevant_packets += 1
        
        total_packets += 1

    print(f"Stats for capture: {pcap_name}")
    print(f"\tTotal number of packets: {total_packets}")
    print(f"\tTotal number of relevant packets: {relevant_packets}")
    print(f"\tThe following protocol layers were seen:")
    for layer in layer_list:
        print(f"\t\t{layer}")


def extract_IPs(pcap_name):
    for (pkt_data, pkt_metadata) in RawPcapReader(pcap_name):
        ether_pkt = Ether(pkt_data)

        if ether_pkt.src in globals.DEVICES.keys():
            if ether_pkt.haslayer(IP) and ip_address(ether_pkt[IP].dst).is_global and (ether_pkt[IP].dst not in globals.DEVICES[ether_pkt.src]["IPs"]):
                globals.DEVICES[ether_pkt.src]["IPs"].append(ether_pkt[IP].dst)


def create_device_dict(input_file):
    with open(input_file) as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader: 
            globals.DEVICES[row["MAC"]] = {}
            globals.DEVICES[row["MAC"]]["Name"] = row["Name"]
            globals.DEVICES[row["MAC"]]["IPs"] = []


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse PCAP files for external device dependencies.")
    parser.add_argument("-m", dest="device_map", type=str, help="CSV file mapping device MAC addresses to names", default="./device_map.txt")
    parser.add_argument("-p", dest="pcap_list", type=str, help="List of PCAP files to parse", default="./pcap_list.txt")
    parser.add_argument("-o", dest="output_dir", type=str, help="Directory to output JSON results", default="./data/")
    args = parser.parse_args()

    create_device_dict(args.device_map)

    with open(args.pcap_list) as f:
        for line in f.readlines():
            extract_IPs(line.strip())
    
    pprint(globals.DEVICES)

