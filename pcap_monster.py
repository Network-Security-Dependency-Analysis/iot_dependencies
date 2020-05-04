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


# ==================================================================================================
# Get the latitude and longitude of an IP address

def get_ip_geo(ip_address):
    try:
        geo_ip_data = globals.GEO_LIB.city(ip_address)
        if geo_ip_data:
            lat = geo_ip_data.location.latitude
            long = geo_ip_data.location.longitude
            return lat, long

    except Exception as e:
        print("ERROR (GEOIP): " + str(e))

    return None, None


# ==================================================================================================
# Get the Autonomous System information for the IP address

def get_ip_asn(ip_address):
    try:
        asn_ip_data = globals.ASN_LIB.asn(ip_address)
        if asn_ip_data:
            asn = asn_ip_data.autonomous_system_number
            as_org = asn_ip_data.autonomous_system_organization
            return asn, as_org
    except Exception as e:
        print("ERROR (ASNIP): " + str(e))

    return None, None


def extract_IPs(ether_pkt):
    source_mac = ether_pkt.src
    dest_ip = ether_pkt[IP].dst

    # Is the destination IP globally routable (i.e. not a private address)?
    if ip_address(dest_ip).is_global:
        if dest_ip not in globals.DEVICES[source_mac]["IPs"].keys():
            ipgeo = get_ip_geo(dest_ip)
            ipasn = get_ip_asn(dest_ip)
            globals.DEVICES[source_mac]["IPs"][dest_ip] = {
                "count": 1,
                "lat": ipgeo[0],
                "lon": ipgeo[1],
                "asn": ipasn[0],
                "as_org": ipasn[1]
                }
        else:
            globals.DEVICES[source_mac]["IPs"][dest_ip]["count"] += 1


def extract_dns(ether_pkt):
    source_mac = ether_pkt.src
    
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

        # If the src MAC is not from a device we care about, skip packet
        if ether_pkt.src not in globals.DEVICES.keys():
            continue

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
            globals.DEVICES[row["MAC"]]["MAC"] = row["MAC"]
            globals.DEVICES[row["MAC"]]["IPs"] = {}
            globals.DEVICES[row["MAC"]]["DNS"] = {}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse PCAP files for external device dependencies.")
    parser.add_argument("-m", dest="device_map", type=str, help="CSV file mapping device MAC addresses to names", default="./device_map.csv")
    parser.add_argument("-p", dest="pcap_list", type=str, help="List of PCAP files to parse", default="./pcap_list.txt")
    parser.add_argument("-o", dest="output_dir", type=str, help="Directory to output JSON results", default="./data/")
    args = parser.parse_args()

    create_device_dict(args.device_map)

    with open(args.pcap_list) as f:
        for line in f.readlines():
            analyze_pcap(line.strip())
    
    output_to_json(args.output_dir)

