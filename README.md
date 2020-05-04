# iot_dependencies
This module can be used to parse PCAP files for external communications by any pre-defined devices. Output files will be written to disk and formatted as JSON objects that contain outgoing IP and DNS communication by the devices.

## Usage
usage: pcap_monster.py [-h] [-m DEVICE_MAP] [-p PCAP_LIST] [-o OUTPUT_DIR]

Parse PCAP files for external device dependencies.

optional arguments:
  -h, --help     show this help message and exit
  -m DEVICE_MAP  CSV file mapping device MAC addresses to names
  -p PCAP_LIST   List of PCAP files to parse
  -o OUTPUT_DIR  Directory to output JSON results

DEVICE_MAP defaults to device_map.csv, PCAP_LIST defaults to pcap_list.txt, and the OUTPUT_DIR defaults to creating (and overwriting existing files within) a directory called ./data

The device_map.csv file must start with a line containing the column headers: MAC,Name