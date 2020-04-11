import geoip2.database

global DEVICES
global GEO_LIB
global ASN_LIB
global GEO_LIB
global ASN_LIB

def init():
    global  DEVICES, GEO_LIB, ASN_LIB

    DEVICES = {}
    GEO_LIB = geoip2.database.Reader('databases/geo_ip_database/GeoLite2-City.mmdb')
    ASN_LIB = geoip2.database.Reader('databases/asn_ip_database/GeoLite2-ASN.mmdb')



