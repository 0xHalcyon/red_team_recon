#!/usr/bin/env python3

import json
import sys
from shodan import Shodan
from math import ceil
import shodan
import simplejson

api_key = 'ChangeMe'
api = Shodan(api_key)

if len(sys.argv) < 2:
    print("Use: ./download__ip_port_by_cidr.py <CIDR>")
    sys.exit(1)

CIDR_BLK = ''.join(sys.argv[1])

CIDR = api.count('net:"%s"' % CIDR_BLK)

print("Found %i results." % CIDR['total'])

if CIDR['total'] == 0:
    print("No results found, exiting")
    sys.exit(1)

cont = input('Do you want to continue downloading this CIDR? y/n: ')
if cont.lower() != 'y':
    sys.exit(1)

pages = ceil(CIDR['total']/100)

i = 1
ip_ports = {}
while i <= pages:
    try:
        print("Downloading page %i of %i." % (i, pages))
        t = api.search('net:"%s"' % CIDR_BLK, page=i)
        for s in t['matches']:
            ip = s['ip_str']
            port = s['port']
            org = s['org']
            as_number = s['asn']
            if ip not in ip_ports.keys():
                ip_ports['%s' % ip ] = []
            if port not in ip_ports[ip]:
                ip_ports[ip].append(port)

        print("Downloaded page %i of %i." % (i, pages))
        i += 1
    except simplejson.errors.JSONDecodeError as e:
        print("Someone at Shodan didn't properly handle this: %s" % e)
        print("As a result, we're retrying page: %i" % i)
        continue
    except shodan.exception.APIError as e:
        print("Someone at Shodan didn't properly handle this: %s" % e)
        print("As a result, we're retrying page: %i" % i)
        continue
CIDR['matches'].append(ip_ports)
org = org.replace(' ', '_')
filename = 'shodan_ip_port_%s__%s_%s.json' % (CIDR_BLK.lower().replace('/', '_'), as_number, org.replace('/','_'))
print("Writing to %s" % filename)
f = open(filename , 'w')
f.write(json.dumps(CIDR, indent=4, sort_keys=True))
f.flush()
f.close()

#For bash pipeline handling
sys.stderr.write(filename)
sys.stderr.flush()

sys.exit(0)
