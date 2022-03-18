#!/usr/bin/env python3

import json
import sys
from shodan import Shodan
from math import ceil
import simplejson
import shodan

api_key = 'ChangeMe'
api = Shodan(api_key)

if len(sys.argv) < 2:
    print("Use: ./download_asn.py <AS> <ORG NAME>")
    sys.exit(1)

Autonomous_System = ''.join(sys.argv[1])
Org_Name = ''.join(sys.argv[2].replace(' ', '_'))

ASN = api.count('asn:"%s"' % Autonomous_System)

print("Found %i results." % ASN['total'])

cont = input('Do you want to continue downloading this ASN? y/n: ')
if cont.lower() != 'y':
    sys.exit(1)

pages = ceil(ASN['total']/100)

i = 1
ip_ports = {}
while i <= pages:
    try:
        print("Downloading page %i of %i." % (i, pages))
        t = api.search('asn:"%s"' % Autonomous_System, page=i)
        for s in t['matches']:
            ip = s['ip_str']
            port = s['port']
            if ip not in ip_ports.keys():
                ip_ports['%s' % ip ] = []
            if port not in ip_ports[ip]:
                ip_ports[ip].append(port)

        print("Downloaded page %i of %i." % (i, pages))
        i += 1
    except simplejson.errors.JSONDecodeError as e:
        print("Someone at Shodan didn't properly handle this: %s" % e)
        print("As a result, we're skipping page: %i" % i)
        print("You may want to manualy download this page")
        #i += 1
        continue
    except shodan.exception.APIError as e:
        print("Someone at Shodan didn't properly handle this: %s" % e)
        print("As a result, we're skipping page: %i" % i)
        print("You may want to manualy download this page")
        #i += 1
        continue
ASN['matches'].append(ip_ports)
filename = 'shodan_ip_port_%s_%s.json' % (Autonomous_System.lower(), Org_Name)
print("Writing to %s" % filename)
f = open(filename , 'w')
f.write(json.dumps(ASN, indent=4, sort_keys=True))
f.flush()
f.close()

#For bash pipeline handling
sys.stderr.write(filename)
sys.stderr.flush()

sys.exit(0)

