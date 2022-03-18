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
    print("Use: ./download_asn.py <COUNTRY CODE> <COUNTRY NAME>")
    sys.exit(1)

Country_code = ''.join(sys.argv[1])
Country_name = ''.join(sys.argv[2].replace(' ', '_'))

Country = api.count('country:"%s"' % Country_code)

print("Found %i results." % Country['total'])

cont = input('Do you want to continue downloading this Country? y/n: ')
if cont.lower() != 'y':
    sys.exit(1)

pages = ceil(Country['total']/100)

i = 1
ip_ports = {}
while i <= pages:
    try:
        print("Downloading page %i of %i." % (i, pages))
        t = api.search('country:"%s"' % Country_code, page=i)
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
        print("As a result, we're retrying page: %i" % i)
        continue
    except shodan.exception.APIError as e:
        print("Someone at Shodan didn't properly handle this: %s" % e)
        print("As a result, we're retrying page: %i" % i)
        continue

Country['matches'].append(ip_ports)
filename = 'shodan_ip_port_%s_%s.json' % (Country_code.lower(), Country_name)
print("Writing to %s" % filename)
f = open(filename , 'w')
f.write(json.dumps(Country, indent=4, sort_keys=True))
f.flush()
f.close()

# For Bash pipeline handling

sys.stderr.write(filename)
sys.stderr.flush()

sys.exit(0)


#all search facets: ['asn', 'bitcoin.ip', 'bitcoin.ip_count', 'bitcoin.port', 'bitcoin.user_agent', 'bitcoin.version', 'city', 'cloud.provider', 'cloud.region', 'cloud.service', 'country', 'cpe', 'device', 'domain', 'has_screenshot', 'hash', 'http.component', 'http.component_category', 'http.favicon.hash', 'http.html_hash', 'http.robots_hash', 'http.status', 'http.title', 'http.waf', 'ip', 'isp', 'link', 'mongodb.database.name', 'ntp.ip', 'ntp.ip_count', 'ntp.more', 'ntp.port', 'org', 'os', 'port', 'postal', 'product', 'redis.key', 'region', 'rsync.module', 'screenshot.label', 'snmp.contact', 'snmp.location', 'snmp.name', 'ssh.cipher', 'ssh.fingerprint', 'ssh.hassh', 'ssh.mac', 'ssh.type', 'ssl.alpn', 'ssl.cert.alg', 'ssl.cert.expired', 'ssl.cert.extension', 'ssl.cert.fingerprint', 'ssl.cert.issuer.cn', 'ssl.cert.pubkey.bits', 'ssl.cert.pubkey.type', 'ssl.cert.serial', 'ssl.cert.subject.cn', 'ssl.chain_count', 'ssl.cipher.bits', 'ssl.cipher.name', 'ssl.cipher.version', 'ssl.ja3s', 'ssl.jarm', 'ssl.version', 'state', 'tag', 'telnet.do', 'telnet.dont', 'telnet.option', 'telnet.will', 'telnet.wont', 'uptime', 'version', 'vuln', 'vuln.verified']
