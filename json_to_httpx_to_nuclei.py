#!/usr/bin/env python3
import json
import os
import sys
import subprocess
import shlex
import math

common_ports = [80,443,7547,8080,8089,4567,8008,8443,8081,2087,2083,2082,5985,2086,8000,8888,1024,21,81,8880,9080,5000,49152,9000,3128,7170,8085,8090,5001,8001,9999,10000,10443,8083,9090,3000,88,5357,9100,7777,82,52869,9443,4443,8800,9306,8181,444,7443,9001,2096,8086,5222,8010,1234,8009,8200,2095,10001,9002,83,6000,20000,9009,50000,5005,6443,9200,32400,2222,5555,3001,8069,8099,8889,6001,1900,8060,9998,5006,7001,84,5986,8123,888,25,12345,5800,631,10250,8098,7548,2000,2121,8112,3702,2077,8087,5010,8126]

httpx_str = "httpx -random-agent -nf -rl 5000 -t 1000 -p %s -o %s"
nuclei_str = "nuclei -l %s -o %s.tmp -severity critical,high,medium,low"
nuclei_out = "%s.tmp"

if len(sys.argv) < 2:
    print("Use: ./json_to_httpx_to_nuclei.py <Shodan ip_port results json>")

try:
    f = open(sys.argv[1]).read()
except Exception as e:
    print("Failed to open file: %s" % e)
    sys.exit(1)

ip_ports = json.loads(f)

r = str(sys.argv[1].split('.json')[0])
httpx_output =  r + '_nuke_this.txt'
print (httpx_output)

matches = ip_ports['matches']

for hosts in matches:
    num_hosts = len(hosts)
    i = 1

    for ip in hosts:
        com_ports = common_ports
        print('Scanning target #%i of %i' % (i, num_hosts))
        target_ip = ip
        for port in hosts[ip]:
            if port not in com_ports:
                com_ports.append(port)
        ports = ','.join([str(port) for port in com_ports])
        httpx_target = httpx_str % (ports, httpx_output)
        nuke_out = nuclei_out % httpx_output
        nuclei_target = nuclei_str % (httpx_output,httpx_output)
        httpx_args = shlex.split(httpx_target)
        nuclei_args = shlex.split(nuclei_target)

        try:
            print ('Running %s against %s' % (httpx_target, target_ip))
            p = subprocess.run(httpx_args, stderr=subprocess.DEVNULL, input=ip, encoding='ascii')
            if p.returncode != 0:
                print("%s failed with return code: %i" % (httpx_target, p.returncode))
                i+=1
                continue
        except Exception as e:
            print("Something went wrong on the last subprocess: %s" % e)
            i += 1
            continue

        if not os.path.exists(httpx_output):
            print("httpx returned no results, skipping nuke")
            i+=1
            continue

        if os.stat(httpx_output).st_size == 0:
            print('httpx returned no results, skipping nuke')
            i += 1
            continue

        try:
            print ('Running %s against %s' % (nuclei_target, target_ip))
            p = subprocess.run(nuclei_args, stderr=subprocess.DEVNULL)
            if p.returncode != 0:
                i += 1
                continue
        except Exception as e:
            print("Something went wrong on the last subprocess: %s" % e )
            i += 1
        i += 1
        # append current nuked targets to running file
        nuke_final = r + '.nuked'
        print("To view nuclei results, `tail -f %s/%s`" % (os.environ['PWD'],nuke_final))
        os.system("cat %s >> %s" % (nuke_out, nuke_final))
        os.system("rm %s" % nuke_out)
