#!/bin/bash

if [ "$#" -ne 2 ];
  then echo "Use nuke_asn.sh <ASN> <Org Name>"
  exit 2
fi

echo "Let's get 'em"
echo "TARGET: $1 $2"
echo "Downloading ASN IPs and Ports"
TARGETS=$(echo 'y' | download_ip_port_by_asn.py $1 "$2" 2>&1 > /dev/null)
echo "$TARGETS"
echo "httpx to nuclei"
json_to_httpx_to_nuclei.py "$TARGETS"
echo "Been nice doing business with you"
