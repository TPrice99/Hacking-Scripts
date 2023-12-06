#!/bin/bash

# Prompt user for IP address
read -p "Enter the IP address: " IP

# Run quick scan and save results to file
nmap -p- -Pn "$IP" -oG "$IP"_quick.txt

# Extract open and filtered ports from quick scan results
open_and_filtered_ports=$(grep -oP '\d+/(open|filtered)' "$IP"_quick.txt | cut -d '/' -f 1 | tr '\n' ',' | sed 's/,$//')

# Run full scan on open and filtered ports
if [ -n "$open_and_filtered_ports" ]; then
    echo "$open_and_filtered_ports"
    nmap -sC -sV -p "$open_and_filtered_ports" "$IP" -oG "$IP"_full.txt
    echo "Full scan completed. Results saved to $IP_full.txt"
else
    echo "No open or filtered ports found. Full scan not performed."
fi

echo "Quick scan completed. Results saved to $IP_quick.txt"
