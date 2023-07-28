#!/bin/bash
time=$(date +'%m/%d/%Y')

read -p "Enter IP: " IP
read -p "1: Quick '\n'2: Full" Speed
#mkdir Recon/$IP_$time_recon

if [ $Speed -eq "1" ]
    then
        nmap $IP #> Recon/$IP_$time_recon/nmap.txt
    else
        sudo nmap -sC -sV -p- $IP #> Recon/$IP_$time_recon/tcp_nmap.txt
        sudo nmap -sU $IP #> Recon/$IP_$time_recon/_udpnmap.txt
fi
