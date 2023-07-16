#!/bin/bash

read -p "Enter IP:PORT or domain: " IP
read -p "Enter in a wordlist: " wordlist
read -p "Do you want subdomain (1) or directories (2)" option

if [ $option -eq "1" ]
    then
        ffuf -w $wordlist:FUZZ -u http://$IP/FUZZ
    else
        ffuf -w $wordlist:FUZZ -u http://FUZZ.$IP
fi
