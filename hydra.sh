#!/bin/bash
#Reads user variables
read -p "Enter IP: " IP
read -p "Enter Service (ftp, smb, ssh): " Service
read -p "Different port? Enter port if yes, leave blank if no " port

read -p "Username (1) or wordlist (2): " userlist
read -p "Password (1) or wordlist (2): " passlist

if [ $userlist -eq "1" ]
    then
        read -p "Enter username: " user
        umod=-l
    else
        read -p "Enter userlist: " user
        umod=-L
fi

if [ $passlist -eq "1" ]
    then
        read -p "Enter passwordname: " pass
        pmod=-p
    else
        read -p "Enter passlist: " pass
        pmod=-P
fi

if [ -z $port ]
	then
		$ports=""
	else
		$ports="-s $port"
fi

echo "hydra $umod $user $pmod $pass $Service://$IP $ports"

hydra $umod $user $pmod $pass $Service://$IP $ports
