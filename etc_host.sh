#!/bin/bash

[[ -z "$1" ]] && read -p 'IP:' IP ||  IP=$1
[[ -z "$2" ]] && read -p 'Url:' Url ||  Url=$2


echo $IP $Url >> /etc/hosts