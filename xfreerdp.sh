#!/bin/bash
echo "XFreeRDP Login"
#IP of target
read -p "Enter IP: " IP
#Login username
read -p "Enter Username: " Username
#Login Password
read -p "Enter Password: " Password
echo "xfreerdp /v:$IP /u:$Username /p:$Password"
#Use parameters and try to RDP
xfreerdp /v:$IP /u:$Username /p:$Password
