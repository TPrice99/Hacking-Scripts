#!/bin/bash

echo "===Host Info==="
echo "--Kernel--"
uname -a
cat /etc/lsb-release 
cat /proc/version
cat /etc/issue
cat /etc/os-release
sudo -V
hostname
cat /etc/shells

echo "--Permissions--"
id
whoami
sudo -l
history
cat /etc/passwd
cat /etc/shadow
cat /var/spool/mail

echo "--IP Info--"
ip -a
route
netstat -rn

echo "--Running programs--"
w
ps aux

echo "===Downloaded Software==="
apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list
/usr/local/
/usr/local/src
/usr/local/bin
/opt/
/home
/var/
/usr/src/

echo "===Files Permissions==="
#Find SUID
find / -perm -u=s -type f 2>/dev/null
#Find GUID
find / -perm -g=s -type f 2>/dev/null

echo "===Cron Jobs==="
crontab -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root

echo "===NFS==="
showmount -e