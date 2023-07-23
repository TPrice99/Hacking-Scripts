# OSCP PlayBook

## Table of Contents
- [Recon](#recon)
    - [Nmap](#nmap)
    - [Services](#services)


## Recon

#### Nmap
```c
#Quick scan
nmap -p- IP

#Thorough scan
sudo nmap -sC -sV -p- IP 

#UDP Scan
sudo nmap -sU IP
```

### Services

#### FTP
```c
#Connect
ftp IP PORT
nc -nv IP PORT
telnet IP PORT
openssl s_client -connect IP:PORT -starttls ftp

#anonymous login, try both
username: anonymous password: blank
username: anonymous password: anonymous

#Brute Force login
hydra -L username.list -P password.list ftp://IP

```
#### SSH

## Enumeration

### 