# OSCP PlayBook

## Table of Contents
- [Recon](#recon)
    - [Nmap](#nmap)
    - [Services](#services)
        - [FTP](#ftp-port-21)
        - [SSh](#ssh-port-22)
        - [Http/ Https](#http-https-ports-80-443)
        - [SMB/ Samba](#smb-samba-ports-137-138-139-445)
        - [SMTP](#smtp-ports-25-587-465)
        - [IMAP/ POP3](#imap-pop3-ports-110-143-993-995)
        - [MSSQL](#mssql-port-1433)
        - [MySQL](#mysql-port-3306)
- [Active Directory](#active-directory)

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
#### Ping sweep
```c
#Bash
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done

#CMD
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"

#PowerShell
1..254 | % {"172.16.5.$($*): $(Test-Connection -count 1 -comp 172.15.5.$($*) -quiet)"}
```

### Services

#### FTP Port 21
```c
#Connect
ftp IP PORT
nc -nv IP PORT
telnet IP PORT
openssl s_client -connect IP:PORT -starttls ftp

#anonymous login, try both
ftp anonymous@IP
username: anonymous password: blank
username: anonymous password: anonymous

#Brute Force login
hydra -L username.list -P password.list ftp://IP
```
#### SSH Port 22
```c
#Connect
ssh username@IP
ssh username@IP -p PORT

#Connect with Key
chmod 600 rsa_key
ssh -i rsa_key username@IP 

#Brute Force Login
hydra -L username.list -P password.list ssh://IP
```

#### HTTP/ HTTPS Ports 80/ 443
```c
```

#### SMB/ Samba Ports 137, 138, 139, 445
```c
Windows
    cmd:
        # Connect
        dir \\IP\Share
        net use n: \\IP\Share /user:user Password

        # Enumerate
        dir n: /a-d /s /b | find /c ":\"
        n:\*name* /s /b
    PS1:
        # Connect
        Get-ChildItem \\IP\Share
        New-PSDrive -Name "N" -Root "\\IP\Share" -PSProvider "FileSystem"

        # With credentials
        $password = 'abc' 
        $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
        Get-ChildItem -Recurse -Path N:\ -Include *cred* -File

Linux
    # Enumerate Shares
    smbclient -N -L //IP
    smbmap -H IP
    crackmapexec smb IP --shares -u '' -p ''

    # Enumerate Users/ Passwords
    hydra -L user.list -P password.list smb://IP
    MSF Smb_Login
    crackmapexec smb IP -u userlist.txt -p password.txt --local-auth

    # Login
    smbclient -U user //IP/share

    # Mount Drive
    sudo mkdir /mnt/test
    sudo mount -t cifs -o username=Username,password=Password,domain=. //IP/Share /mnt/test
```

#### SMTP Ports 25, 587, 465
```c
```

#### IMAP/ POP3 Ports 110, 143, 993, 995
```c
```

#### MSSQL Port 1433
```c

```

#### MySQL Port 3306
```c
#Connect
    #Local access
    mysql -u user -p pass
    #External
    mysql -u username -ppass -h IP

#Commands
show databases;
select version();
use database;
show tables;
show columns from table;
select * from <table> where <column> = "<string>";
```


## Enumeration

### Linux

### Windows

## Exploit

### Linux

### Windows


## Active Directory
### Enumeration
#### Passive
```c
sudo tcpdump -i ens224

sudo responder -I ens224 -A
```

#### Active
```c
# Ping Sweep
    - Linux
        for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
        fping -asgq 172.16.5.0/23

    - Windows
        CMD: for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
        PS1: 1..254 | % {"172.16.5.$($*): $(Test-Connection -count 1 -comp 172.15.5.$($*) -quiet)"}


# User Enumeration
    - Linux
        kerbrute userenum -d DOMAIN_NAME --dc DC_IP username_wordlist.txt -o valid_ad_users
        enum4linux -U IP | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
        rpcclient -U "" -N IP
        crackmapexec smb IP --users

    # Need valid credentials
    - Linux
        sudo crackmapexec smb CD_IP -u valid_user -p valid_pass (--users or --groups or --loggedon-users or --shares or -M spider_plus --share 'sharename')
        python3 windapsearch.py --dc-ip DC_IP -u USERNAME@DOMAIN_NAME -p Password --da
        python3 windapsearch.py --dc-ip DC_IP -u USERNAME@DOMAIN_NAME -p Password -PU
    - Windows


# Get Password Policy
    - Linux
        crackmapexec smb IP -u username -p password --pass-pol
        rpcclient -U "" -N IP  ->  querydominfo
        ldapsearch -h IP -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
        enum4linux -P IP
        enum4linux-ng -P IP -oA file.txt
    - Windows
        CMD
            net use \\host\ipc$ "" /u:""
            net accounts
        PS1
            import-module .\PowerView.ps1  ->  Get-DomainPolicy


# Password Spray
    - Linux
        for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" IP | grep Authority; done
        kerbrute passwordspray -d DOMAIN_NAME --dc IP valid_users.txt Password
        sudo crackmapexec smb IP -u valid_users.txt -p Password123 | grep +
        sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +
    - Windows
        Import-Module .\DomainPasswordSpray.ps1
        Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue


# Enumerate Secruity Controls
    - Windows
        Get-MpComputerStatus
        Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
        $ExecutionContext.SessionState.LanguageMode
        Find-LAPSDelegatedGroups
        Find-AdmPwdExtendedRights
        Get-LAPSComputers
```



### Exploit
```c
```