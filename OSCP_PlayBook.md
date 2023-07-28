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

#### FTP Port 21
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
```


## Enumeration

### 