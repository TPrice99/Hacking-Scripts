#!/bin/python3

list =["aa-exec","ab","agetty","alpine","ar","arj","arp","as","ascii-xfr","ash","aspell","atobm","awk","base32","base64","basenc","basez","bash","bc","bridge","busybox","bzip2","cabal","capsh","cat","chmod","choom","chown","chroot","clamscan","cmp","column","comm","cp","cpio","cpulimit","csh","csplit","csvtool","cupsfilter","curl","cut","dash","date","dd","debugfs","dialog","diff","dig","distcc","dmsetup","docker","dosbox","ed","efax","elvish","emacs","env","eqn","espeak","expand","expect","file","find","fish","flock","fmt","fold","gawk","gcore","gdb","genie","genisoimage","gimp","grep","gtester","gzip","hd","head","hexdump","highlight","hping3","iconv","install","ionice","ip","ispell","jjs","join","jq","jrunscript","julia","ksh","ksshell","kubectl","ld.so","less","logsave","look","lua","make","mawk","more","mosquitto","msgattrib","msgcat","msgconv","msgfilter","msgmerge","msguniq","multitime","mv","nasm","nawk","ncftp","nft","nice","nl","nm","nmap","node","nohup","od","openssl","openvpn","pandoc","paste","perf","perl","pexec","pg","php","pidstat","pr","ptx","python","rc","readelf","restic","rev","rlwrap","rsync","rtorrent","run-parts","rview","rvim","sash","scanmem","sed","setarch","setfacl","setlock","shuf","soelim","softlimit","sort","sqlite3","ss","ssh-agent","ssh-keygen","ssh-keyscan","sshpass","start-stop-daemon","stdbuf","strace","strings","sysctl","systemctl","tac","tail","taskset","tbl","tclsh","tee","terraform","tftp","tic","time","timeout","troff","ul","unexpand","uniq","unshare","unsquashfs","unzip","update-alternatives","uudecode","uuencode","vagrant","view","vigr","vim","vimdiff","vipw","w3m","watch","wc","wget","whiptail","xargs","xdotool","xmodmap","xmore","xxd","xz","yash","zsh","zsoelim"]

lines = []
print ("Copy paste the out for this command: find / -type f -perm -04000 -ls 2>/dev/null:\n")
while True:
    line = input()
    if line:
        lines.append(line)
    else:
        break
text = '\n'.join(lines)

lines = text.strip().split('\n')
file_paths=[]

for line in lines:
    parts = line.split('/')
    file_path = parts[-1]
    file_paths.append(file_path)

for file_path in file_paths:
    file_path = file_path.split('/')
    #print (file_path)
    if file_path[-1] in list:
        print (file_path[-1])