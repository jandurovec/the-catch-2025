# Inaccessible backup (3 points)

Hi, emergency troubleshooter,

One of our servers couldn’t withstand the surge of pure energy and burst into
bright flames. It is backed up, but no one knows where and how the backups are
stored. We only have a memory dump from an earlier investigation available.
Find our backups as quickly as possible.

Stay grounded!

* [Download (memory dump for analysis)](inaccessible_backup.zip)

## Hints

* The server was running on Debian 12 Bookworm.

## Solution

Let's start with extracting the backup (`inaccessible_backup.dump`) from the
archive.

Since we're looking for some "backup" we can use `strings` to do a quick check
for occurrences of "backup".

```
$ strings inaccessible_backup.dump | grep -i backup
```

This yields a lot of occurrences of `rsync` being executed against
`backup.powergrid.tcc` as `bkp` user, i.e.
```
eval $(keychain --eval --quiet /root/.ssh/backup_key) && /usr/bin/rsync --delete -avz /var/www/html/ bkp@backup.powergrid.tcc:/zfs/backup/www/ > /dev/null 2>&1
```

A quick check (e.g. `ping`) reveals that `backup.powergrid.tcc` is still
running, so we'll probably need to log in to that host and download the backup.

The problem is, that we need the key (`/root/.ssh/backup_key`). We can try to
check, whether the key in openssh text format was not still in memory.

I.e. we're looking for character sequences starting with
`-----BEGIN OPENSSH PRIVATE KEY-----` (maybe preceded by some extra characters)
and ending with `-----END OPENSSH PRIVATE KEY-----` (maybe followed by some
extra characters) where the lines between these two markers represent
base64-encoded data (i.e. contain just letters, numbers, `+`, `/` and `=`).

We can either explore the `strings` dump manually (there are just 4 such keys
there) or we can write a simple script to automate this, also skipping the
empty keys where `BEGIN` and `END` markers are present with nothing in between.

```python
#!/usr/bin/env python3
import sys
import re

buffer = []
collecting = False

for line in sys.stdin:
    line = line.rstrip('\n')

    if re.search(r'-----BEGIN OPENSSH PRIVATE KEY-----$', line):
        # Extract just the BEGIN marker and everything after it
        match = re.search(r'(-----BEGIN OPENSSH PRIVATE KEY-----)$', line)
        buffer = [match.group(1)]
        collecting = True
    elif collecting:
        if re.search(r'^-----END OPENSSH PRIVATE KEY-----', line):
            # Only print if buffer has more than just BEGIN at this point (i.e. > 1 line)
            if len(buffer) > 1:
                # Extract just the END marker (ignore anything after it)
                match = re.search(r'^(-----END OPENSSH PRIVATE KEY-----)', line)
                buffer.append(match.group(1))
                print('\n'.join(buffer))
            buffer = []
            collecting = False
        elif re.match(r'^[A-Za-z0-9+/=]+$', line):
            buffer.append(line)
        else:
            # Invalid line, discard buffer
            buffer = []
            collecting = False
```

Running this against our dump reveals 4 key candidates.

```
$ strings inaccessible_backup.dump | ./extract_keys.py
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQTA2qoyMLNozBRTfVQlUEYHGvspOfUO
lHMA7AGtf+HxkgkMv3vuey32zRXP9H4FjJ1qYTLOd5ENWhdd0zmcB7YpAAAAqK0BRKutAU
SrAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMDaqjIws2jMFFN9
VCVQRgca+yk59Q6UcwDsAa1/4fGSCQy/e+57LfbNFc/0fgWMnWphMs53kQ1aF13TOZwHti
kAAAAhAOxGG4s7mlvlYW2E8Ussh9Xor4ShjiO9ax3ppuhkuPh9AAAADXJvb3RAdGhlY2F0
Y2gBAg==
-----END OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDM3J16lgLgNBQmMmQDyjV23FShkCun/mCwi0keOkZ7KAAAAJBqFi+KahYv
igAAAAtzc2gtZWQyNTUxOQAAACDM3J16lgLgNBQmMmQDyjV23FShkCun/mCwi0keOkZ7KA
AAAECGRnl8VobhNE4qCuyaiRzQWZCxv7cFeNNfIWQof1eRhczcnXqWAuA0FCYyZAPKNXbc
VKGQK6f+YLCLSR46RnsoAAAADXJvb3RAdGhlY2F0Y2g=
-----END OPENSSH PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACD/pNcxB72+l6g/JOpPhO9XcYjz/rC+n3Ql/v03dY4jSQAAAKCumQYsrpkG
LAAAAAtzc2gtZWQyNTUxOQAAACD/pNcxB72+l6g/JOpPhO9XcYjz/rC+n3Ql/v03dY4jSQ
AAAECvUkQRNBmF/imckIfnKnRCRCtb4XnZqYjSNAiw/ngWDf+k1zEHvb6XqD8k6k+E71dx
iPP+sL6fdCX+/Td1jiNJAAAAGGJrcEBiYWNrdXAucG93ZXJncmlkLnRjYwECAwQF
-----END OPENSSH PRIVATE KEY-----
```

_Note: The `strings` utility scans for printable character sequences in binary
data, but it does not guarantee that adjacent lines or multi-line text will be
contiguous or in order in a memory dump. Memory fragmentation, buffering, and
internal data structures can cause lines to be scattered or interleaved. If
that happened, we would need to use some more advanced tools or memory forensic
frameworks, however, in this case it seems it was enough (at least to extract
some keys)._

Now we can store these keys to individual files (e.g. `key1` - `key4`) and try
logging in to the backup server using one of them. We need to be a bit careful
about the permissions so that `ssh` does not complain that the key is too open
(and might ignore it as aresult of that). However, with key files readable only
for the user, there should be nothing else stopping us from successfully
retrieving the flag.

```
$ for k in `ls key*`; do ssh -i $k bkp@backup.powergrid.tcc; done
bkp@backup.powergrid.tcc: Permission denied (publickey).
bkp@backup.powergrid.tcc: Permission denied (publickey).
bkp@backup.powergrid.tcc: Permission denied (publickey).
FLAG{VDg1-MfVg-LsJI-NOS4}
Connection to backup.powergrid.tcc closed.
bkp@backup.powergrid.tcc: Permission denied (publickey).
```
