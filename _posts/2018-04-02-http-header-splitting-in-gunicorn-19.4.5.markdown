---
title: "HTTP header splitting in gunicorn 19.4.5 (CVE-2018-1000164)"
layout: post
description: An HTTP response splitting vulnerability reported to Gunicorn's GitHub repository was reported and fixed by the maintainers; but the vulnerability was never assigned a CVE ID. I reported this to the (now defunct) Distributed Weakness Filing System project.
img: /assets/posts/2018/04/02/gunicorn.png
imgcredit: ""
date: 2018-04-02
permalink: /2018/04/02/http-header-splitting-in-gunicorn-19.4.5/
---
Timeline:
- 02 Apr 2018: This post is published
- 02 Apr 2018: CVE ID requested
- 06 Apr 2018: <a target="_blank" href="https://access.redhat.com/security/cve/cve-2018-1000164">CVE-2018-1000164</a> assigned
<br>
<br>

During a vulnerability research spree, I came across this GitHub issue titled <a href="https://github.com/benoitc/gunicorn/issues/1227" target="_blank">Potential HTTP Response Splitting Vulnerability</a>, belonging to the <a href="https://github.com/benoitc/gunicorn" target="_blank">gunicorn</a> project. The title says "potential", but the vulnerability was present and got fixed in commit <a href="https://github.com/fofanov/gunicorn/commit/6c3d8f9c205f541a6ae0a1d5eba32b1cfca252ee" target="_blank">6c3d8</a>.
<br>

Unfortunately, this vulnerability hasn't been reported to <a href="https://www.mitre.org/" target="_blank">MITRE</a> nor to the <a href="http://seclists.org/oss-sec/2016/q1/560">Distributed Weakness Filing System (DWF)</a>; therefore it's not listed in any public <a href="https://en.wikipedia.org/wiki/Common_Vulnerabilities_and_Exposures" target="_blank">CVE</a> database. In an effort to spread this information to anyone considering using this version of gunicorn, I'll fill in a DWF report hoping this issue gets a CVE ID.
<br>

An HTTP header splitting vulnerability is caused by not sanitizing strings containing characters with special meaning in HTTP (such as `CR` and `LF`) in data that will later be used to generate HTTP headers.
<br>

We can test this vulnerability by creating a Python2 virtual environment with gunicorn 19.4.5 installed:

{% highlight bash %}
user@pc:~$ virtualenv venv
user@pc:~$ source venv/bin/activate
(venv) user@pc:~$ pip install gunicorn==19.4.5
{% endhighlight %}

The following code (`myapp.py`) will define both `Foo` and `Bar`:

{% highlight python %}
def app(environ, start_response):
    data = b"Hello, World!\n"
    start_response("200 OK", [
        ("Content-Type", "text/plain"),
        ("Foo", "Foo\r\nBar: Bar"),
        ("Content-Length", str(len(data)))
    ])
    return iter([data])
{% endhighlight %}

We can run this by executing `gunicorn -w 4 myapp:app` and going to `http://127.0.0.1:8000`. Here's the resulting HTTP response:

{% highlight bash %}
user@pc:~$ curl -i http://127.0.0.1:8000/
HTTP/1.1 200 OK
Server: gunicorn/19.4.5
Connection: close
Content-Type: text/plain
Foo: Foo
Bar: Bar
Content-Length: 14

Hello, World!
{% endhighlight %}

If we attempt to do this in gunicorn 19.5.0+, this will be the resulting HTTP response:

{% highlight html %}
user@pc:~$ curl -i http://127.0.0.1:8000/
HTTP/1.1 400 Bad Request
Connection: close
Content-Type: text/html
Content-Length: 163

<html>
  <head>
    <title>Bad Request</title>
  </head>
  <body>
    <h1><p>Bad Request</p></h1>
    Invalid HTTP Header: "'Foo\\r\\nBar: Bar'"
  </body>
</html>
{% endhighlight %}

This behavior is expected, thanks to commit <a href="https://github.com/fofanov/gunicorn/commit/6c3d8f9c205f541a6ae0a1d5eba32b1cfca252ee" target="_blank">6c3d8</a>.
