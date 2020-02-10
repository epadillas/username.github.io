---
title: "On secure web downloads"
layout: post
permalink: /2016/10/01/on-secure-web-downloads
description: It's not uncommon to find files, their signatures, and PGP keys distributed without TLS on today's web. This exposes users to MitM attacks which can eventually compromise their systems.
date: 2015-10-01
img: /assets/posts/2016/10/01/keys.jpg
imgcredit: "Randall Chacon / freeimages.com"
---

It's not uncommon to find files, their signatures, and PGP keys distributed without TLS on today's web. This exposes users to MitM attacks which can eventually compromise their systems.
<br>

This post covers the following topics:
1. X.509 certificates, TLS, trust, and Firefox
2. RSA keypairs, HKP, and public key distribution
3. The usefulness of jointly using TLS and RSA keypairs
<br>
<br>

Although the majority of this post applies to generic HTTP transfers, the client's perspective will be limited to Firefox versions 45 to 49 and GPG 1.4. In this context, a secure download is understood as the unmodified and undisturbed data flow between one requesting client and one responding server.

<br>
<hr>
<br>
### X.509 certificates, TLS, trust, and Firefox

To download something securely, the first problem to solve is how to authenticate a web server: How can I prove that this is not an attacker posing as the online store I'm trying to use?
<br>

In the physical world, we use identity documents such as passports to identify people. A document of this type contains information that uniquely identifies a person: Name, photograph, date and place of birth, and so on. Combining a passport and the person's physical presence is enough to deem that person authentic; as long as that person looks like the one in the photograph.
<br>

In the virtual world, servers can use files known as X.509 certificates to advertise an identity. A certificate of this type contains information that uniquely identifies its owner: Name, common name, geographic location, public key, and so on. Combining an X.509 certificate and the server's virtual presence is enough to deem that server authentic; as long as that server's domain name matches the common name specified in the certificate.
<br>

Naturally, other mechanisms exist that may invalidate a passport or a certificate, for example, expiration dates and revocation lists. This won't be covered in this post.
<br>

The common name element of an X.509 certificate is of utmost importance. It links the certificate to a reachable virtual address; be it a domain name such as `google.com`, or an IP address such as `8.8.8.8`. This virtual address is what we as humans use to identify Internet entities: It's meant to be clear and easy to read. This is similar to a passport's photograph: Our face must be shown in a clear fashion for easy identification.
<br>

If we visit `google.com` and we are offered a certificate with `facebook.com` as the common name, we cannot trust that server. Modern browsers take care of this check. Firefox 49 does this in the `CheckCertHostname` function in the `security/pkix/lib/pkixnames.cpp` file. The following authored snippet contains the relevant code: 
<br>


{% highlight c %}
if (IsValidReferenceDNSID(hostname)) {
  rv = SearchNames(subjectAltName, subject, GeneralNameType::dNSName,
                   hostname, fallBackToSearchWithinSubject, match);
} else if (ParseIPv6Address(hostname, ipv6)) {
  rv = SearchNames(subjectAltName, subject, GeneralNameType::iPAddress,
                   Input(ipv6), FallBackToSearchWithinSubject::No, match);
} else if (ParseIPv4Address(hostname, ipv4)) {
  rv = SearchNames(subjectAltName, subject, GeneralNameType::iPAddress,
                   Input(ipv4), fallBackToSearchWithinSubject, match);
} else {
  return Result::ERROR_BAD_CERT_DOMAIN;
}
switch (match) {
  case MatchResult::Mismatch:
    return Result::ERROR_BAD_CERT_DOMAIN;
  case MatchResult::Match:
    return Success;
}
{% endhighlight %}

This function checks if we are dealing with either a hostname (based on a mixture of RFCs and erratas described in the `IsValidDNSID` function) or an IP address. Then, the underlying functions check if the address shown in the certificate (`presentedID`) matches the one in the address bar (`referenceID`). If so, this test will pass and Firefox will keep going.
<br>

The next problem to solve is how to know if a certificate is genuine. The same problem exists for passports. It's not enough to carry any piece of paper and call it a passport; just as it's not enough to offer any X.509 certificate with outrageous claims (such as "yeah I own `google.com` and this is its public key"). Genuine certificates and passports are issued by Internet Authorities (IA) and governmental agencies respectively. These organizations follow security standards to ensure that the documents they issue are hard to forge.
<br>

Passports follow the recommendations listed in ICAO's <a href="http://www.icao.int/publications/pages/publication.aspx?docnum=9303" target="_blank">Document 9303</a>, which includes specifications regarding <a href="http://www.icao.int/publications/Documents/9303_p4_cons_en.pdf#14" target="_blank">layout</a>, <a href="http://www.icao.int/publications/Documents/9303_p9_cons_en.pdf#17" target="_blank">biometric data</a>, and so on. On the other hand, X.509 certificates rely on public key cryptography, where the IA's signature and the validity of the IA as a trusted entity are used to determine if a certificate is trustworthy.
<br>

IAs sign certificates with their private key. Consider the example of an IA called "XYZ" who's asked to sign a certificate for Amazon. That signature can be understood as if XYZ had said "yes, I'm certain that the person asking me to sign a certificate with `amazon.com` as the common name actually works at Amazon and has the authority to request this". These requests are known as <a href="https://tools.ietf.org/html/rfc2986" target="_blank">certificate signing requests</a> (CSRs).
<br>

<center>
<img width="75%" height="75%" src="/assets/posts/2016/10/01/csr_edit.png"/>
</center>

The IA's signature cannot be forged (or better put, the way to do it hasn't been discovered <i>yet</i>), and we can verify its legitimacy only if we have its corresponding public key. Which now prompts us with the problem of knowing the public keys of these IAs.
<br>

We have not yet solved the problem of securely downloading <i>anything</i>, so downloading these public keys is not an option. Would we need to physically visit every IA and ask for their public keys? What about new IAs? Would this become weekly activity? Certainly this is not practical. This <i>impracticality</i> problem can be solved with <a href="https://tools.ietf.org/html/rfc5914" target="_blank">trust anchors</a>. The basic principle behind this strategy is to pre-install the public keys of IAs (embedded in their very own X.509 certificates) in operating systems. These certificates act as anchors because we fully trust them to authenticate Internet entities, such as websites, by verifying the signature in the certificates they offer. These IAs are also known as Certificate Authorities (CAs).
<br>

There's no limit to the amount of signatures a CA can create, so it can vouch for the identity of unlimited websites. Instead of worrying about having the certificate of <i>every</i> website, this allows us to worry about a <i>way</i> smaller set belonging to CAs.
<br>

In Debian and Ubuntu, CA certificates are stored in `/etc/ssl/certs`. The package responsible for them is `ca-certificates`, and every fresh install has it. Firefox stores its own in `/usr/share/ca-certificates/mozilla`. In Android, you can list them by going to <code class="inlin">Settings -> Security -> Trusted Credentials`. Internet big-names such as Symantec, GoDaddy, and VeriSign (just to name a few) are "trusted" by the Internet to act as CAs.
<br>

Wrapping things up, the "trust path" we have described starts with CA certificates (trust anchors) in our computers. These CAs vouch for the identity of  servers accessible through common names.  Modern browsers are capable of <a href="https://tools.ietf.org/html/rfc4158" target="_blank">processing the certification path</a> of whatever X.509 certificate they get when connecting to a website. By using the `BuildCertChain` function, Firefox will eventually figure out that Amazon's certificate was signed by XYZ, and that XYZ has a CA certificate in my computer:
<center>
<img width="90%" height="90%" src="/assets/posts/2016/10/01/1toN_certs.png"/>
</center>
If a website offers a certificate that hasn't been signed by a CA (or by an organization trusted by my computer), encryption is still possible. But securely connecting to that website is inconvenient: There's no way of knowing if the offered public key is genuine or not. Firefox will show a warning when the certification path of a certificate doesn't end in a CA certificate installed in my computer:

<center>
<img width="60%" height="60%" src="/assets/posts/2016/10/01/untrusted_root_ca.png"/>
</center>
After concluding that the certificate offered by a website is authentic, it's time to start an encrypted communication channel by using the public key in it. Whatever is encrypted with that key can only be decrypted with its corresponding private key (known only to the web server offering the certificate). This mechanism is used by Firefox and its underlying TLS libraries to negotiate an encryption mechanism for the rest of the communication with the server (eg. a symmetric key).
<br>

In conclusion, as long as servers have their certificates in place (signed by a CA or not, as long as we can be sure they are genuine), communication channels with them can be considered secure against MitM attacks, assuming that no other protocols are attacked.

<br>
<hr>
<br>
### RSA keypairs, HKP, and public key distribution

When a Software Provider (SP) publishes files, it's in its best interest to offer mechanisms to verify their integrity and authenticity. If TLS is properly implemented, external attackers won't be able to impersonate the SP server. But questions arise when multiple people have privileged access to that server (eg. sysadmins, or other not-so-privileged UNIX users):
- Are all of these users trustworthy?
- Is the server configured to keep users from modifying eachother's files?
- How likely is it that a <a href="https://en.wikipedia.org/wiki/Zero-day_%28computing%29" target="_blank">0-day</a> could help a user circumvent these measures?
- Could it be that one of these users would like to tamper with these files?
- How can we increase the granularity of the authenticity and integrity checks for these files?
<br>
<br>

A popular solution to this problem is the signing and verification processes enabled by RSA key pairs. These keypairs can be seen, subjectively, as a more personal and decentralized identity-proving mechanism. You can create your own with `gpg --key-gen`. A key pair consists of:
- A public key: You disclose this to the Internet. People can encrypt data with it. Said data can only be decrypted with this key's corresponding private key.
- A private key: You keep this secret. You use this to decrypt data. Said data must have been encrypted with this key's corresponding public key. You can also use this to digitally sign data.
<br>
<br>

As an example, Alice publishes `program.exe`. Another administrator, Mallory, wants to swap `program.exe` for a trojan horse. Alice is aware of this, so she computes the SHA-256 hash of her program, creates a message that includes that hash, signs it, and offers it for download too, as `program.exe.sig`. This file looks like this:

{% highlight bash %}
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

Hi guys,

The SHA-256 hash for program.exe is:
6c58bc00fea09c8d7fdb97c7b58741ad37bd7ba8e5c76d35076e3b57071b172b

Make sure to verify this, I dont trust the other administrators.
-----BEGIN PGP SIGNATURE-----
Version: GnuPG v1

iQEcBAEBCAAGBQJX5wG4AAoJEI7X0Hkx3674GsQIAKLzAVqC5vIrvxdVze9GWzIY
3rimodkcesmxCLwgx1TRZ5bsCPp8OP7mlSbd/CAM8Vy61Zto1IJ209dRojdtMoUp
Tj41IZF3ke2q2LhOxmSacEGtjMtkndLI1KhJtF5hALQj3Kydzy9sxmHFSbJymFSd
D0YIancB8KJs6ZZfpSZCtmDMjOcQ8OGxr6/+mHFVe+g5skLfB6EPqhXOffWzirRx
p1E86j+AuY08GhQU8Nl0/mIPADGIiT2F07hEf6OPTZtFZsUiK8sCWOLi45iRDTvV
BwTy32nmzBLHAqpUiTAZSnKR3sArbtTXzC9+20ZyydKxdch/l4Xz/SJW2JhLal8=
=n7Pd
-----END PGP SIGNATURE-----
{% endhighlight %}

Alice's friends already have her public key, since she wrote it down for them in person. For them, TLS in the SP server is redundant for <i>authenticity</i> purposes since they can already verify that the signed message comes from Alice thanks to GPG. Sharing public keys in person is not practical either. This <i>impracticality</i> problem is approached by trust models such as the <a href="https://en.wikipedia.org/wiki/Web_of_trust" target="_blank">web of trust</a>, but this is beyond the scope of this post.
<br>

Alice's friends need only to verify the authenticity of this signature by using `gpg --verify`. If the message is authentic, they can download `program.exe`, compute its SHA-256 hash, and compare it with the one in the signature. If they match, they can be sure that they are dealing with the original file and not a trojan horse.
<br>

Had Mallory changed the hash in `program.exe.sig`, the authenticity check done by Alice's friends would have failed, since the PGP signature wouldn't match with the contents of `program.exe.sig`. Had Mallory swapped `program.exe.sig` completely, Alice's friends would have noticed that the file was not signed by Alice's private key, therefore she wasn't the author.
<br>

In practice, operating systems come with the public keys of their developers and security teams already pre-installed. The operating system, aiming to protect itself, will use these keys to verify the updates it automatically downloads. Consider Ubuntu and <a href="https://en.wikipedia.org/wiki/Advanced_Packaging_Tool" target="_blank">`apt`</a>. Every fresh install comes with a couple of pre-installed keys, which can be listed with `apt-key list`. If you delete these keys, the next time you run `apt-get update` you'll rightfully get an error message saying that `apt` couldn't verify the resources downloaded from Ubuntu's package servers.
<br>

Additional public keys can be downloaded via traditional HTTP and via the HTTP Keyserver Protocol (HKP, which has a popular implementation called <a href="https://bitbucket.org/skskeyserver/sks-keyserver/wiki/Home" target="_blank">sks-keyserver</a>), with `gpg --recv-keys`; this last one being the default protocol for `gpg` versions 1.4.18 (used by Debian Jessie stable) and 1.4.20 (used by Ubuntu Xenial). This is an interesting case because section 8 of <a href="https://tools.ietf.org/html/draft-shaw-openpgp-hkp-00" target="_blank">HKP's draft specification</a> states the following:

>Without some sort of trust relationship between the client and server, information returned from a keyserver in search results cannot be trusted by the client until the OpenPGP client actually retrieves and checks the key for itself.  This is important and must be stressed: without a specific reason to treat information otherwise, all search results must be regarded as untrustworthy and informational only.

The last part refers to multiple checks done by <code clas="inline">gpg`: From <a href="https://en.wikipedia.org/wiki/Cyclic_redundancy_check" target="_blank">CRC checks</a> to comparing the downloaded key to the requested one.
<br>

As an example, consider the following command which downloads the public key for `cdimage@ubuntu.com`, used by Ubuntu to sign its ISO files (as stated in <a href="https://www.ubuntu.com/download/how-to-verify" target="_blank">Ubuntu's ISO-verification guide</a>):

{% highlight bash %}
gpg --keyserver hkp://keyserver.ubuntu.com \\
    --recv-keys "8439 38DF 228D 22F7 B374 2BC0 D94A A3F0 EFE2 1092"
{% endhighlight %}

An HTTP GET request made by `gpg` will eventually fetch the following resource from Ubuntu's keyserver on port 11371: `/pks/lookup?op=get&options=mr&search=0x843938DF228D22F7B3742BC0D94AA3F0EFE21092`. If an attacker were to swap the public key while it was being transferred, `gpg` would discard it and output the following error, where `XXXXXXXX` is the short ID of the attacker's public key:

{% highlight bash %}
gpg: requesting key EFE21092 from hkp server keyserver.ubuntu.com
gpg: key XXXXXXXX: rejected by import filter
gpg: Total number processed: 1
{% endhighlight %}

This scenario is possible due to the lack of TLS between `gpg` and the keyserver. This is the default behaviour in `gpg` versions 1.4.18 (used by Debian Jessie stable) and 1.4.20 (used by Ubuntu Xenial). Newer versions support TLS (HKPS), which doesn't have this problem. Even if `gpg` understands that the key is invalid, there's still the chance of a specially-crafted key triggering unexpected behaviour when being parsed; this is certainly unwanted.

<br>
<hr>
<br>
### The usefulness of jointly using TLS and RSA keypairs

Offering your program, public key, and signed message on the same server using TLS will protect you from external agents. The following truth table shows when a download can be considered safe from their attacks, assuming the user is proactive and tries to verify the program:
<br>

<table border="0">
<tr style="background:green;border:1"><th>Case</th><th>Genuine Program</th><th>Genuine Key</th><th>Genuine Signature</th><th>Secure</th></tr>
<tr><td>1</td><td>T</td><td>T</td><td>T</td><td>T</td></tr>
<tr style="background:#6e6969"><td>2</td><td>T</td><td>T</td><td>F</td><td>T</td></tr>
<tr><td>3</td><td>T</td><td>F</td><td>T</td><td>T</td></tr>
<tr style="background:#6e6969"><td>4</td><td>T</td><td>F</td><td>F</td><td>T</td></tr>
<tr><td>5</td><td>F</td><td>T</td><td>T</td><td>T</td></tr>
<tr style="background:#6e6969"><td>6</td><td>F</td><td>T</td><td>F</td><td>T</td></tr>
<tr><td>7</td><td>F</td><td>F</td><td>T</td><td>T</td></tr>
<tr style="background:#6e6969"><td>8</td><td>F</td><td>F</td><td>F</td><td style="background:#df795f;color:black">F</td></tr>
</table>

After introducing a public key and a signed message into the equation, cases 5 to 7 provide a way to download a program from an insecure medium and still be able to know if it's authentic or not. Case 8 fails in every possible aspect: Every file can be swapped for a specially crafted one. An attacker could swap the program for malware, the public key for his own, and its corresponding signed message for verifying the malware file.
<br>

If an SP doesn't provide a public key and signature, their absence can be considered to be an `F` in the above table. Having stated this, case 8 is not hard to find.

<br>
<hr>
<br>
### Footnotes
When validating a certificate, even though Firefox checks the validity of its issuing organization first, this post describes this process backwards for the sake of simplicity.
