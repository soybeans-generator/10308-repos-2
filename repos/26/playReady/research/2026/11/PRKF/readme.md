# PRKF

~~~
C:\Users\Steven\AppData\Local\Microsoft\Edge\User Data\Default\
MediaFoundationCdmStore\x86_64\0123456789ABCDEF0123456789ABCDEF\
com.microsoft.playready\Cache\msprcore.bla
~~~

## Microsoft Warbird and PMP Security Research

- <https://security-explorations.com/materials/wbpmp_doc.md.txt>
- https://packetstorm.news/files/id/182931

## Microsoft PlayReady Activation Protocol Issues

https://packetstorm.news/files/id/208299

## prompt

using the attached documents, I was able to create the attached scripts to
extract these from msprcore.bla:

- `*.sig.prv`
Obfuscated private ECC key component used for signing license requests
- `*.sig.pub`
Public ECC key component used for signing license requests

then I was able to create the attached scripts to create:

- `*.sig.plain`
Plaintext value of ECC key component used for signing license requests

I think all that is left is getting these:

- `*.enc.prv`
Obfuscated private ECC key component used for license blob encryption
- `*.enc.pub`
Public ECC key component used for license blob encryption
- `*.enc.plain`
Plaintext value of a private ECC key component used for license blob encryption

but I am not sure if that is in msprcore.bla or somewhere else
