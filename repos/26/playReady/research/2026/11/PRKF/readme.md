# PRKF

~~~
C:\Users\Steven\AppData\Local\Microsoft\Edge\User Data\Default\
MediaFoundationCdmStore\x86_64\0123456789ABCDEF0123456789ABCDEF\
com.microsoft.playready\Cache\msprcore.bla
~~~

https://packetstorm.news/files/id/208299

I am trying to generate client identity, as shown in the documents. I assume
this is derived from fake.sig.prv.plain using normal methods:

fake.sig.pub       - ECC signing key (public component)

these are embedded as is in msprcore.bla:

- fake.cert          - PlayReady Identity Certificate Chain
- fake.sig.prv       - ECC signing key (encrypted private component)

and this is derived by decrypting fake.sig.prv:

fake.sig.prv.plain - ECC signing key (plaintext private component)

what I need is:

1. how to extract fake.cert from msprcore.bla
2. how to extract fake.sig.pub from msprcore.bla
3. how to extract fake.sig.prv from msprcore.bla
4. how to decrypt fake.sig.prv

I have these files from the documents:

- msprcore.bla
- fake.cert
- fake.sig.prv
- fake.sig.prv.plain
- fake.sig.pub
