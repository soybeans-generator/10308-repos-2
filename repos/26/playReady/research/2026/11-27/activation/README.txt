README.txt

# Microsoft Warbird and PMP security research
# (c) Security Explorations    2008-2024 Poland
# (c) AG Security Research     2019-2024 Poland

This package illustrates the result of an arbitrary fake Windows 10
PlayReady client identity generation.

Files description:
* msprcore.bla       - Windows PlayReady Key File (PRKF)
* fake.cert          - PlayReady Identity Certificate Chain
* fake.sig.pub       - ECC signing key (public component)
* fake.sig.prv       - ECC signing key (encrypted private component)
* fake.sig.prv.plain - ECC signing key (plaintext private component)

The following structure embedded in a leaf client certificate carries
fake unique system ID data:

2E size
 F1 22 3E B6 1D 59 DB 01         = 28-12-2024 12:43:28 (file time)
  26 size
   00 00 00 00 00 00 00 01 00 00
   00 00 00 02 00 00 00 01 00 01
   00 01 00 96 7D 00 00 
   46 41 4B 45 2E 50 52 2E 49 44 = "FAKE.PR.ID"  (HW / MF system id)

The following carries proof for ECC signing key compromise (partial
identity compromise):

msprcp> checkkeypair fake.sig.prv.plain fake.sig.pub
KEY CHECK:

- prv: a046c304e4d7a4e7650f979b7e2196dbbf42f8af90ae25c47b7b584a9d62739
- pub:
  X: 9692e26d8638645d37c80cf7343cb7252140e9f607a0a310534dde7a684fe6d6
  Y: 197dd2a496da0a9e8f8b3da6767cf6e117c71468d08eaf8483651a685b7d0a34
KEY CHECK OK
