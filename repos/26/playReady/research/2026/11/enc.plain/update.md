# update

thought id jump in here, as i saw this in your readme 

```
The kernel honours only ONE heap-exec decrypt per loaded image. Decrypting a
second block in the same image appears to succeed (res 0) but leaves the code
unchanged. A fresh LoadLibraryW is mandatory per heap-exec block.
```

this is wrong, if you use the same offset as your descriptor it returns as 0
but does nothing as it assumes its already decrypted

```
Only s4 is live for this build's key format. Patching the other seven produces
sixteen identical outputs — the signal used to rule them out.
```

this is because the encryption key  has different paths it goes down depending
on opcode (encrypted_key[65] % 3) and is expected, also shows why your nibble
map was different than adam gowdiaks
