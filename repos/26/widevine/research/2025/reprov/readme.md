# reprov

~~~
40001: "Widevine Device Certificate Revocation (wv 127)",
40002: "Widevine Device Certificate Revocation - Permanently (wv 175)",
~~~

the one in this folder is:

~~~
client max hdcp version = HDCP_V2_2
internal status = 127
make = Transsion
model = TECNO-CE9TEST
oem crypto api version = 16
platform = android
security level = 3
soc = Mediatek MT6785
status = ACCESS_DENIED
status message = device-certificate-revoked: 18167
system id = 18167
~~~

how to reprov? we need to find a keybox for one thats 127. cannot find. is the
keybox in `device_client_id_blob`?

https://github.com/zybpp/Python/tree/master/Python/keybox/keybox/X705M/widevine
