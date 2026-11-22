# unext

1. unext.jp
2. 31 days now free trial
3. Japan VPN
4. get started now
5. last name
   - スティーブン
6. first name
   - ペニー
7. year
8. month
9. date
10. e-mail
   - mail.tm
11. password
12. phone
   - 0312345678
13. next
14. card number - NEW CARD EACH TIME
15. name of card
16. month
17. year
18. security code
19. disable uBlock Origin
20. start using
21. not to add family account
22. to u-next home

## jp.unext.tv.player

https://play.google.com/store/apps/details?id=jp.unext.tv.player

## jp.unext.mediaplayer

- https://apkpure.com/u-next／ユーネクスト：映画、ドラマ、アニメなどが見放題/jp.unext.mediaplayer
- https://play.google.com/store/apps/details?id=jp.unext.mediaplayer

~~~
package: name='jp.unext.mediaplayer' versionCode='57100' versionName='5.71.0'
compileSdkVersion='37' compileSdkVersionCodename='17'
sdkVersion:'32'
  uses-feature: name='android.hardware.faketouch'
~~~

Create Pixel 5, API 32 device. install system certificate

Black Button:
Log in

~~~
adb shell pm clear jp.unext.mediaplayer
~~~

then:

~~~
adb install-multiple (Get-ChildItem *.apk)
~~~

then:

~~~
adb shell input text HELLO
~~~

Osaka is blocked but Tokyo works - I was tricked because the Osaka error is weird

~~~
mitmproxy --mode upstream:http://isp.decodo.com:10001 --set upstream_auth=USERNAME:PASSWORD

emulator -avd Pixel_5 -http-proxy http://127.0.0.1:8080

adb root
adb shell "sysctl -w net.ipv6.conf.all.disable_ipv6=1"
~~~
