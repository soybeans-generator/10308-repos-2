# draken

## account

1. sweden VPN/proxy
2. drakenfilm.se/offers
3. Draken Film – Bas
   - try it free for 14 days
   - activate now
4. your email address
   - 2timemail.com
5. continue
6. password
7. repeat password
8. I agree to the terms
9. create account
10. card number
11. expiration date
12. security code
13. name of card
14. postcode
15. save card details

## web

Magine-Accesstoken is hard coded in the JavaScript

## android

https://play.google.com/store/apps/details?id=com.draken.android

then:

https://apkcombo.com/draken-film/com.draken.android

armeabi-v7a so need Android 9. install system certificate. Magine-AccessToken
in the APK:

~~~java
@Override // wc.b
public String a() {
  return "22cc71a2-8b77-4819-95b0-8c90f4cf5663";
}

@Override // wc.b
public String b() {
  return "ea6fc0bb-8352-4bd6-9c4d-040a2c478fe8";
}
~~~

then:

~~~
~/.android/avd/Pixel_XL.avd/emulator-user.ini
~~~

to:

~~~
window.x = 0
window.y = 0
~~~

https://stackoverflow.com/questions/78813238

~~~
adb install-multiple (Get-ChildItem *.apk)
~~~

then:

~~~
adb shell input text HELLO
~~~
