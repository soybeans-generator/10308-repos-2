# Peacock TV

> When you find someone who had the same problem as you
>
> Joel Haver
> https://youtube.com/watch?v=hnUpTyKSjag

- https://apkmirror.com/apk/peacock-tv-llc/peacock-tv-android-tv
- https://play.google.com/store/apps/details?id=com.peacocktv.peacockandroid

create Pixel 5, APK lies you need at least API 31. install system certificate

~~~
emulator -avd Pixel_5 -no-snapshot-load -http-proxy http://127.0.0.1:8080
~~~

then:

~~~
adb install-multiple (Get-ChildItem *.apk)
~~~

then:

~~~
adb shell am force-stop com.peacocktv.peacockandroid
adb shell pm clear com.peacocktv.peacockandroid
~~~

## UHD

Peacock does offer certain content in 4K Ultra HD to Premium and Premium Plus
subscribers on some supported devices that are 4K Ultra HD compatible

https://peacocktv.com/help/article/4k-uhd
