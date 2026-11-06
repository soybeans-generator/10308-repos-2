# Widevine

> Theatricality and deception, powerful agents to the uninitiated. But we are
> initiated, aren't we, Bruce?
>
> — *The Dark Knight Rises* (2012)

A Widevine implementation. The first Widevine commit landed on **May 21, 2022**:

- [`9d3dff5` — gucio321/mech](https://github.com/gucio321/mech/commit/9d3dff51fbfe8e9ceec5db8d328b7da7434953dc)

**Background reading**

- <https://wikipedia.org/wiki/Digital_rights_management>
- <https://wikipedia.org/wiki/Widevine>

## wvdumper/dumper

**1 — Create an Android virtual device.** Install [Android Studio][1], then create an AVD with:

| Setting | Value |
| --- | --- |
| **ABI** | `x86` |
| **API level** | `24` |
| **Target** | Android 7.0 (Google APIs) |

**2 — Install Widevine Dumper.** Download [Widevine Dumper][2], then install its dependencies:

```bash
pip install -r requirements.txt
```

**3 — Set up Frida server.** Download [Frida server][3]. Example artifact:

```text
frida-server-15.1.17-android-x86.xz
```

Start it on the device:

```bash
adb root
adb push frida-server-15.1.17-android-x86 /data/frida-server
adb shell chmod +x /data/frida-server
adb shell /data/frida-server
```

**4 — Trigger a key dump.** Launch **Chrome** on the emulator and open [Shaka Player][4]. Click the green play button. If this prompt appears:

> `bitmovin.com` wants to play protected content. Your device's identity will be verified by Google.

…click **ALLOW**. Then start the dumper:

```powershell
$env:PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION = 'python'
python dump_keys.py
```

Once you see `Hooks completed`, return to Chrome and click the green play button again. Result:

```text
2022-05-21 02:10:52 PM - Helpers.Scanner - 49 - INFO - Key pairs saved at
key_dumps\Android Emulator 5554/private_keys/4464/2770936375
```

[1]: https://developer.android.com/studio
[2]: https://github.com/wvdumper/dumper
[3]: https://github.com/frida/frida/releases
[4]: https://integration.widevine.com/player

## where did proto file come from?

```text
media_cas_proxy_sdk\ubuntu\protos\public
```

## other tools

- <https://github.com/Jnzzi/4464_L3-CDM>
- <https://github.com/FoxRefire/wvg>
- <https://github.com/hyugogirubato/KeyDive>
- <https://github.com/search?q=L3+CDM>

## contact

| Channel | Details |
| --- | --- |
| **Email** | `27@riseup.net` |
| **Discord username** | `10308` |
| **Discord invite** | <https://discord.com/invite/rMFzDRQhSx> |
