# Peacock PS4 TLS Capture

PC `192.168.0.12`, PS4 `192.168.0.11`, title `CUSA20387`, port `8080`. Run everything from `D:\Desktop`.

## 1. Get PC LAN IP

```powershell
ipconfig
```

## 2. Set PS4 proxy

`Settings → Network → Set Up Internet Connection → [connection] → Advanced Settings → Proxy Server → Use` — PC IP, port `8080`.

## 3. Confirm FTP

```powershell
curl.exe "ftp://192.168.0.11:2121/data/"
```

## 4. Pull cert bundle

Launch Peacock first. Save as `pull_app_certs.py`:

```python
from ftplib import FTP

HOST, PORT = '192.168.0.11', 2121
BASE = '/mnt/sandbox/pfsmnt/CUSA20387-app0-patch0-union/assets/ssl'
FILES = ['root-ca.pem', 'proxy-ca.pem', 'client-cert.pem', 'client-key.pem']

ftp = FTP()
ftp.connect(HOST, PORT, timeout=30)
ftp.login()
ftp.set_pasv(True)

for name in FILES:
    with open(name, 'wb') as f:
        ftp.retrbinary('RETR %s/%s' % (BASE, name), f.write)
    print('saved %-18s %8d bytes' % (name, len(open(name, 'rb').read())))

ftp.quit()
```

```powershell
python .\pull_app_certs.py
```

Expect `167735`, `167735`, `1965`, `1934`.

## 5. Build mTLS files from the PS4's own pair (untested)

```powershell
python -c "c=open('client-cert.pem','rb').read(); k=open('client-key.pem','rb').read(); d=c + (b'' if c.endswith(b'\n') else b'\n') + k; [open(h+'.pem','wb').write(d) for h in ('play.clients.peacocktv.com','tv.clients.peacocktv.com')]; print(len(d),'bytes each')"
```

Result must be `play.clients.peacocktv.com.pem` and `tv.clients.peacocktv.com.pem` in `D:\Desktop`.

**Not tested.** Only the Android TV pair was verified working. The PS4 pair may be rejected or scoped differently. If the handshake fails at step 11, this is the first suspect.

## 6. Kill the app

PS button → Close Application.

## 7. Copy mitmproxy CA

```powershell
Copy-Item "$env:USERPROFILE\.mitmproxy\mitmproxy-ca-cert.pem" .\mitm-ca.pem
```

## 8. Get AFR plugin

```powershell
curl.exe -L -o .\GoldPlugins.zip "https://github.com/GoldHEN/GoldHEN_Plugins_Repository/releases/download/1.210-998fe03f/GoldPlugins-1.210-998fe03f.zip"
Expand-Archive .\GoldPlugins.zip -DestinationPath .\GoldPlugins -Force
curl.exe -T .\GoldPlugins\plugins\afr.prx "ftp://192.168.0.11:2121/data/GoldHEN/plugins/afr.prx"
```

## 9. Upload patched bundles

Save as `install_afr.py`:

```python
from ftplib import FTP
from io import BytesIO

HOST, PORT = '192.168.0.11', 2121
TITLE = 'CUSA20387'

mitm = open('mitm-ca.pem', 'rb').read().strip() + b'\n'

ftp = FTP()
ftp.connect(HOST, PORT, timeout=30)
ftp.login()
ftp.set_pasv(True)

path = ''
for part in ['data', 'GoldHEN', 'AFR', TITLE, 'assets', 'ssl']:
    path += '/' + part
    try:
        ftp.mkd(path)
    except Exception:
        pass

for name in ['root-ca.pem', 'proxy-ca.pem']:
    data = open(name, 'rb').read()
    if not data.endswith(b'\n'):
        data += b'\n'
    data += mitm
    ftp.storbinary('STOR %s/%s' % (path, name), BytesIO(data))
    print('uploaded %-14s %8d bytes' % (name, len(data)))

ftp.quit()
```

```powershell
python .\install_afr.py
```

Expect `168907` each.

## 10. Enable loader, register AFR

Save as `enable_afr.py`:

```python
from ftplib import FTP
from io import BytesIO

HOST, PORT = '192.168.0.11', 2121
TITLE = 'CUSA20387'

ftp = FTP()
ftp.connect(HOST, PORT, timeout=30)
ftp.login()
ftp.set_pasv(True)

buf = BytesIO()
ftp.retrbinary('RETR /data/GoldHEN/config.ini', buf.write)
cfg = buf.getvalue().decode()
if 'PluginLoader_Enabled = 0' in cfg:
    cfg = cfg.replace('PluginLoader_Enabled = 0', 'PluginLoader_Enabled = 1')
    print('config.ini: PluginLoader_Enabled -> 1')
ftp.storbinary('STOR /data/GoldHEN/config.ini', BytesIO(cfg.encode()))

ini = '[default]\n\n[%s]\n/data/GoldHEN/plugins/afr.prx\n' % TITLE
ftp.storbinary('STOR /data/GoldHEN/plugins.ini', BytesIO(ini.encode()))
print('plugins.ini written')

ftp.quit()
```

```powershell
python .\enable_afr.py
```

`afr.prx` requires the `plugins.ini` entry.

## 11. Start capture

```powershell
mitmdump --listen-host 0.0.0.0 --listen-port 8080 --set client_certs=. -w peacock.flows
```

## 12. Activate

1. Restart PS4
2. Reload GoldHEN
3. Confirm step 11 running
4. Launch Peacock

```
GET https://tv.clients.peacocktv.com/... 200
GET https://play.clients.peacocktv.com/... 200
```
