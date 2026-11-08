# ============ setup-prindiv.ps1 ============
# Complete PrIndivHelper setup - fresh machine edition.
# Run as Administrator. Uses only in-box tools (no SDK, no pip).

$ErrorActionPreference = "Stop"

$pkgDir  = "D:\Desktop\PrPkg"        # adjust if no D: drive
$gacMsil = "$env:WINDIR\Microsoft.NET\assembly\GAC_MSIL"
$wm      = "$env:WINDIR\System32\WinMetadata"

# 1. Directories
New-Item -ItemType Directory -Path $pkgDir -Force | Out-Null
New-Item -ItemType Directory -Path "$pkgDir\Assets" -Force | Out-Null
Write-Host "[+] Directories ready: $pkgDir"

# 2. Developer Mode
$devKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock"
if (-not (Test-Path $devKey)) { New-Item -Path $devKey -Force | Out-Null }
Set-ItemProperty -Path $devKey -Name "AllowDevelopmentWithoutDevLicense" -Value 1 -Type DWord
Write-Host "[+] Developer Mode enabled"

# 3. Logos
Add-Type -AssemblyName System.Drawing
foreach ($size in 44,150) {
    $p = "$pkgDir\Assets\logo$size.png"
    if (-not (Test-Path $p)) {
        $bmp = New-Object System.Drawing.Bitmap($size,$size)
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.Clear([System.Drawing.Color]::Black); $g.Dispose()
        $bmp.Save($p,[System.Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
    }
}
Write-Host "[+] Logos created"

# 4. Helper source (v6)
$src = @'
using System;
using System.IO;
using System.Threading;
using Windows.Foundation;
using Windows.Storage;
using Windows.Media.Protection.PlayReady;

class PrIndiv
{
    static string _log;
    static void W(string s)
    {
        try { File.AppendAllText(_log, DateTime.Now.ToString("HH:mm:ss.fff") + "  " + s + "\r\n"); } catch {}
        try { Console.WriteLine(s); } catch {}
    }

    static int Main()
    {
        _log = Path.Combine(Path.GetTempPath(), "pr-indiv-log.txt");
        try { File.Delete(_log); } catch {}

        W("[*] PrIndiv v6 starting");

        string goFile = Path.Combine(Path.GetTempPath(), "go.txt");
        W("[*] WAITING for go signal: " + goFile);
        DateTime deadline = DateTime.UtcNow.AddSeconds(180);
        while (!File.Exists(goFile) && DateTime.UtcNow < deadline)
            Thread.Sleep(250);
        if (File.Exists(goFile)) { try { File.Delete(goFile); } catch {} W("[+] Go signal received"); }
        else W("[!] Timed out - proceeding anyway");

        try
        {
            try
            {
                var req = (System.Net.HttpWebRequest)System.Net.WebRequest.Create("https://example.com");
                req.Timeout = 15000;
                var resp = (System.Net.HttpWebResponse)req.GetResponse();
                W("[+] Net test: HTTP " + (int)resp.StatusCode + " from example.com");
                resp.Close();
            }
            catch (Exception e0) { W("[!] Net test failed: " + e0.Message); }

            var appData = ApplicationData.Current;
            W("[+] Package identity OK. LocalCache: " + appData.LocalCacheFolder.Path);

            var cont = appData.LocalSettings.CreateContainer("PlayReady",
                ApplicationDataCreateDisposition.Always);
            cont.Values["SoftwareOverride"] = 1;
            W("[+] SoftwareOverride = 1 -> SWDRM PlayReady stack forced");

            string prDir = Path.Combine(appData.LocalCacheFolder.Path, "PlayReady");
            if (Directory.Exists(prDir))
            {
                try { Directory.Delete(prDir, true); W("[+] Cleared prior PlayReady store"); }
                catch (Exception e) { W("[!] Could not clear store: " + e.Message); }
            }

            var indiv = new PlayReadyIndividualizationServiceRequest();
            W("[+] Constructor OK - SWDRM path active");

            W("[*] BeginServiceRequest()...");
            IAsyncAction action = indiv.BeginServiceRequest();

            var done = new ManualResetEvent(false);
            AsyncStatus finalStatus = AsyncStatus.Started;
            action.Completed = new AsyncActionCompletedHandler(
                (a, s) => { finalStatus = s; done.Set(); });

            if (!done.WaitOne(120000))
            {
                W("[!] Timed out after 120s");
            }
            else
            {
                W("[+] Finished. AsyncStatus: " + finalStatus);
                if (finalStatus == AsyncStatus.Error)
                {
                    try
                    {
                        object ecode = action.ErrorCode;
                        W("[!] ErrorCode raw : " + ecode);
                        Exception e4 = ecode as Exception;
                        if (e4 != null)
                            W("[!] ErrorCode HR   : 0x" + e4.HResult.ToString("X8"));
                    }
                    catch (Exception e3) { W("[!] ErrorCode read failed: " + e3.Message); }
                }
            }

            var next = indiv.NextServiceRequest();
            W(next == null ? "[+] NextServiceRequest = null -> chain complete"
                           : "[*] NextServiceRequest returned: " + next.GetType().FullName);

            try { W("[*] Cert security level: " + PlayReadyStatics.PlayReadyCertificateSecurityLevel + "  (>0 = individualized, <3000 = SWDRM)"); }
            catch (Exception e2) { W("[*] Security level n/a: " + e2.Message); }

            if (Directory.Exists(prDir))
            {
                foreach (string f in Directory.GetFiles(prDir))
                {
                    long len = 0;
                    try { len = new FileInfo(f).Length; } catch {}
                    W("    store file: " + Path.GetFileName(f) + " (" + len + " bytes)");
                }
            }
            else { W("[*] Store dir not created"); }
        }
        catch (Exception e)
        {
            W("[!] FAILED: " + e.GetType().FullName);
            W("    Message : " + e.Message);
            W("    HResult : 0x" + e.HResult.ToString("X8"));
            var ie = e.InnerException; int d = 1;
            while (ie != null)
            {
                W("    inner[" + d + "]: " + ie.GetType().FullName + " : " + ie.Message + "  HR=0x" + ie.HResult.ToString("X8"));
                ie = ie.InnerException; d++;
            }
        }
        W("[*] Done. Log: " + _log + "  (window stays open 60s)");
        Thread.Sleep(60000);
        return 0;
    }
}
'@
Set-Content -Path "$pkgDir\PrIndiv.cs" -Value $src -Encoding UTF8
Write-Host "[+] Source written (v6)"

# 5. References
$refPaths = @()
foreach ($name in @("System.Runtime","System.Collections","System.Linq",
                    "System.ObjectModel","System.Threading.Tasks","System.IO")) {
    $dll = Get-ChildItem "$gacMsil\$name" -Recurse -Filter "$name.dll" -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName
    if ($dll) { $refPaths += $dll } else { Write-Host "[!] Facade not found: $name" }
}
foreach ($w in @("Windows.Foundation.winmd","Windows.Media.winmd","Windows.Storage.winmd")) {
    if (-not (Test-Path "$wm\$w")) { throw "Missing $wm\$w" }
    $refPaths += "$wm\$w"
}
Write-Host "[+] References resolved: $($refPaths.Count) assemblies"

# 6. Compile
$csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$refArgs = @(); foreach ($r in $refPaths) { $refArgs += "/r:$r" }
& $csc /nologo /out:"$pkgDir\PrIndiv.exe" $refArgs "$pkgDir\PrIndiv.cs"
if ($LASTEXITCODE -ne 0) { throw "csc compile failed ($LASTEXITCODE)" }
Write-Host "[+] Compiled: $pkgDir\PrIndiv.exe"

# 7. Manifest
$manifest = @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
  <Identity Name="PrIndivHelper" Publisher="CN=PrIndivHelper" Version="1.0.0.6" ProcessorArchitecture="x64"/>
  <Properties>
    <DisplayName>PrIndivHelper</DisplayName>
    <PublisherDisplayName>Research</PublisherDisplayName>
    <Logo>Assets\logo44.png</Logo>
  </Properties>
  <Resources><Resource Language="en-us"/></Resources>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.26100.0"/>
  </Dependencies>
  <Capabilities>
    <Capability Name="internetClient"/>
    <rescap:Capability Name="runFullTrust"/>
  </Capabilities>
  <Applications>
    <Application Id="App" Executable="PrIndiv.exe" EntryPoint="Windows.FullTrustProcess">
      <uap:VisualElements DisplayName="PrIndivHelper"
                          Description="PlayReady individualization research helper"
                          BackgroundColor="#1e1e1e"
                          Square150x150Logo="Assets\logo150.png"
                          Square44x44Logo="Assets\logo44.png"/>
    </Application>
  </Applications>
</Package>
'@
Set-Content -Path "$pkgDir\AppxManifest.xml" -Value $manifest -Encoding UTF8
Write-Host "[+] Manifest written"

# 8. Register + loopback exemption
Get-AppxPackage PrIndivHelper -ErrorAction SilentlyContinue | Remove-AppxPackage
Add-AppxPackage -Register "$pkgDir\AppxManifest.xml"
$pkg = Get-AppxPackage PrIndivHelper
Write-Host ("[+] Registered. PFN: {0}" -f $pkg.PackageFamilyName)
C:\Windows\System32\CheckNetIsolation.exe LoopbackExempt -a -n=$($pkg.PackageFamilyName) | Out-Null
Write-Host "[+] Loopback exemption applied"

Write-Host "`n==================== SETUP COMPLETE ===================="
Write-Host ("  PFN: {0}" -f $pkg.PackageFamilyName)
Write-Host "  Next: run .\run-capture.ps1 (see instructions)"
Write-Host "========================================================="
