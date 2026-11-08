using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Windows.ApplicationModel;
using Windows.Foundation;
using Windows.Management.Deployment;
using Windows.Media.Protection.PlayReady;
using Windows.Storage;

static class PrIndiv
{
   static string _log;

   static void W(string s)
   {
      try { File.AppendAllText(_log, s + "\r\n"); } catch { }
      try { Console.WriteLine(s); } catch { }
   }

   [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
   static extern int GetCurrentPackageFamilyName(ref int len, StringBuilder name);

   static int Main()
   {
      _log = Path.Combine(Path.GetTempPath(), "prindiv.log");
      try { File.Delete(_log); } catch { }

      try
      {
         return Run();
      }
      catch (Exception e)
      {
         W("[x] CRASH: " + e.GetType().FullName);
         W("    " + e.Message);
         W("    0x" + e.HResult.ToString("X8"));
         W(e.StackTrace);
         return 1;
      }
   }

   static int Run()
   {
      if (FamilyName() == null)
         return Register();

      W("[+] identity: " + FamilyName());

      try
      {
         ApplicationDataContainer c = ApplicationData.Current.LocalSettings
            .CreateContainer("PlayReady", ApplicationDataCreateDisposition.Always);
         c.Values["SoftwareOverride"] = 1;
         W("[+] SoftwareOverride = 1");
      }
      catch (Exception e)
      {
         W("[x] " + e.Message + "  0x" + e.HResult.ToString("X8"));
         return 1;
      }

      string src = Path.Combine(ApplicationData.Current.LocalCacheFolder.Path, "PlayReady");
      if (Directory.Exists(src))
      {
         try { Directory.Delete(src, true); W("[+] cleared old store"); }
         catch (Exception e) { W("[!] clear: " + e.Message); }
      }

      try
      {
         IPlayReadyServiceRequest req = new PlayReadyIndividualizationServiceRequest();
         while (req != null)
         {
            W("[*] individualizing - network round trip, this takes ~10s...");
            IAsyncAction act = req.BeginServiceRequest();

            AsyncStatus st = AsyncStatus.Started;
            using (var done = new ManualResetEvent(false))
            {
               act.Completed = new AsyncActionCompletedHandler(
                  delegate(IAsyncAction a, AsyncStatus s) { st = s; done.Set(); });
               if (!done.WaitOne(120000)) { W("[x] timeout"); return 3; }
            }

            if (st != AsyncStatus.Completed)
            {
               Exception ex = act.ErrorCode as Exception;
               W("[x] " + st + (ex != null
                  ? "  0x" + ex.HResult.ToString("X8") + "  " + ex.Message : ""));
               return 1;
            }
            W("[+] request completed");
            req = req.NextServiceRequest();
         }
         W("[+] chain complete");
      }
      catch (Exception e)
      {
         W("[x] " + e.Message + "  0x" + e.HResult.ToString("X8"));
         return 1;
      }

      try
      {
         W("[*] security level: " + PlayReadyStatics.PlayReadyCertificateSecurityLevel);
      }
      catch (Exception e) { W("[!] security level: " + e.Message); }

      if (!Directory.Exists(src))
      {
         W("[!] store was never created: " + src);
         return 1;
      }

      foreach (string f in Directory.GetFiles(src, "*", SearchOption.AllDirectories))
         W("    " + f + "  (" + new FileInfo(f).Length + " bytes)");

      return 0;
   }

   static int Register()
   {
      string dir = Path.GetDirectoryName(typeof(PrIndiv).Assembly.Location);
      PackageManager pm = new PackageManager();

      Console.WriteLine("[*] registering package...");
      try
      {
         IAsyncOperationWithProgress<DeploymentResult, DeploymentProgress> op =
            pm.RegisterPackageByUriAsync(
               new Uri(Path.Combine(dir, "AppxManifest.xml")),
               new RegisterPackageOptions { DeveloperMode = true });

         using (var done = new ManualResetEvent(false))
         {
            op.Completed = delegate(IAsyncOperationWithProgress<DeploymentResult, DeploymentProgress> o, AsyncStatus s)
               { done.Set(); };
            done.WaitOne();
            if (op.Status != AsyncStatus.Completed)
            {
               Exception err = op.ErrorCode as Exception;
               throw new Exception(err != null ? err.Message : "deployment failed");
            }
         }
         Console.WriteLine("[+] registered");
      }
      catch (Exception e)
      {
         Console.Error.WriteLine("[!] register: " + e.Message);
      }

      string pfn = FindFamilyName();
      if (pfn == null)
      {
         Console.Error.WriteLine("[x] not registered");
         return 1;
      }

      string store = Path.Combine(
         Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
         "Packages", pfn, "LocalCache", "PlayReady");

      Console.WriteLine("[*] bla will be: " + Path.Combine(store, "Cache", "msprcore.bla"));
      Console.WriteLine("[*] launching packaged instance...");

      System.Diagnostics.Process.Start("explorer.exe", "shell:AppsFolder\\" + pfn + "!App");
      return 0;
   }
   static string FindFamilyName()
   {
      try
      {
         foreach (Package p in new PackageManager().FindPackagesForUser(""))
            if (p.Id.Name == "PrIndivHelper") return p.Id.FamilyName;
      }
      catch { }
      return null;
   }

   static string FamilyName()
   {
      int len = 0;
      if (GetCurrentPackageFamilyName(ref len, null) == 15700) return null;
      StringBuilder sb = new StringBuilder(len);
      return GetCurrentPackageFamilyName(ref len, sb) == 0 ? sb.ToString() : null;
   }
}
