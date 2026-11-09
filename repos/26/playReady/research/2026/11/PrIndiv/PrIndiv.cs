using System;
using System.IO;
using System.Threading;
using Windows.ApplicationModel;
using Windows.Foundation;
using Windows.Management.Deployment;
using Windows.Media.Protection.PlayReady;
using Windows.Storage;

static class PrIndiv
{
   static int Main()
   {
      try
      {
         ApplicationDataContainer c = ApplicationData.Current.LocalSettings
            .CreateContainer("PlayReady", ApplicationDataCreateDisposition.Always);
         c.Values["SoftwareOverride"] = 1;
      }
      catch (Exception e)
      {
         if (e.HResult != unchecked((int)0x80073D54))
         {
            Console.Error.WriteLine("[x] " + e.Message + "  0x" + e.HResult.ToString("X8"));
            return 1;
         }
         return Register();
      }

      string src = Path.Combine(ApplicationData.Current.LocalCacheFolder.Path, "PlayReady");
      if (Directory.Exists(src))
         Directory.Delete(src, true);

      IPlayReadyServiceRequest req = new PlayReadyIndividualizationServiceRequest();
      while (req != null)
      {
         Console.WriteLine("[*] individualizing...");
         IAsyncAction act = req.BeginServiceRequest();

         using (var done = new ManualResetEvent(false))
         {
            act.Completed = (a, s) => done.Set();
            done.WaitOne(120000);
         }

         if (act.Status != AsyncStatus.Completed)
         {
            Exception ex = act.ErrorCode as Exception;
            Console.Error.WriteLine("[x] " + (ex != null
               ? "0x" + ex.HResult.ToString("X8") + "  " + ex.Message : "incomplete"));
            return 1;
         }
         req = req.NextServiceRequest();
      }

      if (!Directory.Exists(src))
      {
         Console.Error.WriteLine("[!] no store: " + src);
         return 1;
      }

      foreach (string f in Directory.GetFiles(src, "*", SearchOption.AllDirectories))
         Console.WriteLine(f);

      return 0;
   }

   static int Register()
   {
      string dir = Path.GetDirectoryName(typeof(PrIndiv).Assembly.Location);
      PackageManager pm = new PackageManager();

      IAsyncOperationWithProgress<DeploymentResult, DeploymentProgress> op =
         pm.RegisterPackageByUriAsync(
            new Uri(Path.Combine(dir, "AppxManifest.xml")),
            new RegisterPackageOptions { DeveloperMode = true });

      using (var done = new ManualResetEvent(false))
      {
         op.Completed = (o, s) => done.Set();
         done.WaitOne();
      }

      if (op.Status != AsyncStatus.Completed)
      {
         Exception err = op.ErrorCode as Exception;
         Console.Error.WriteLine("[x] register: " + (err != null ? err.Message : "failed"));
         return 1;
      }

      string pfn = null;
      foreach (Package p in pm.FindPackagesForUser(""))
         if (p.Id.Name == "PrIndivHelper") pfn = p.Id.FamilyName;

      if (pfn == null)
      {
         Console.Error.WriteLine("[x] not found after register");
         return 1;
      }

      Console.WriteLine("[*] bla: " + Path.Combine(
         Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
         "Packages", pfn, "LocalCache", "PlayReady", "Cache", "msprcore.bla"));

      System.Diagnostics.Process.Start("explorer.exe", "shell:AppsFolder\\" + pfn + "!App");
      return 0;
   }
}
