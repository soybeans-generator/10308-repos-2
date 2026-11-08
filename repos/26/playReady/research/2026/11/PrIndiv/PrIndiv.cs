using System;
using System.IO;
using System.Threading;
using Windows.Foundation;
using Windows.Media.Protection.PlayReady;

static class PrIndiv
{
   static int Main()
   {
      try
      {
         IPlayReadyServiceRequest req = new PlayReadyIndividualizationServiceRequest();
         while (req != null)
         {
            IAsyncAction act = req.BeginServiceRequest();

            AsyncStatus st = AsyncStatus.Started;
            using (var done = new ManualResetEvent(false))
            {
               act.Completed = new AsyncActionCompletedHandler(
                  delegate(IAsyncAction a, AsyncStatus s) { st = s; done.Set(); });
               if (!done.WaitOne(120000)) { Console.Error.WriteLine("[x] timeout"); return 3; }
            }

            if (st != AsyncStatus.Completed)
            {
               Exception ex = act.ErrorCode as Exception;
               Console.Error.WriteLine("[x] " + st + (ex != null
                  ? "  0x" + ex.HResult.ToString("X8") + "  " + ex.Message : ""));
               return 1;
            }
            req = req.NextServiceRequest();
         }
      }
      catch (Exception e)
      {
         Console.Error.WriteLine("[x] " + e.Message + "  0x" + e.HResult.ToString("X8"));
         return 1;
      }

      Console.WriteLine(Path.Combine(
         Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
         "Microsoft", "PlayReady"));

      return 0;
   }
}
