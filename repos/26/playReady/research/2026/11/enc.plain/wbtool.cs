// wbtool.cs — decrypt all Warbird segment descriptors in a loaded image, dump it
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

class WBTool {
  [DllImport("kernel32", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr LoadLibraryW(string p);
  [DllImport("ntdll")]
  static extern int NtQuerySystemInformation(int cls, IntPtr si, int len, IntPtr ret);

  static uint U32(byte[] d, int o) { return BitConverter.ToUInt32(d, o); }

  static int Dec(IntPtr img, long segdesc, long relocs, long num) {
    IntPtr a = Marshal.AllocHGlobal(0x30);
    try {
      for (int i = 0; i < 0x30; i += 8) Marshal.WriteInt64(a, i, 0);
      Marshal.WriteInt64(a, 0x00, 1);
      Marshal.WriteInt64(a, 0x08, segdesc);
      Marshal.WriteInt64(a, 0x10, img.ToInt64());
      Marshal.WriteInt64(a, 0x18, img.ToInt64());
      Marshal.WriteInt64(a, 0x20, relocs);
      Marshal.WriteInt64(a, 0x28, num);
      return NtQuerySystemInformation(0xB9, a, 0x30, IntPtr.Zero);
    } finally { Marshal.FreeHGlobal(a); }
  }

  static void Main(string[] args) {
    string path = args.Length > 0 ? args[0] : @"C:\Windows\System32\Windows.Media.Protection.PlayReady.dll";
    byte[] f = File.ReadAllBytes(path);
    int lf = BitConverter.ToInt32(f, 0x3C);
    int nsec = BitConverter.ToUInt16(f, lf + 6);
    int optsz = BitConverter.ToUInt16(f, lf + 20);
    uint sizeImg = U32(f, lf + 24 + 56);
    int stab = lf + 24 + optsz;

    long[][] secs = new long[nsec][];
    for (int i = 0; i < nsec; i++) {
      int o = stab + i * 40;
      secs[i] = new long[] { U32(f, o + 12), U32(f, o + 8), U32(f, o + 20), U32(f, o + 16) };
    }

    List<long[]> list = new List<long[]>();
    using (SHA256 sha = SHA256.Create()) {
      for (int s = 0; s < nsec; s++) {
        int b0 = (int)secs[s][2], n = (int)secs[s][3];
        for (int off = 0; off + 0x40 <= n; off += 4) {
          uint size = U32(f, b0 + off + 0x20);
          if (size < 0x40 || size > 0x2000 || off + size > n) continue;
          byte[] dig = sha.ComputeHash(f, b0 + off + 0x20, (int)size - 0x20);
          bool ok = true;
          for (int k = 0; k < 32; k++) if (dig[k] != f[b0 + off + k]) { ok = false; break; }
          if (!ok) continue;
          list.Add(new long[] { secs[s][0] + off, size });
        }
      }
    }

    IntPtr img = LoadLibraryW(path);
    if (img == IntPtr.Zero) { Console.WriteLine("LoadLibrary failed " + Marshal.GetLastWin32Error()); return; }
    long ib = img.ToInt64();

    StringBuilder log = new StringBuilder();
    log.AppendLine("file " + path);
    log.AppendLine(string.Format("base 0x{0:x}  sizeOfImage 0x{1:x}  descriptors {2}", ib, sizeImg, list.Count));

    int okN = 0, badN = 0;
    foreach (long[] d in list) {
      if (d[1] == 0xF0) continue;
      int fo = -1;
      for (int s = 0; s < nsec; s++)
        if (d[0] >= secs[s][0] && d[0] < secs[s][0] + secs[s][3]) { fo = (int)(secs[s][2] + (d[0] - secs[s][0])); break; }
      if (fo < 0) { log.AppendLine(string.Format("desc 0x{0:x} unmapped", d[0])); continue; }
      long rel = U32(f, fo + 0x2C), num = U32(f, fo + 0x30);
      int r = Dec(img, ib + d[0], rel == 0 ? 0 : ib + rel, num);
      if (r == 0) okN++; else badN++;
      log.AppendLine(string.Format("desc 0x{0:x} size 0x{1:x} rel 0x{2:x}/{3} res 0x{4:x8}",
        d[0], d[1], rel, num, r));
    }
    log.AppendLine(string.Format("decrypted ok {0}  fail {1}", okN, badN));

    byte[] buf = new byte[sizeImg];
    Marshal.Copy(img, buf, 0, (int)sizeImg);
    File.WriteAllBytes("wbtool_img.bin", buf);
    File.WriteAllText("wbtool.txt", log.ToString());
    Console.WriteLine("ok {0} fail {1}  -> wbtool.txt, wbtool_img.bin", okN, badN);
  }
}
