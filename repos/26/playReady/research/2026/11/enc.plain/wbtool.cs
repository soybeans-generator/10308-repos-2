// wbtool.cs — decrypt every Warbird segment in isolation, harvest into one image
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

class WBTool {
  [DllImport("kernel32", SetLastError=true, CharSet=CharSet.Unicode)] static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32")] static extern bool FreeLibrary(IntPtr h);
  [DllImport("kernel32")] static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint p, out uint o);
  [DllImport("ntdll")] static extern int NtQuerySystemInformation(int c, IntPtr si, int len, IntPtr r);

  const uint RWX = 0x40;
  static uint U32(byte[] b, int o) { return BitConverter.ToUInt32(b, o); }
  static void P32(byte[] b, int o, uint v) { b[o]=(byte)v; b[o+1]=(byte)(v>>8); b[o+2]=(byte)(v>>16); b[o+3]=(byte)(v>>24); }
  static bool Eq(byte[] a, int ao, byte[] b, int bo, int n) {
    for (int i = 0; i < n; i++) if (a[ao+i] != b[bo+i]) return false;
    return true;
  }
  static int Dec(IntPtr img, long d, long r, long n) {
    IntPtr a = Marshal.AllocHGlobal(0x30);
    try {
      for (int i = 0; i < 0x30; i += 8) Marshal.WriteInt64(a, i, 0);
      Marshal.WriteInt64(a, 0x00, 1);
      Marshal.WriteInt64(a, 0x08, d);
      Marshal.WriteInt64(a, 0x10, img.ToInt64());
      Marshal.WriteInt64(a, 0x18, img.ToInt64());
      Marshal.WriteInt64(a, 0x20, r);
      Marshal.WriteInt64(a, 0x28, n);
      return NtQuerySystemInformation(0xB9, a, 0x30, IntPtr.Zero);
    } finally { Marshal.FreeHGlobal(a); }
  }
  
  
    static void Main(string[] args) {
    string path = @"C:\Windows\System32\Windows.Media.Protection.PlayReady.dll";
    string outp = args.Length > 0 ? args[0] : "wbtool_img.bin";

    byte[] f = File.ReadAllBytes(path);
    int lf = BitConverter.ToInt32(f, 0x3C);
    int nsec = BitConverter.ToUInt16(f, lf + 6);
    int optsz = BitConverter.ToUInt16(f, lf + 20);
    uint sizeImg = U32(f, lf + 24 + 56);
    int stab = lf + 24 + optsz;
    var secs = new List<long[]>();
    for (int i = 0; i < nsec; i++) {
      int o = stab + i * 40;
      secs.Add(new long[] { U32(f,o+12), U32(f,o+8), U32(f,o+20), U32(f,o+16) });
    }
    Func<long,int> fileOff = rva => {
      foreach (var s in secs) if (rva >= s[0] && rva < s[0] + s[3]) return (int)(s[2] + (rva - s[0]));
      return -1;
    };

    var segs = new List<long[]>();
    var heaps = new List<long[]>();
    long sacRva = 0x6D8000;
    using (var sha = SHA256.Create()) {
      foreach (var s in secs) {
        int b0 = (int)s[2], len = (int)s[3];
        for (int off = 0; off + 0x40 <= len; off += 4) {
          uint size = U32(f, b0+off+0x20);
          if (size < 0x40 || size > 0x2000 || off + size > len) continue;
          byte[] dig = sha.ComputeHash(f, b0+off+0x20, (int)size - 0x20);
          if (!Eq(dig, 0, f, b0+off, 32)) continue;
          if (size == 0xF0)
            heaps.Add(new long[] { s[0]+off, b0+off,
                                   U32(f,b0+off+0x34) & 0x0FFFFFFF,
                                   U32(f,b0+off+0x38) & 0x0FFFFFFF });
          else
            segs.Add(new long[] { s[0]+off, b0+off, size });
        }
      }
    }

    byte[] img = new byte[sizeImg];
    Array.Copy(f, img, Math.Min(f.Length, img.Length));

    var log = new StringBuilder();
    log.AppendLine(string.Format("dll {0}", path));
    log.AppendLine(string.Format("sizeOfImage 0x{0:x}  segments {1}  heap-exec {2}", sizeImg, segs.Count, heaps.Count));

    {
      IntPtr h = LoadLibraryW(path);
      long ib = h.ToInt64();
      int ok = 0;
      foreach (var s in segs) {
        long rel = U32(f, (int)s[1] + 0x2C), num = U32(f, (int)s[1] + 0x30);
        if (Dec(h, ib + s[0], ib + rel, num) == 0) ok++;
      }
      for (int i = 0; i < sizeImg; i++) img[i] = Marshal.ReadByte((IntPtr)(ib + i));
      FreeLibrary(h);
      log.AppendLine(string.Format("segment descriptors {0} ok {1}", segs.Count, ok));
    }

    int done = 0, changed = 0, failed = 0;
    uint oldP = 0, dummy = 0;
    for (int i = 0; i < heaps.Count; i++) {
      var d = heaps[i];
      long codeRva = d[2], codeSz = d[3];
      if (codeRva == 0 || codeSz == 0 || codeRva + codeSz > sizeImg) { failed++; continue; }
      int fo = fileOff(codeRva);
      if (fo < 0) { failed++; continue; }
      byte[] enc = new byte[codeSz];
      Array.Copy(f, fo, enc, 0, (int)codeSz);

      IntPtr h = LoadLibraryW(path);
      if (h == IntPtr.Zero) { failed++; break; }
      long ib = h.ToInt64();
      IntPtr sac = (IntPtr)(ib + sacRva);
      byte[] sacOrig = new byte[0x100];
      Marshal.Copy(sac, sacOrig, 0, 0x100);
      VirtualProtect(sac, (UIntPtr)0x1000, RWX, out oldP);

      byte[] hexec = new byte[0xF0];
      Array.Copy(f, (int)d[1], hexec, 0, 0xF0);
      byte[] fake = new byte[0x100];
      Array.Copy(sacOrig, 0, fake, 0, 0x40);
      Array.Copy(hexec, 0x40, fake, 0x40, 0xF0 - 0x40);
      P32(fake, 0xF0, 1);
      P32(fake, 0xF4, 0x30C);
      P32(fake, 0xF8, (uint)codeRva);
      P32(fake, 0xFC, (uint)codeSz);
      using (var sha = SHA256.Create()) {
        byte[] dig = sha.ComputeHash(fake, 0x20, 0xE0);
        Array.Copy(dig, 0, fake, 0, 32);
      }
      Marshal.Copy(fake, 0, sac, 0x100);
      VirtualProtect(sac, (UIntPtr)0x1000, oldP, out dummy);

      long rel = U32(sacOrig, 0x2C), num = U32(sacOrig, 0x30);
      int res = Dec(h, ib + sacRva, ib + rel, num);

      byte[] got = new byte[codeSz];
      Marshal.Copy((IntPtr)(ib + codeRva), got, 0, (int)codeSz);
      FreeLibrary(h);

      if (res == 0) {
        Array.Copy(got, 0, img, codeRva, (int)codeSz);
        done++;
        if (!Eq(got, 0, enc, 0, (int)codeSz)) changed++;
        if (i < 4)
          log.AppendLine(string.Format("  [sample {0}] code 0x{1:x6}+0x{2:x} {3}",
            i, codeRva, codeSz, BitConverter.ToString(got, 0, Math.Min(16, (int)codeSz))));
      } else failed++;
      if ((i + 1) % 200 == 0) Console.WriteLine("  {0}/{1} ok {2}", i + 1, heaps.Count, done);
    }
    log.AppendLine(string.Format("heap-exec harvested {0}  changed {1}  failed {2}", done, changed, failed));

    log.AppendLine("probe 0x335460 " + BitConverter.ToString(img, 0x335460, 16));
    log.AppendLine("probe 0x337700 " + BitConverter.ToString(img, 0x337700, 16));
    log.AppendLine("probe 0x2b7cd0 " + BitConverter.ToString(img, 0x2b7cd0, 16));
    log.AppendLine("probe 0x523390 " + BitConverter.ToString(img, 0x523390, 16));

    File.WriteAllBytes(outp, img);
    File.WriteAllText("wbtool.txt", log.ToString());
    Console.WriteLine("harvested {0}/{1} changed {2} failed {3} -> {4}", done, heaps.Count, changed, failed, outp);
  }
  
  
  
}
