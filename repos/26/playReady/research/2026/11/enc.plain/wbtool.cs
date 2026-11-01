// wbtool.cs — decrypt segment descriptors AND heap-exec code in place, dump image
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

class WBTool {
  [DllImport("kernel32", SetLastError=true, CharSet=CharSet.Unicode)]
  static extern IntPtr LoadLibraryW(string p);
  [DllImport("kernel32", SetLastError=true)]
  static extern bool VirtualProtect(IntPtr addr, UIntPtr size, uint prot, out uint old);
  [DllImport("ntdll")]
  static extern int NtQuerySystemInformation(int cls, IntPtr si, int len, IntPtr ret);

  const uint PAGE_EXECUTE_READWRITE = 0x40;

  static uint U32(byte[] b, int o) { return BitConverter.ToUInt32(b, o); }
  static void P32(byte[] b, int o, uint v) {
    b[o]=(byte)v; b[o+1]=(byte)(v>>8); b[o+2]=(byte)(v>>16); b[o+3]=(byte)(v>>24);
  }
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

  static IntPtr img;
  static long sac;
  static uint sacProt, dummy;
  static byte[] sacOrig;

  // write bytes into the descriptor page, then hand the page back at its original protection
  static void WriteDesc(byte[] src) {
    if (!VirtualProtect((IntPtr)sac, (UIntPtr)0x1000, PAGE_EXECUTE_READWRITE, out dummy))
      throw new Exception("VP rw failed " + Marshal.GetLastWin32Error());
    Marshal.Copy(src, 0, (IntPtr)sac, 0x100);
    if (!VirtualProtect((IntPtr)sac, (UIntPtr)0x1000, sacProt, out dummy))
      throw new Exception("VP restore failed " + Marshal.GetLastWin32Error());
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
    for (int i = 0; i < nsec; i++) { int so = stab + i * 40; secs[i] = new long[] { U32(f,so+12), U32(f,so+8), U32(f,so+20), U32(f,so+16) }; }

    List<long[]> all = new List<long[]>();
    using (SHA256 sha = SHA256.Create()) {
      for (int s = 0; s < nsec; s++) {
        int b0 = (int)secs[s][2], len = (int)secs[s][3];
        for (int off = 0; off + 0x40 <= len; off += 4) {
          uint size = U32(f, b0 + off + 0x20);
          if (size < 0x40 || size > 0x2000 || off + size > len) continue;
          byte[] dig = sha.ComputeHash(f, b0 + off + 0x20, (int)size - 0x20);
          bool hit = true;
          for (int k = 0; k < 32; k++) if (dig[k] != f[b0 + off + k]) { hit = false; break; }
          if (hit) all.Add(new long[] { secs[s][0] + off, size, b0 + off });
        }
      }
    }

    List<long[]> segspans = new List<long[]>();
    foreach (long[] d in all) {
      if (d[1] == 0xF0) continue;
      int fo = (int)d[2];
      for (int i = 0; i < (d[1] - 0xF4) / 0xC; i++) {
        int eo = fo + 0xF4 + i * 0xC;
        long r = U32(f, eo + 4) & 0x0FFFFFFF, sz = U32(f, eo + 8);
        if (sz > 0 && sz < 0x1000000) segspans.Add(new long[] { r, r + sz });
      }
    }
    Func<long, bool> inSeg = r => { foreach (long[] sp in segspans) if (r >= sp[0] && r < sp[1]) return true; return false; };

    img = LoadLibraryW(path);
    if (img == IntPtr.Zero) { Console.WriteLine("LoadLibrary failed " + Marshal.GetLastWin32Error()); return; }
    long ib = img.ToInt64();
    StringBuilder log = new StringBuilder();
    log.AppendLine(string.Format("base 0x{0:x} descriptors {1}", ib, all.Count));

    sac = ib + 0x6D8000;
    sacOrig = new byte[0x100];
    Marshal.Copy((IntPtr)sac, sacOrig, 0, 0x100);
    long rel = U32(sacOrig, 0x2C), num = U32(sacOrig, 0x30);
    if (!VirtualProtect((IntPtr)sac, (UIntPtr)0x1000, PAGE_EXECUTE_READWRITE, out sacProt)) {
      Console.WriteLine("VP probe failed " + Marshal.GetLastWin32Error()); return;
    }
    VirtualProtect((IntPtr)sac, (UIntPtr)0x1000, sacProt, out dummy);
    log.AppendLine(string.Format("sac page orig prot 0x{0:x} relocs 0x{1:x}/{2}", sacProt, rel, num));

    int nSeg = 0, nSegOk = 0;
    foreach (long[] d in all) {
      if (d[1] == 0xF0) continue;
      nSeg++;
      int fo = (int)d[2];
      int res = Dec(img, ib + d[0], ib + U32(f, fo + 0x2C), U32(f, fo + 0x30));
      if (res == 0) nSegOk++; else log.AppendLine(string.Format("seg  0x{0:x6} res 0x{1:x8}", d[0], res));
    }
    log.AppendLine(string.Format("segments {0} ok {1}", nSeg, nSegOk));

    int nHeap = 0, nOk = 0, nBad = 0, nSkip = 0;
    byte[] hexec = new byte[0xF0], fake = new byte[0x100];
    foreach (long[] d in all) {
      if (d[1] != 0xF0) continue;
      nHeap++;
      Array.Copy(f, (int)d[2], hexec, 0, 0xF0);
      long codeRVA = U32(hexec, 0x34) & 0x0FFFFFFF;
      long codeSz = U32(hexec, 0x38) & 0x0FFFFFFF;
      if (codeSz == 0 || codeRVA == 0 || inSeg(codeRVA)) { nSkip++; continue; }

      Array.Copy(sacOrig, 0, fake, 0, 0x40);
      Array.Copy(hexec, 0x40, fake, 0x40, 0xF0 - 0x40);
      P32(fake, 0xF0, 1);
      P32(fake, 0xF4, 0x30C);
      P32(fake, 0xF8, (uint)codeRVA);
      P32(fake, 0xFC, (uint)codeSz);
      using (SHA256 sha = SHA256.Create()) {
        byte[] dig = sha.ComputeHash(fake, 0x20, 0x100 - 0x20);
        Array.Copy(dig, 0, fake, 0, 0x20);
      }
      WriteDesc(fake);
      int res = Dec(img, sac, ib + rel, num);
      WriteDesc(sacOrig);
      if (res == 0) nOk++; else nBad++;
      if (res != 0 && nBad <= 8)
        log.AppendLine(string.Format("hexec 0x{0:x6} code 0x{1:x6}+0x{2:x} res 0x{3:x8}", d[0], codeRVA, codeSz, res));
    }
    log.AppendLine(string.Format("heap-exec total {0}  ok {1}  fail {2}  skip {3}", nHeap, nOk, nBad, nSkip));

    byte[] buf = new byte[sizeImg];
    Marshal.Copy(img, buf, 0, (int)sizeImg);
    File.WriteAllBytes("wbtool_img.bin", buf);
    File.WriteAllText("wbtool.txt", log.ToString());
    Console.WriteLine("seg {0}/{1}  hexec {2} ok {3} fail {4} skip {5} -> wbtool.txt", nSegOk, nSeg, nHeap, nOk, nBad, nSkip);
  }
}
