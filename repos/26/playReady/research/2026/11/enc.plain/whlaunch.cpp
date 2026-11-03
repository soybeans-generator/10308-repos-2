// whlaunch.cpp
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <vector>

static const wchar_t* LOGPATH = L"D:\\wbhook.log";
static void note(const wchar_t* s) {
  FILE* f = _wfopen(LOGPATH, L"a");
  if (f) { fwprintf(f, L"[injector] %s\n", s); fflush(f); fclose(f); }
}

static DWORD findpid(const wchar_t* name) {
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) return 0;
  PROCESSENTRY32W pe = { sizeof(pe) };
  DWORD pid = 0;
  for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe))
    if (!_wcsicmp(pe.szExeFile, name)) { pid = pe.th32ProcessID; break; }
  CloseHandle(snap);
  return pid;
}

struct Hooked {
  DWORD  pid;
  HANDLE h;
  BYTE*  buf;
  ULONGLONG sysN, infN, infCls;
  bool   dead;
};

static BOOL install(DWORD pid, Hooked* out) {
  /* --- classify: protected or not, before we try to open --- */
  {
    HANDLE q = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (q) {
      BYTE pb[1] = {0xFF};
      ULONG ret = 0;
      HMODULE nt0 = GetModuleHandleW(L"ntdll.dll");
      typedef LONG (NTAPI *pNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
      pNtQIP qip = (pNtQIP)GetProcAddress(nt0, "NtQueryInformationProcess");
      LONG r = qip ? qip(q, 61, pb, 1, &ret) : -1;
      wchar_t b[160];
      if (r >= 0) {
        _snwprintf_s(b, _TRUNCATE,
          L"  pid %lu protection type=%u audit=%u level=%u",
          pid, pb[0] & 0x7, (pb[0] >> 3) & 1, pb[0] >> 4);
      } else {
        _snwprintf_s(b, _TRUNCATE, L"  pid %lu protection query failed (0x%lx)", pid, r);
      }
      note(b);
      CloseHandle(q);
    } else {
      wchar_t b[96];
      _snwprintf_s(b, _TRUNCATE, L"  pid %lu not even queryable", pid);
      note(b);
    }
  }

  const DWORD need = PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                     PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;
  HANDLE h = NULL;
  DWORD last = 0;
  for (int i = 0; i < 200 && !h; i++) {
    h = OpenProcess(need, FALSE, pid);
    if (!h) { last = GetLastError(); Sleep(50); }
  }
  if (!h) {
    wchar_t b[96];
    _snwprintf_s(b, _TRUNCATE, L"  pid %lu OpenProcess failed err=%lu", pid, last);
    note(b);
    return FALSE;
  }

  HMODULE nt = GetModuleHandleW(L"ntdll.dll");
  BYTE* stubSys = (BYTE*)GetProcAddress(nt, "NtQuerySystemInformation");
  BYTE* stubInf = (BYTE*)GetProcAddress(nt, "NtQueryInformationProcess");
  if (!stubSys || !stubInf) { note(L"no stubs"); CloseHandle(h); return FALSE; }

  DWORD ssnSys = *(DWORD*)(stubSys + 4);
  DWORD ssnInf = *(DWORD*)(stubInf + 4);

  BYTE* code = (BYTE*)VirtualAllocEx(h, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);
  if (!code) { note(L"alloc failed"); CloseHandle(h); return FALSE; }

  /* ---------- stub A: NtQuerySystemInformation, at code+0 ---------- */
  std::vector<BYTE> c;
  std::vector<size_t> ats, tgts;
  auto p32 = [&](DWORD v) { for (int i = 0; i < 4; i++) c.push_back((BYTE)(v >> (8*i))); };
  auto store = [&](const BYTE* op3, size_t tgt) {
    for (int i = 0; i < 3; i++) c.push_back(op3[i]);
    ats.push_back(c.size()); tgts.push_back(tgt);
    p32(0);
  };

  store((const BYTE[]){0x48,0xFF,0x05}, 0x00);
  {
    const BYTE mra[] = {0x48,0x8B,0x04,0x24};
    for (auto x : mra) c.push_back(x);
    store((const BYTE[]){0x48,0x89,0x05}, 0x08);
  }
  store((const BYTE[]){0x48,0x89,0x0D}, 0x20);
  store((const BYTE[]){0x48,0x89,0x15}, 0x28);
  store((const BYTE[]){0x4C,0x89,0x05}, 0x30);

  const BYTE cmp[] = {0x48,0x81,0xF9,0xB9,0,0,0};
  for (auto x : cmp) c.push_back(x);
  size_t jne = c.size(); c.push_back(0x75); c.push_back(0);
  const BYTE td[] = {0x48,0x85,0xD2};
  for (auto x : td) c.push_back(x);
  size_t jz = c.size(); c.push_back(0x74); c.push_back(0);

  for (int i = 0; i < 6; i++) {
    if (i == 0) { const BYTE a[] = {0x48,0x8B,0x02}; for (auto x : a) c.push_back(x); }
    else        { const BYTE a[] = {0x48,0x8B,0x42,(BYTE)(i*8)}; for (auto x : a) c.push_back(x); }
    store((const BYTE[]){0x48,0x89,0x05}, 0x38 + i*8);
  }

  size_t go = c.size();
  c[jne+1] = (BYTE)(go - (jne+2));
  c[jz +1] = (BYTE)(go - (jz +2));

  const BYTE r10[] = {0x4C,0x8B,0xD1};
  for (auto x : r10) c.push_back(x);
  c.push_back(0xB8); p32(ssnSys);
  c.push_back(0x0F); c.push_back(0x05);
  c.push_back(0xC3);

  size_t dataOff = (c.size() + 15) & ~(size_t)15;
  c.resize(dataOff + 0x200, 0);
  for (size_t i = 0; i < ats.size(); i++) {
    INT32 d = (INT32)(dataOff + tgts[i] - (ats[i] + 4));
    memcpy(&c[ats[i]], &d, 4);
  }
  if (!WriteProcessMemory(h, code, c.data(), c.size(), NULL)) {
    note(L"write A failed"); CloseHandle(h); return FALSE;
  }

  /* ---------- stub B: NtQueryInformationProcess, at code+0x400 ----------
     logs counter@0x100 and class@0x108; fakes class 61 as type=2 level=1,
     but only when a 1-byte buffer was actually supplied (NULL-safe)        */
  {
    std::vector<BYTE> s;
    std::vector<size_t> at2, tg2;
    auto p32s = [&](DWORD v) { for (int i = 0; i < 4; i++) s.push_back((BYTE)(v >> (8*i))); };
    auto st2 = [&](const BYTE* op3, size_t tgt) {
      for (int i = 0; i < 3; i++) s.push_back(op3[i]);
      at2.push_back(s.size()); tg2.push_back(tgt);
      p32s(0);
    };
    auto emit = [&](const BYTE* p, size_t n) { for (size_t i = 0; i < n; i++) s.push_back(p[i]); };

    st2((const BYTE[]){0x48,0xFF,0x05}, 0x100);          /* inc qword [buf+0x100] */
    st2((const BYTE[]){0x48,0x89,0x15}, 0x108);          /* mov [buf+0x108], rdx  */

    const BYTE c61[] = {0x83,0xFA,0x3D};                 /* cmp edx, 61  */
    emit(c61, sizeof(c61));
    size_t j1 = s.size(); s.push_back(0x75); s.push_back(0);

    const BYTE t1[] = {0x4D,0x85,0xC0};                  /* test r8, r8  */
    emit(t1, sizeof(t1));
    size_t j2 = s.size(); s.push_back(0x74); s.push_back(0);

    const BYTE c1[] = {0x41,0x83,0xF9,0x01};             /* cmp r9d, 1   */
    emit(c1, sizeof(c1));
    size_t j3 = s.size(); s.push_back(0x72); s.push_back(0);

    const BYTE fake[] = {0x41,0xC6,0x00,0x12};           /* mov byte [r8], 0x12 */
    emit(fake, sizeof(fake));
    const BYTE ret0[] = {0x31,0xC0,0xC3};                /* xor eax,eax; ret    */
    emit(ret0, sizeof(ret0));

    size_t real = s.size();
    const BYTE rr[] = {0x4C,0x8B,0xD1};                  /* mov r10, rcx */
    emit(rr, sizeof(rr));
    s.push_back(0xB8); p32s(ssnInf);
    s.push_back(0x0F); s.push_back(0x05);
    s.push_back(0xC3);

    s[j1+1] = (BYTE)(real - (j1 + 2));
    s[j2+1] = (BYTE)(real - (j2 + 2));
    s[j3+1] = (BYTE)(real - (j3 + 2));

    for (size_t i = 0; i < at2.size(); i++) {
      INT32 d = (INT32)(dataOff + tg2[i] - (0x400 + at2[i] + 4));
      memcpy(&s[at2[i]], &d, 4);
    }
    if (!WriteProcessMemory(h, code + 0x400, s.data(), s.size(), NULL)) {
      note(L"write B failed"); CloseHandle(h); return FALSE;
    }
  }

  auto hook5 = [&](BYTE* stub, BYTE* tgt) -> BOOL {
    BYTE jmp[5];
    jmp[0] = 0xE9;
    INT32 rel = (INT32)(tgt - (stub + 5));
    memcpy(jmp + 1, &rel, 4);
    DWORD oldp;
    if (!VirtualProtectEx(h, stub, 5, PAGE_EXECUTE_READWRITE, &oldp)) return FALSE;
    BOOL w = WriteProcessMemory(h, stub, jmp, 5, NULL);
    VirtualProtectEx(h, stub, 5, oldp, &oldp);
    return w;
  };
  if (!hook5(stubSys, code)) { note(L"patch sys failed"); CloseHandle(h); return FALSE; }
  if (!hook5(stubInf, code + 0x400)) { note(L"patch inf failed"); CloseHandle(h); return FALSE; }

  BYTE verify[5] = {0};
  SIZE_T got = 0;
  ReadProcessMemory(h, stubInf, verify, 5, &got);
  wchar_t b[200];
  _snwprintf_s(b, _TRUNCATE, L"  pid %lu hooked, stubInf now %02x %02x %02x %02x %02x",
               pid, verify[0], verify[1], verify[2], verify[3], verify[4]);
  note(b);

  out->pid = pid;
  out->h = h;
  out->buf = code + dataOff;
  out->sysN = out->infN = out->infCls = 0;
  out->dead = false;
  return TRUE;
}

static void pollAll(std::vector<Hooked>& list) {
  for (auto& hk : list) {
    if (hk.dead) continue;
    BYTE q[0x120];
    SIZE_T got = 0;
    if (!ReadProcessMemory(hk.h, hk.buf, q, sizeof(q), &got) || got != sizeof(q)) {
      hk.dead = true;
      DWORD ec = 0;
      GetExitCodeProcess(hk.h, &ec);
      wchar_t b[160];
      _snwprintf_s(b, _TRUNCATE, L"  pid %lu READ FAILED (exit=%lu) after sys=%llu inf=%llu",
                   hk.pid, ec, hk.sysN, hk.infN);
      note(b);
      continue;
    }
    ULONGLONG sysN  = *(ULONGLONG*)(q + 0x000);
    ULONGLONG infN  = *(ULONGLONG*)(q + 0x100);
    ULONGLONG infCl = *(ULONGLONG*)(q + 0x108);
    if (sysN != hk.sysN || infN != hk.infN || infCl != hk.infCls) {
      wchar_t b[192];
      _snwprintf_s(b, _TRUNCATE, L"  pid %lu sysHits=%llu infHits=%llu lastClass=%llu",
                   hk.pid, sysN, infN, infCl);
      note(b);
      hk.sysN = sysN; hk.infN = infN; hk.infCls = infCl;
    }
  }
}

int wmain(int argc, wchar_t** argv) {
  if (argc < 2) { note(L"usage: whlaunch.exe process [secs]"); return 1; }
  const wchar_t* name = argv[1];
  int secs = argc > 2 ? _wtoi(argv[2]) : 90;

  note(L"polling started");
  std::vector<Hooked> list;
  std::vector<DWORD> tried;
  DWORD t0 = GetTickCount();

  while ((int)((GetTickCount() - t0) / 1000) < secs) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
      PROCESSENTRY32W pe = { sizeof(pe) };
      for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe)) {
        if (_wcsicmp(pe.szExeFile, name)) continue;
        DWORD pid = pe.th32ProcessID;
        bool dup = false;
        for (DWORD t : tried) if (t == pid) dup = true;
        if (dup) continue;
        tried.push_back(pid);

        wchar_t b[128];
        _snwprintf_s(b, _TRUNCATE, L"candidate %s pid %lu", name, pid);
        note(b);

        Hooked hk;
        if (install(pid, &hk)) list.push_back(hk);
      }
      CloseHandle(snap);
    }
    if (!list.empty()) pollAll(list);
    Sleep(50);
  }

  int live = 0;
  for (auto& hk : list) if (!hk.dead) live++;
  wchar_t b[128];
  _snwprintf_s(b, _TRUNCATE, L"polling ended, %d hooked, %d still alive", (int)list.size(), live);
  note(b);
  return 0;
}
