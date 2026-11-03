// wbhook.cpp — kernel32-only logger DLL (no CRT, no api-ms-win-crt-*)
#include <windows.h>

#define LOGPATH L"C:\\Users\\Public\\wbhook.log"

typedef LONG (NTAPI *pNtQ)(ULONG, PVOID, ULONG, PULONG);

static HANDLE g_log = INVALID_HANDLE_VALUE;
static BYTE*  g_tramp;
static pNtQ   g_orig;
static int    g_hits;

static void wstr(const wchar_t* s) {
  DWORD n = 0, w;
  while (s[n]) n++;
  if (g_log != INVALID_HANDLE_VALUE && n) WriteFile(g_log, s, n * 2, &w, NULL);
}

static void whex(unsigned long long v, int digits) {
  wchar_t b[17];
  const wchar_t* h = L"0123456789abcdef";
  for (int i = digits - 1; i >= 0; i--) { b[i] = h[(int)(v & 0xF)]; v >>= 4; }
  b[digits] = 0;
  wstr(b);
}

static void wdump(const wchar_t* tag, unsigned long long a, int n) {
  unsigned char buf[0x40];
  SIZE_T got = 0;
  if (!a || a < 0x10000 || a > 0x7FFFFFFFFFFFULL) return;
  if (n > 0x40) n = 0x40;
  if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)a, buf, (SIZE_T)n, &got)
      || got != (SIZE_T)n) {
    wstr(L"  <unreadable>\r\n");
    return;
  }
  wstr(L"  "); wstr(tag); wstr(L" @");
  whex(a >> 32, 8); whex(a & 0xFFFFFFFFULL, 8); wstr(L" ");
  for (int i = 0; i < n; i++) whex(buf[i], 2);
  wstr(L"\r\n");
}

static LONG NTAPI hookfn(ULONG cls, PVOID info, ULONG len, PULONG ret) {
  if (cls == 0xB9 && info && g_log != INVALID_HANDLE_VALUE && g_hits < 4000) {
    unsigned long long v[8];
    SIZE_T got = 0;
    int i;
    for (i = 0; i < 8; i++) v[i] = 0;
    if (ReadProcessMemory(GetCurrentProcess(), info, v,
                          (SIZE_T)(len < 0x40 ? len : 0x40), &got)) {
      g_hits++;
      wstr(L"=== WB #"); whex((unsigned long long)g_hits, 4);
      wstr(L" op=");      whex(v[0], 2);
      wstr(L" desc=");    whex(v[1], 16);
      wstr(L" len=");     whex((unsigned long long)len, 8);
      wstr(L"\r\n");
      wdump(L"a0", v[2], 0x40);
      wdump(L"a1", v[3], 0x40);
      wdump(L"a2", v[4], 0x40);
      wdump(L"a3", v[5], 0x40);
      wdump(L"a4", v[6], 0x40);
      FlushFileBuffers(g_log);
    }
  }
  return g_orig(cls, info, len, ret);
}

static void install(void) {
  HMODULE nt;
  BYTE* stub;
  DWORD old;
  int i;

  g_log = CreateFileW(LOGPATH, FILE_APPEND_DATA,
                      FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                      OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  wstr(L"--- hook installed ---\r\n");

  nt = GetModuleHandleW(L"ntdll.dll");
  if (!nt) { wstr(L"no ntdll\r\n"); return; }
  stub = (BYTE*)GetProcAddress(nt, "NtQuerySystemInformation");
  if (!stub) { wstr(L"no stub\r\n"); return; }

  g_tramp = (BYTE*)VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
  if (!g_tramp) { wstr(L"no tramp\r\n"); return; }
  for (i = 0; i < 12; i++) g_tramp[i] = stub[i];   /* mov r10,rcx; mov eax,ssn; syscall; ret */
  g_orig = (pNtQ)g_tramp;

  if (!VirtualProtect(stub, 12, PAGE_EXECUTE_READWRITE, &old)) {
    wstr(L"vp fail\r\n");
    return;
  }
  stub[0] = 0x48; stub[1] = 0xB8;
  *(unsigned long long*)(stub + 2) = (unsigned long long)hookfn;
  stub[10] = 0xFF; stub[11] = 0xE0;                /* jmp rax */
  VirtualProtect(stub, 12, old, &old);
  FlushInstructionCache(GetCurrentProcess(), stub, 12);
  wstr(L"stub patched\r\n");
}

//extern "C" BOOL WINAPI DllMainCRTStartup(HINSTANCE h, DWORD reason, LPVOID) {
extern "C" BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(h);
    install();
  }
  return TRUE;
}
