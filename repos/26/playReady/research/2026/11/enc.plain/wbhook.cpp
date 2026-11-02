// wbhook.cpp  ->  cl /LD /EHsc wbhook.cpp   (x64)
#include <windows.h>
#include <stdio.h>

static FILE* g_f;
static void* g_tramp;
typedef LONG (NTAPI *pNtQ)(ULONG, PVOID, ULONG, PULONG);
static pNtQ g_orig;

static void dumpbuf(const char* tag, ULONGLONG addr, int n) {
  if (!addr || addr < 0x10000 || addr > 0x7FFFFFFFFFFFULL) return;
  __try {
    const BYTE* p = (const BYTE*)addr;
    fprintf(g_f, "  %s @%llx ", tag, addr);
    for (int i = 0; i < n; i++) fprintf(g_f, "%02x", p[i]);
    fprintf(g_f, "\n");
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    fprintf(g_f, "  %s @%llx <unreadable>\n", tag, addr);
  }
}

static LONG NTAPI Detour(ULONG cls, PVOID info, ULONG len, PULONG ret) {
  if (cls == 0xB9 && info && g_f) {
    ULONGLONG v[8] = {0};
    __try { memcpy(v, info, (len < 0x40 ? len : 0x40)); } __except (1) {}
    fprintf(g_f, "WB op=%llu desc=%llx len=%x\n", v[0], v[1], len);
    dumpbuf("a0", v[2], 0x40);
    dumpbuf("a1", v[3], 0x40);
    dumpbuf("a2", v[4], 0x40);
    dumpbuf("a3", v[5], 0x40);
    fflush(g_f);
  }
  return g_orig(cls, info, len, ret);
}

static void install() {
  g_f = fopen("C:\\wbhook.log", "a");
  HMODULE nt = GetModuleHandleW(L"ntdll.dll");
  BYTE* stub = (BYTE*)GetProcAddress(nt, "NtQuerySystemInformation");
  if (!stub) return;
  g_tramp = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  memcpy(g_tramp, stub, 12);            // mov r10,rcx / mov eax,ssn / syscall / ret
  g_orig = (pNtQ)g_tramp;
  BYTE patch[12] = {0x48,0xB8};
  *(ULONGLONG*)(patch + 2) = (ULONGLONG)Detour;
  patch[10] = 0xFF; patch[11] = 0xE0;   // jmp rax
  DWORD old;
  VirtualProtect(stub, 12, PAGE_EXECUTE_READWRITE, &old);
  memcpy(stub, patch, 12);
  VirtualProtect(stub, 12, old, &old);
}

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) install();
  return TRUE;
}
