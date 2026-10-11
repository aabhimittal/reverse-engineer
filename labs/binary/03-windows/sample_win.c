/*
 * Lab 03: a benign Windows PE that *imports* APIs associated with process
 * injection and persistence, so you can see how capability detection maps
 * imports and strings to MITRE ATT&CK. It never performs injection: every
 * call is made with NULL handles and does nothing even if executed.
 *
 * Built without a CRT (clang + lld-link + llvm-dlltool import libraries),
 * see scripts/build-fixtures.sh.
 */
typedef void *HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;
typedef unsigned long long SIZE_T;

__declspec(dllimport) BOOL __stdcall IsDebuggerPresent(void);
__declspec(dllimport) void __stdcall ExitProcess(unsigned int);
__declspec(dllimport) void *__stdcall VirtualAllocEx(HANDLE, void *, SIZE_T, DWORD, DWORD);
__declspec(dllimport) BOOL __stdcall WriteProcessMemory(HANDLE, void *, const void *, SIZE_T, SIZE_T *);
__declspec(dllimport) HANDLE __stdcall CreateRemoteThread(HANDLE, void *, SIZE_T, void *, void *, DWORD, DWORD *);
__declspec(dllimport) int __stdcall MessageBoxA(HANDLE, const char *, const char *, unsigned int);

/* External linkage keeps these strings in the binary (no constant folding). */
const char *config[] = {
    "http://update.example.com/gate.php",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) rex-lab",
};

int capabilities_demo(void) {
    /* NULL process handle: these calls fail harmlessly. */
    void *p = VirtualAllocEx(0, 0, 0, 0, 0);
    WriteProcessMemory(0, p, 0, 0, 0);
    CreateRemoteThread(0, 0, 0, 0, 0, 0, 0);
    return p != 0;
}

void start(void) {
    if (IsDebuggerPresent()) {
        ExitProcess(1);
    }
    MessageBoxA(0, config[0], "rex lab 03", 0);
    if (config[1][0] == 'X') {
        capabilities_demo();
    }
    ExitProcess(0);
}
