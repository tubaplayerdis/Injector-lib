#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <psapi.h>
#include <stdbool.h>

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "Version.lib")
#pragma comment(lib, "Kernel32.lib")
#pragma comment(lib, "Shlwapi.lib")

unsigned long find_process_id(const wchar_t* processName)
{
    PROCESSENTRY32 entry = { 0 };
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (wcscmp(entry.szExeFile, processName) == 0)
            {
                return entry.th32ProcessID;
            }
        }
    }

    CloseHandle(snapshot);
    return 0;
}

__declspec(dllexport) bool EjectDLL(const DWORD process_id, const wchar_t* dll_name)
{
    const HANDLE h_snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_id);
    if (h_snap == INVALID_HANDLE_VALUE) return FALSE;

    MODULEENTRY32 me32 = { sizeof(me32) };
    BOOL found = FALSE;
    LPVOID base_addr = NULL;

    if (Module32First(h_snap, &me32)) {
        do {
            if (_wcsicmp(me32.szModule, dll_name) == 0 ||
                _wcsicmp(me32.szExePath, dll_name) == 0) {
                base_addr = me32.modBaseAddr;
                found = TRUE;
                break;
                }
        } while (Module32Next(h_snap, &me32));
    }
    CloseHandle(h_snap);
    if (!found) return FALSE;

    // Open target process
    const HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    if (!h_process) return FALSE;

    // Get FreeLibrary address
    const LPVOID p_free_lib = GetProcAddress(GetModuleHandleA("kernel32.dll"), "FreeLibrary");
    if (!p_free_lib) { CloseHandle(h_process); return FALSE; }

    // Call FreeLibrary remotely
    const HANDLE h_thread = CreateRemoteThread(h_process, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)p_free_lib,
                                        base_addr, 0, NULL);
    if (!h_thread) { CloseHandle(h_process); return FALSE; }

    WaitForSingleObject(h_thread, INFINITE);

    CloseHandle(h_thread);
    CloseHandle(h_process);
    return TRUE;
}

/*
 * Returns:
 * 0 - Not Loaded
 * 1 - Loaded
 * 2 - Process Not Found
 * 3 - Process Cant Open
 */
__declspec(dllexport) int DLLIsLoaded(const wchar_t* dll_name, const wchar_t* process_name)
{
    const unsigned long process_id = find_process_id(process_name);
    if (process_id == 0) return 2;

    const HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    if (!h_process) return 3;

    HMODULE h_mods[1024];
    DWORD cb_needed;
    if (EnumProcessModules(h_process, h_mods, sizeof(h_mods), &cb_needed))
    {
        for (unsigned int i = 0; i < (cb_needed / sizeof(HMODULE)); i++)
        {
            TCHAR szModName[MAX_PATH];
            if (GetModuleFileNameEx(h_process, h_mods[i], szModName, sizeof(szModName) / sizeof(TCHAR)))
            {
                if (StrStr(szModName, dll_name) != NULL) {
                    CloseHandle(h_process);
                    return 1;
                }
            }
        }
    }

    CloseHandle(h_process);
    return 0;
}

#define RETURN_SUCCESS 0
#define RETURN_PROCESS_NOT_FOUND 1
#define RETURN_DLL_NOT_FOUND 2
#define RETURN_PROCESS_OPENING_FAILURE 3
#define RETURN_DLL_ALREADY_LOADED 4
#define RETURN_INJECTION_FAILURE 5

/*
 * Returns:
 * 0 - Success
 * 1 - Process Not Found
 * 2 - Dll Not Found
 * 3 - Process Opening Failure
 * 4 - DLL already loaded
 * 5 - Injection Failure
 */
__declspec(dllexport) int InjectDll(const wchar_t* dll_path_name, const wchar_t* process_name)
{
    const unsigned long process_id = find_process_id(process_name);
    if (process_id == 0) return RETURN_PROCESS_NOT_FOUND;

    const HANDLE h_file = CreateFile(
        dll_path_name,              // File name
        GENERIC_READ,            // Access mode
        FILE_SHARE_READ,         // Share mode
        NULL,                    // Security attributes
        OPEN_EXISTING,           // Creation disposition
        FILE_ATTRIBUTE_NORMAL,   // Flags and attributes
        NULL                     // Template file
    );

    if (h_file == INVALID_HANDLE_VALUE)
    {
        CloseHandle(h_file);
        return RETURN_DLL_NOT_FOUND;
    }

    CloseHandle(h_file);

    const HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
    if (!h_process)
    {
        CloseHandle(h_process);
        return RETURN_PROCESS_OPENING_FAILURE;
    }

    if (DLLIsLoaded(PathFindFileNameW(dll_path_name), process_name) > 1)
    {
        CloseHandle(h_process);
        return RETURN_DLL_ALREADY_LOADED;
    }

    LPVOID alloc = VirtualAllocEx(h_process, NULL, wcslen(dll_path_name) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!alloc)
    {
        CloseHandle(h_process);
        return RETURN_INJECTION_FAILURE;
    }

    if (!WriteProcessMemory(h_process, alloc, dll_path_name, wcslen(dll_path_name) + 1, NULL))
    {
        CloseHandle(h_process);
        return RETURN_INJECTION_FAILURE;
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPVOID loadLib = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");

    if (hKernel32 == NULL || loadLib == NULL)
    {
        CloseHandle(h_process);
        return RETURN_INJECTION_FAILURE;
    }

    HANDLE hThread = CreateRemoteThread(h_process, 0, 0, (LPTHREAD_START_ROUTINE)loadLib, alloc, 0, 0);
    if (!hThread)
    {
        CloseHandle(h_process);
        CloseHandle(hThread);
        return RETURN_INJECTION_FAILURE;
    }

    if (WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED)
    {
        CloseHandle(h_process);
        CloseHandle(hThread);
        return RETURN_INJECTION_FAILURE;
    }

    VirtualFreeEx(h_process, alloc, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(h_process);

    return RETURN_SUCCESS;
}



