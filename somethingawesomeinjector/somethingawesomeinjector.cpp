// somethingawesomeinjector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

DWORD GetProcId(const char* procName) {
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry);

        if (Process32First(hSnap, &procEntry)) {
            do {
                if (!_stricmp(procEntry.szExeFile, procName)) {
                    procId = procEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &procEntry));
        }
    }
    CloseHandle(hSnap);
    return procId;
}

int main()
{
    const char* dllPath = "";
    const char* procName = "ac_client.exe";
    DWORD procId = 0;

    while (!procId) {
        procId = GetProcId(procName);
        printf("waiting for %s\n", procName);
        Sleep(1000);
    }

    HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, 0, procId);

    if (handle) {
        if (handle != INVALID_HANDLE_VALUE) {
            LPVOID loc = VirtualAllocEx(handle, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (loc) {
                BOOL success = WriteProcessMemory(handle, loc, dllPath, strlen(dllPath) + 1, 0);
                if (success) {
                    HANDLE hThread = CreateRemoteThread(handle, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, 0);
                    if (hThread) {
                        CloseHandle(hThread);
                    }
                }
            }
        }
    }

    if (handle) {
        CloseHandle(handle);
    }
    return 0;
}