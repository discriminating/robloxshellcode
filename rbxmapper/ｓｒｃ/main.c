#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>

#include <psapi.h>
#include <process.h>

#include "defs.h"

#define PAGE_SIZE 0x1000

unsigned char Shellcode[] = {
        0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x7C, 0x24, 0x10,
        0x55, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x40, 0x65, 0x48,
        0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x33, 0xD2, 0x49,
        0xB8, 0x47, 0x65, 0x74, 0x50, 0x72, 0x6F, 0x63, 0x41, 0x48,
        0x8B, 0x48, 0x18, 0x48, 0x8B, 0x41, 0x20, 0x48, 0x8B, 0x08,
        0x48, 0x8B, 0x01, 0x4C, 0x8B, 0x50, 0x20, 0x49, 0x63, 0x42,
        0x3C, 0x46, 0x8B, 0x9C, 0x10, 0x88, 0x00, 0x00, 0x00, 0x43,
        0x8B, 0x44, 0x13, 0x20, 0x49, 0x03, 0xC2, 0x48, 0x63, 0x08,
        0x4E, 0x39, 0x04, 0x11, 0x74, 0x1A, 0x66, 0x66, 0x0F, 0x1F,
        0x84, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x63, 0x48, 0x04,
        0x48, 0x8D, 0x40, 0x04, 0xFF, 0xC2, 0x4E, 0x39, 0x04, 0x11,
        0x75, 0xF0, 0x4C, 0x63, 0xC2, 0x48, 0xB8, 0x4C, 0x6F, 0x61,
        0x64, 0x4C, 0x69, 0x62, 0x72, 0x43, 0x8B, 0x54, 0x13, 0x24,
        0x49, 0x8B, 0xCA, 0x49, 0x03, 0xD2, 0x4E, 0x0F, 0xBF, 0x0C,
        0x42, 0x43, 0x8B, 0x54, 0x13, 0x1C, 0x49, 0x03, 0xD2, 0x4A,
        0x63, 0x1C, 0x8A, 0x48, 0x8D, 0x55, 0xE0, 0x49, 0x03, 0xDA,
        0x48, 0x89, 0x45, 0xE0, 0x48, 0xC7, 0x45, 0xE8, 0x61, 0x72,
        0x79, 0x41, 0xFF, 0xD3, 0x48, 0xB9, 0x75, 0x73, 0x65, 0x72,
        0x33, 0x32, 0x2E, 0x64, 0x48, 0xC7, 0x45, 0xE8, 0x6C, 0x6C,
        0x00, 0x00, 0x48, 0x89, 0x4D, 0xE0, 0x48, 0x8D, 0x4D, 0xE0,
        0xFF, 0xD0, 0x48, 0xB9, 0x4D, 0x65, 0x73, 0x73, 0x61, 0x67,
        0x65, 0x42, 0x48, 0xC7, 0x45, 0xE8, 0x6F, 0x78, 0x41, 0x00,
        0x48, 0x89, 0x4D, 0xE0, 0x48, 0x8D, 0x55, 0xE0, 0x48, 0x8B,
        0xC8, 0xFF, 0xD3, 0x48, 0x8B, 0xF8, 0x48, 0xC7, 0x45, 0xE8,
        0x21, 0x21, 0x00, 0x00, 0x48, 0xB8, 0x68, 0x65, 0x79, 0x20,
        0x67, 0x75, 0x79, 0x73, 0x4C, 0x8D, 0x45, 0xE0, 0x45, 0x33,
        0xC9, 0x48, 0x89, 0x45, 0xE0, 0x48, 0x8D, 0x55, 0xE0, 0x33,
        0xC9, 0xFF, 0xD7, 0x48, 0xB8, 0x77, 0x6F, 0x6E, 0x64, 0x65,
        0x72, 0x66, 0x75, 0x48, 0xC7, 0x45, 0xF0, 0x72, 0x00, 0x00,
        0x00, 0x48, 0x89, 0x45, 0xE0, 0x4C, 0x8D, 0x45, 0xEA, 0x48,
        0xB8, 0x6C, 0x20, 0x77, 0x65, 0x61, 0x74, 0x68, 0x65, 0x48,
        0x8D, 0x55, 0xE0, 0x45, 0x33, 0xC9, 0x48, 0x89, 0x45, 0xE8,
        0x33, 0xC9, 0xFF, 0xD7, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60,
        0x00, 0x00, 0x00, 0x48, 0x8D, 0x55, 0xE0, 0x33, 0xC9, 0x48,
        0x8B, 0x58, 0x10, 0x48, 0xB8, 0x48, 0x65, 0x6C, 0x6C, 0x6F,
        0x20, 0x52, 0x4F, 0x48, 0x89, 0x45, 0xE0, 0x48, 0x81, 0xC3,
        0x20, 0xB5, 0x2D, 0x01, 0x48, 0xB8, 0x42, 0x4C, 0x4F, 0x58,
        0x21, 0x0A, 0x00, 0x00, 0x48, 0x89, 0x45, 0xE8, 0xFF, 0xD3,
        0x48, 0x8D, 0x55, 0xE0, 0xB9, 0x01, 0x00, 0x00, 0x00, 0xFF,
        0xD3, 0x48, 0x8D, 0x55, 0xE0, 0xB9, 0x02, 0x00, 0x00, 0x00,
        0xFF, 0xD3, 0x48, 0x8D, 0x55, 0xE0, 0xB9, 0x03, 0x00, 0x00,
        0x00, 0xFF, 0xD3, 0x48, 0xB8, 0x63, 0x6C, 0x69, 0x63, 0x6B,
        0x20, 0x6D, 0x65, 0x48, 0xC7, 0x45, 0xF0, 0x68, 0x21, 0x00,
        0x00, 0x48, 0x89, 0x45, 0xE0, 0x4C, 0x8D, 0x45, 0xEC, 0x48,
        0xB8, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x72, 0x61, 0x73, 0x48,
        0x8D, 0x55, 0xE0, 0x45, 0x33, 0xC9, 0x48, 0x89, 0x45, 0xE8,
        0x33, 0xC9, 0xFF, 0xD7, 0x48, 0x8B, 0x5C, 0x24, 0x50, 0x48,
        0x8B, 0x7C, 0x24, 0x58, 0x48, 0x83, 0xC4, 0x40, 0x5D, 0xC3 
};

BOOL Execute(HANDLE hRoblox, PVOID pPayloadAddress, HANDLE hIoPort)
{
    funcNtAssociateWaitCompletionPacket pNtAssociateWaitCompletionPacket = NULL;
    PVOID pRemoteTpDirect = NULL;
    PVOID pRemoteTpWait = NULL;
    HANDLE hEvent = NULL;
    PFULL_TP_WAIT pTpWait = NULL;
    NTSTATUS lStatus = ERROR_SUCCESS;

    pNtAssociateWaitCompletionPacket = (funcNtAssociateWaitCompletionPacket)
        GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"),
            "NtAssociateWaitCompletionPacket"
        );

    if (pNtAssociateWaitCompletionPacket == NULL) {
        MessageBoxA(NULL,
            "Failed to locate NtAssociateWaitCompletionPacket.",
            "Error",
            MB_ICONERROR
        );

        return FALSE;
    }

    pTpWait = (PFULL_TP_WAIT)CreateThreadpoolWait(
        (PTP_WAIT_CALLBACK)pPayloadAddress,
        NULL,
        NULL
    );

    if (pTpWait == NULL) {
        MessageBoxA(NULL,
            "Failed to create TP_WAIT object",
            "Error",
            MB_ICONERROR
        );

        return FALSE;
    }

    pRemoteTpWait = VirtualAllocEx(hRoblox,
        NULL,
        sizeof(FULL_TP_WAIT),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (pRemoteTpWait == NULL) {
        MessageBoxA(NULL,
            "Failed to allocate memory for TP_WAIT object",
            "Error",
            MB_ICONERROR
        );

        return FALSE;
    }

    if (!WriteProcessMemory(hRoblox,
        pRemoteTpWait,
        pTpWait,
        sizeof(FULL_TP_WAIT),
        NULL
    )) {
        MessageBoxA(NULL,
            "Failed to write memory for TP_WAIT object",
            "Error",
            MB_ICONERROR
        );

        return FALSE;
    }

    pRemoteTpDirect = VirtualAllocEx(
        hRoblox,
        NULL,
        sizeof(TP_DIRECT),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (pRemoteTpDirect == NULL) {
        MessageBoxA(NULL,
            "Failed to allocate memory for TP_DIRECT object",
            "Error",
            MB_ICONERROR
        );

        return FALSE;
    }

    if (!WriteProcessMemory(
        hRoblox,
        pRemoteTpDirect,
        &pTpWait->Direct,
        sizeof(TP_DIRECT),
        NULL
    )) {
        MessageBoxA(NULL,
            "Failed to write memory for TP_DIRECT object",
            "Error",
            MB_ICONERROR
        );

        return FALSE;
    }

    CHAR szEvent[21];
    WCHAR szEventW[21];

    srand(time(0));
    snprintf(szEvent,
        21,
        "%.*s",
        rand() % 6 + 15,
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        +
        (rand() % (62 - 20))
    );

    SIZE_T nCharsConverted = 0;
    mbstowcs_s(&nCharsConverted, szEventW, 21, szEvent, 21);

    hEvent = CreateEventW(NULL,
        FALSE,
        FALSE,
        szEventW
    );

    if (hEvent == NULL) {
        MessageBoxA(NULL,
            "Failed to create event object",
            "Error",
            MB_ICONERROR
        );

        return FALSE;
    }

    lStatus = pNtAssociateWaitCompletionPacket(
        pTpWait->WaitPkt,
        hIoPort,
        hEvent,
        pRemoteTpDirect,
        pRemoteTpWait,     // <----- callback
        0,
        0,
        NULL
    );

    if (lStatus != ERROR_SUCCESS) {
        MessageBoxA(NULL,
            "Failed to associate wait completion packet",
            "Error",
            MB_ICONERROR);

        return FALSE;
    }

    // call the callback
    SetEvent(hEvent);

    return TRUE;
}

HANDLE DupHandle(HANDLE hTargetProcess, CONST WCHAR* wszHandleTypeName, UINT32 nDesiredAccess)
{
    PPROCESS_HANDLE_SNAPSHOT_INFORMATION pProcessSnapshotInfo = { 0 };
    PPUBLIC_OBJECT_TYPE_INFORMATION sObjInfo = { 0 };

    funcNtQueryInformationProcess pQueryProcInfo = NULL;
    funcNtQueryObject pQueryObject = NULL;

    HANDLE hDupHandle = INVALID_HANDLE_VALUE;
    UINT32 nTotalHandles = NULL;
    UINT32 nHandleInfoSz = NULL;
    UINT32 nObjReturnSz = NULL;
    NTSTATUS lStatus = NULL;
    BOOL bHandleFound = FALSE;

    pQueryProcInfo = (funcNtQueryInformationProcess)GetProcAddress(
        GetModuleHandleW(L"NTDLL.DLL"), "NtQueryInformationProcess");

    pQueryObject = (funcNtQueryObject)GetProcAddress(
        GetModuleHandleW(L"NTDLL.DLL"), "NtQueryObject");

    if (!pQueryProcInfo || !pQueryObject) {
        hDupHandle = INVALID_HANDLE_VALUE;

        goto cleanup;
    }

    if (!GetProcessHandleCount(hTargetProcess,
        (PDWORD)&nTotalHandles
    )) {
        MessageBoxA(NULL,
            "Failed to get process handle count",
            "Error",
            MB_ICONERROR
        );

        goto cleanup;
    }

    nHandleInfoSz = sizeof(PROCESS_HANDLE_SNAPSHOT_INFORMATION) +
        ((nTotalHandles + 15) * sizeof(PROCESS_HANDLE_TABLE_ENTRY_INFO));

    pProcessSnapshotInfo = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nHandleInfoSz);

    if (pProcessSnapshotInfo == NULL) {
        MessageBoxA(NULL,
            "Failed to allocate memory for process snapshot info",
            "Error",
            MB_ICONERROR
        );

        goto cleanup;
    }

    lStatus = pQueryProcInfo(
        hTargetProcess,
        (PROCESSINFOCLASS)51,
        pProcessSnapshotInfo,
        nHandleInfoSz,
        NULL
    );

    if (lStatus != ERROR_SUCCESS) {
        MessageBoxA(NULL,
            "Failed to query process information",
            "Error",
            MB_ICONERROR
        );

        goto cleanup;
    }

    for (SIZE_T i = 0; i < pProcessSnapshotInfo->NumberOfHandles; i++) {
        if (!DuplicateHandle(hTargetProcess,
            pProcessSnapshotInfo->Handles[i].HandleValue,
            GetCurrentProcess(),
            &hDupHandle,
            nDesiredAccess,
            FALSE,
            NULL
        )) {
            continue;
        }

        pQueryObject(hDupHandle,
            ObjectTypeInformation,
            NULL,
            NULL,
            (PULONG)&nObjReturnSz
        );

        sObjInfo = (PPUBLIC_OBJECT_TYPE_INFORMATION)
            HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nObjReturnSz);

        if (sObjInfo == NULL)
            break;

        lStatus = pQueryObject(hDupHandle,
            ObjectTypeInformation,
            sObjInfo,
            nObjReturnSz,
            NULL
        );

        if (lStatus != ERROR_SUCCESS) {
            MessageBoxA(NULL,
                "Failed to query object information",
                "Error",
                MB_ICONERROR
            );

            break;
        }

        if (wcsncmp(wszHandleTypeName, sObjInfo->TypeName.Buffer,
            wcslen(wszHandleTypeName)) == 0
            ) {
            bHandleFound = TRUE;
            break;
        }

        HeapFree(GetProcessHeap(), 0, sObjInfo);
    }

    if (!bHandleFound)
        hDupHandle = INVALID_HANDLE_VALUE;

cleanup:
    if (pProcessSnapshotInfo)
        HeapFree(GetProcessHeap(), 0, pProcessSnapshotInfo);

    if (sObjInfo)
        HeapFree(GetProcessHeap(), 0, sObjInfo);

    return hDupHandle;
}


VOID GetSharedPages(HANDLE hRoblox, DWORD64* dwPageList)
{
    HMODULE modules[1024];
    DWORD cbNeeded;

    if (!EnumProcessModules(hRoblox,
        modules,
        sizeof(modules),
        &cbNeeded
    )) {
        printf("Failed to enumerate modules. Error: %lu\n", GetLastError());

        CloseHandle(hRoblox);
        return;
    }

    size_t moduleCount = cbNeeded / sizeof(HMODULE);
    printf("Scanning %zu modules...\n", moduleCount);

    INT nPageCount = 0;

    for (size_t i = 0; i < moduleCount; i++)
    {
        MODULEINFO moduleInfo;

        if (!GetModuleInformation(hRoblox,
            modules[i],
            &moduleInfo,
            sizeof(moduleInfo)
        )) {
            printf("Failed to get module information. Error: %lu\n", GetLastError());

            continue;
        }

        WCHAR moduleName[MAX_PATH];
        if (!GetModuleFileNameExW(hRoblox,
            modules[i],
            moduleName,
            MAX_PATH
        )) {
            printf("Failed to get module name. Error: %lu\n", GetLastError());
        }

        if (wcsstr(moduleName, L"Roblox") != NULL)
            continue;

        DWORD_PTR address = (DWORD_PTR)moduleInfo.lpBaseOfDll;
        DWORD_PTR endAddress = address + moduleInfo.SizeOfImage;

        while (address < endAddress)
        {
            MEMORY_BASIC_INFORMATION mbi;

            if (VirtualQueryEx(hRoblox,
                (LPCVOID)address,
                &mbi,
                sizeof(mbi)
            ) == 0) {
                address += PAGE_SIZE;

                continue;
            }

            if (mbi.State != MEM_COMMIT)
            {
                address += mbi.RegionSize;

                continue;
            }

            PSAPI_WORKING_SET_EX_INFORMATION wsInfo = { 0 };
            wsInfo.VirtualAddress = (PVOID)address;

            if (!QueryWorkingSetEx(hRoblox,
                &wsInfo,
                sizeof(wsInfo)
            )) {
				printf("Failed to query working set !! skipping ...");

				address += mbi.RegionSize;
				continue;
            }

            if (!(wsInfo.VirtualAttributes.Shared == 0 &&
                (mbi.Protect & PAGE_EXECUTE_READWRITE
                    || mbi.Protect & PAGE_EXECUTE_READ)))
            {
				address += mbi.RegionSize;

				continue;
            }

            if (nPageCount <= 20) {
                dwPageList[nPageCount++] = address;

                printf("Shared COW page at: 0x%p\n", address);
            }

            address += mbi.RegionSize;
        }
    }
}

BOOL WriteShellcode(HANDLE hProcess, PVOID pPayload, SIZE_T nPayloadSz, PVOID* pRemoteAddress)
{
    /*
        fix for hyperion stripping EXECUTE permissions from allocated memory
        since it allows you to write shellcode to a memory region that is already executable

        how fantastic, though write limit per dll is PAGE_SIZE
    */

    PVOID pRemote = NULL;

    DWORD64 dwPageList[20] = { 0 };
    GetSharedPages(hProcess, &dwPageList);

    for (INT i = 0; i < 20; i++) {
        if (dwPageList[i] == 0)
            break;

        if (sizeof(Shellcode) <= PAGE_SIZE)
            pRemote = (PVOID)dwPageList[i];
        else
            MessageBoxA(NULL,
                "Shellcode size exceeds PAGE_SIZE!! You will have to scatter shellcode!",
                "Error",
                MB_ICONERROR
            );

        break;
    }


    if (pRemote == NULL) {
        MessageBoxA(NULL,
            "Failed to find suitable memory for payload",
            "Error",
            MB_ICONERROR
        );

        return FALSE;
    }

    SIZE_T nBytesWritten = 0;
    if (!WriteProcessMemory(
        hProcess,
        pRemote,
        pPayload,
        nPayloadSz,
        &nBytesWritten)
        || nBytesWritten != nPayloadSz
        ) {
        MessageBoxA(NULL,
            "Failed to write payload into process",
            "Error",
            MB_ICONERROR
        );

        return FALSE;
    }

    DWORD dwOldProtect;
    if (!VirtualProtectEx(hProcess, pRemote, nPayloadSz,
        PAGE_EXECUTE_READ, (PDWORD)&dwOldProtect)
        ) {
        MessageBoxA(NULL,
            "Failed to protect memory region",
            "Error",
            MB_ICONERROR
        );

        return FALSE;
    }

    printf("wrote shellcode at: %p\n", pRemote);

    *pRemoteAddress = pRemote;

    return TRUE;
}


INT GetRobloxPid()
{
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS, 0
    );

    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        MessageBoxA(NULL,
            "Failed to create process snapshot",
            "Error",
            MB_ICONERROR
        );

        goto exit;
    }

    if (!Process32First(hSnapshot, &pe32))
    {
        MessageBoxA(NULL,
            "Failed to get first process",
            "Error",
            MB_ICONERROR
        );

        goto cleanup;
    }

    do
    {
        if (wcscmp(pe32.szExeFile,
            L"RobloxPlayerBeta.exe") == 0
            ) {
            CloseHandle(hSnapshot);

            return pe32.th32ProcessID;
        }

    } while (Process32Next(hSnapshot, &pe32));

cleanup:
    CloseHandle(hSnapshot);
exit:
    return 0;
}

INT main()
{
    PVOID pRemotePayload = NULL;
    HWND hRoblox = FindWindowA(NULL, "Roblox");

    if (!hRoblox) {
        MessageBoxA(NULL,
            "Failed to find Roblox window",
            "Error",
            MB_ICONERROR
        );

        return 1;
    }

    DWORD nPid = 0;
    DWORD nTid = GetWindowThreadProcessId(hRoblox, &nPid);

    while (!nPid || !nTid) {
        printf("Failed to get Roblox PID/TID\n");

        Sleep(1000);

        nTid = GetWindowThreadProcessId(hRoblox, &nPid);
    }

    printf("Roblox PID: %d\n", nPid);

    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        nPid
    );

    if (hProcess == NULL) {
        MessageBoxA(NULL,
            "Failed to open Roblox",
            "Error",
            MB_ICONERROR
        );

        return 1;
    }

    HANDLE hIoPort = DupHandle(hProcess,
        L"IoCompletion",
        IO_COMPLETION_ALL_ACCESS
    );

    if (hIoPort == INVALID_HANDLE_VALUE) {
        MessageBoxA(NULL,
            "Failed to hijack process I/O port",
            "Error",
            MB_ICONERROR
        );

        return 1;
    }

    if (!WriteShellcode(hProcess,
        Shellcode,
        sizeof(Shellcode),
        &pRemotePayload)
        ) {
        MessageBoxA(NULL,
            "Failed to inject shellcode",
            "Error",
            MB_ICONERROR
        );

        return 1;
    }

    if (!Execute(hProcess,
        pRemotePayload,
        hIoPort)
        ) {
        MessageBoxA(NULL,
            "Failed to execute shellcode",
            "Error",
            MB_ICONERROR
        );

        return 1;
    }

    printf("shellcode executed!!\n");

    return 0;
}