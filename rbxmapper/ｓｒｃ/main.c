#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>

#include "defs.h"

unsigned char Shellcode[] = {
        0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x74, 0x24, 0x18, 0x55, 0x57,
        0x41, 0x56, 0x48, 0x8B, 0xEC, 0x48, 0x83, 0xEC, 0x70, 0x65, 0x48, 0x8B,
        0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x33, 0xD2, 0x49, 0xB8, 0x47, 0x65,
        0x74, 0x50, 0x72, 0x6F, 0x63, 0x41, 0x48, 0x8B, 0x48, 0x18, 0x48, 0x8B,
        0x41, 0x20, 0x48, 0x8B, 0x08, 0x48, 0x8B, 0x01, 0x4C, 0x8B, 0x70, 0x20,
        0x49, 0x63, 0x46, 0x3C, 0x46, 0x8B, 0x8C, 0x30, 0x88, 0x00, 0x00, 0x00,
        0x43, 0x8B, 0x44, 0x31, 0x20, 0x49, 0x03, 0xC6, 0x48, 0x63, 0x08, 0x4E,
        0x39, 0x04, 0x31, 0x74, 0x17, 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x63, 0x48, 0x04, 0x48, 0x8D, 0x40, 0x04, 0xFF, 0xC2, 0x4E, 0x39,
        0x04, 0x31, 0x75, 0xF0, 0x43, 0x8B, 0x4C, 0x31, 0x24, 0x48, 0xB8, 0x4C,
        0x6F, 0x61, 0x64, 0x4C, 0x69, 0x62, 0x72, 0x49, 0x03, 0xCE, 0x48, 0x63,
        0xD2, 0x4C, 0x0F, 0xBF, 0x04, 0x51, 0x48, 0x8D, 0x55, 0xC0, 0x43, 0x8B,
        0x4C, 0x31, 0x1C, 0x49, 0x03, 0xCE, 0x4A, 0x63, 0x1C, 0x81, 0x49, 0x8B,
        0xCE, 0x49, 0x03, 0xDE, 0x48, 0x89, 0x45, 0xC0, 0x48, 0xC7, 0x45, 0xC8,
        0x61, 0x72, 0x79, 0x41, 0xFF, 0xD3, 0x48, 0xB9, 0x75, 0x73, 0x65, 0x72,
        0x33, 0x32, 0x2E, 0x64, 0x48, 0xC7, 0x45, 0xC8, 0x6C, 0x6C, 0x00, 0x00,
        0x48, 0x89, 0x4D, 0xC0, 0x48, 0x8D, 0x4D, 0xC0, 0xFF, 0xD0, 0x48, 0xB9,
        0x4D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x42, 0x48, 0xC7, 0x45, 0xC8,
        0x6F, 0x78, 0x41, 0x00, 0x48, 0x89, 0x4D, 0xC0, 0x48, 0x8D, 0x55, 0xC0,
        0x48, 0x8B, 0xC8, 0xFF, 0xD3, 0x48, 0x8B, 0xF0, 0x48, 0xC7, 0x45, 0xC8,
        0x21, 0x21, 0x00, 0x00, 0x48, 0xB8, 0x68, 0x65, 0x79, 0x20, 0x67, 0x75,
        0x79, 0x73, 0x4C, 0x8D, 0x45, 0xC0, 0x45, 0x33, 0xC9, 0x48, 0x89, 0x45,
        0xC0, 0x48, 0x8D, 0x55, 0xC0, 0x33, 0xC9, 0xFF, 0xD6, 0x48, 0xB8, 0x77,
        0x6F, 0x6E, 0x64, 0x65, 0x72, 0x66, 0x75, 0x48, 0xC7, 0x45, 0xD0, 0x72,
        0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0xC0, 0x4C, 0x8D, 0x45, 0xCA, 0x48,
        0xB8, 0x6C, 0x20, 0x77, 0x65, 0x61, 0x74, 0x68, 0x65, 0x48, 0x8D, 0x55,
        0xC0, 0x45, 0x33, 0xC9, 0x48, 0x89, 0x45, 0xC8, 0x33, 0xC9, 0xFF, 0xD6,
        0x48, 0xB8, 0x41, 0x6C, 0x6C, 0x6F, 0x63, 0x43, 0x6F, 0x6E, 0x48, 0xC7,
        0x45, 0xE8, 0x73, 0x6F, 0x6C, 0x65, 0x48, 0x8D, 0x55, 0xE0, 0x48, 0x89,
        0x45, 0xE0, 0x49, 0x8B, 0xCE, 0xFF, 0xD3, 0xFF, 0xD0, 0x48, 0xB8, 0x47,
        0x65, 0x74, 0x53, 0x74, 0x64, 0x48, 0x61, 0x48, 0xC7, 0x45, 0xE8, 0x6E,
        0x64, 0x6C, 0x65, 0x48, 0x8D, 0x55, 0xE0, 0x48, 0x89, 0x45, 0xE0, 0x49,
        0x8B, 0xCE, 0xFF, 0xD3, 0xB9, 0xF5, 0xFF, 0xFF, 0xFF, 0xFF, 0xD0, 0x48,
        0x8B, 0xF8, 0x48, 0x8D, 0x55, 0xE0, 0x48, 0xB8, 0x57, 0x72, 0x69, 0x74,
        0x65, 0x43, 0x6F, 0x6E, 0x49, 0x8B, 0xCE, 0x48, 0x89, 0x45, 0xE0, 0x48,
        0xB8, 0x73, 0x6F, 0x6C, 0x65, 0x41, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45,
        0xE8, 0xFF, 0xD3, 0x48, 0x8B, 0xD8, 0x48, 0xC7, 0x44, 0x24, 0x20, 0x00,
        0x00, 0x00, 0x00, 0x48, 0xB8, 0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x52,
        0x4F, 0x4C, 0x8D, 0x4D, 0x20, 0x48, 0x89, 0x45, 0xE0, 0x48, 0x8D, 0x55,
        0xE0, 0x48, 0xB8, 0x42, 0x4C, 0x4F, 0x58, 0x21, 0x0A, 0x00, 0x00, 0x41,
        0xB8, 0x0E, 0x00, 0x00, 0x00, 0x48, 0x8B, 0xCF, 0x48, 0x89, 0x45, 0xE8,
        0xFF, 0xD3, 0x48, 0xB8, 0x48, 0x6F, 0x77, 0x20, 0x61, 0x72, 0x65, 0x20,
        0x48, 0x89, 0x45, 0xE0, 0x48, 0xB8, 0x79, 0x61, 0x3F, 0x3F, 0x20, 0x3A,
        0x70, 0x00, 0x4C, 0x8D, 0x4D, 0x20, 0x48, 0x89, 0x45, 0xE8, 0x41, 0xB8,
        0x0F, 0x00, 0x00, 0x00, 0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00,
        0x00, 0x48, 0x8D, 0x55, 0xE0, 0x48, 0x8B, 0xCF, 0xFF, 0xD3, 0x48, 0xB8,
        0x63, 0x6C, 0x69, 0x63, 0x6B, 0x20, 0x6D, 0x65, 0x48, 0xC7, 0x45, 0xD0,
        0x68, 0x21, 0x00, 0x00, 0x48, 0x89, 0x45, 0xC0, 0x4C, 0x8D, 0x45, 0xCC,
        0x48, 0xB8, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x72, 0x61, 0x73, 0x48, 0x8D,
        0x55, 0xC0, 0x45, 0x33, 0xC9, 0x48, 0x89, 0x45, 0xC8, 0x33, 0xC9, 0xFF,
        0xD6, 0x4C, 0x8D, 0x5C, 0x24, 0x70, 0x49, 0x8B, 0x5B, 0x28, 0x49, 0x8B,
        0x73, 0x30, 0x49, 0x8B, 0xE3, 0x41, 0x5E, 0x5F, 0x5D, 0xC3 
};

BOOL Execute(HANDLE hRoblox, PVOID pPayloadAddress, HANDLE hIoPort)
{
    funcNtAssociateWaitCompletionPacket pNtAssociateWaitCompletionPacket = NULL;
    PVOID pRemoteTpDirect =     NULL;
    PVOID pRemoteTpWait =       NULL;
    HANDLE hEvent =             NULL;
    PFULL_TP_WAIT pTpWait =     NULL;
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

    hEvent = CreateEventW(NULL, 
        FALSE, 
        FALSE, 
        L"peanuts"
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
    PPROCESS_HANDLE_SNAPSHOT_INFORMATION pProcessSnapshotInfo =     { 0 };
    PPUBLIC_OBJECT_TYPE_INFORMATION sObjInfo =                      { 0 };

    funcNtQueryInformationProcess pQueryProcInfo = NULL;
    funcNtQueryObject pQueryObject =               NULL;

    HANDLE hDupHandle =         INVALID_HANDLE_VALUE;
    UINT32 nTotalHandles =      NULL;
    UINT32 nHandleInfoSz =      NULL;
    UINT32 nObjReturnSz =       NULL;
    NTSTATUS lStatus =          NULL;
    BOOL bHandleFound =         FALSE;

    pQueryProcInfo = (funcNtQueryInformationProcess)GetProcAddress(
        GetModuleHandleW(L"NTDLL.DLL"), "NtQueryInformationProcess");

    pQueryObject = (funcNtQueryObject)GetProcAddress(
        GetModuleHandleW(L"NTDLL.DLL"), "NtQueryObject");

    if (!pQueryProcInfo || !pQueryObject) {
        hDupHandle = INVALID_HANDLE_VALUE;
        
        goto cleanup;
    }

    if (!GetProcessHandleCount(hTargetProcess, 
        (PDWORD)&nTotalHandles)
    ) {
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

BOOL WriteShellcode(HANDLE hProcess, PVOID pPayload, SIZE_T nPayloadSz, PVOID* pRemoteAddress)
{
    //PVOID pRemote = VirtualAllocEx(hProcess,
    //    NULL,
    //    nPayloadSz,
    //    MEM_COMMIT | MEM_RESERVE,
    //    PAGE_READWRITE
    //);

	/* 
		temporary fix for hyperion stripping EXECUTE permissions from allocated memory
		since it allows you to write shellcode to a memory region that is already executable

		how fantastic, though write limit per dll is PAGE_SIZE
    */
	HMODULE hUcrtBase = GetModuleHandleW(L"ucrtbase.dll");

	if (!hUcrtBase) {
		MessageBoxA(NULL,
			"Failed to get ucrtbase.dll handle",
			"Error",
			MB_ICONERROR
		);

		return FALSE;
	}

	FARPROC pSinF = GetProcAddress(hUcrtBase, "sinf");

	PVOID pRemote = (PVOID)pSinF;

    if (pRemote == NULL) {
		MessageBoxA(NULL, 
            "Failed to allocate memory for payload", 
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

INT main()
{
    PVOID remotePayload = NULL;
	//HWND hRoblox = FindWindowA(NULL, "Untitled - Notepad");
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

#define PAGE_SIZE 0x1000

    if (sizeof(Shellcode) > PAGE_SIZE)
    {
		MessageBoxA(NULL,
			"Shellcode size exceeds PAGE_SIZE!! You will have to scatter shellcode!",
			"Error",
			MB_ICONERROR
		);

		return 1;
	}

	if (!WriteShellcode(hProcess, 
        Shellcode, 
        sizeof(Shellcode), 
        &remotePayload)
    ) {
		MessageBoxA(NULL, 
            "Failed to inject shellcode", 
            "Error", 
            MB_ICONERROR
        );

		return 1;
	}

	if (!Execute(hProcess, 
        remotePayload, 
        hIoPort)
    ) {
		MessageBoxA(NULL, 
            "Failed to execute shellcode", 
            "Error", 
            MB_ICONERROR
        );

		return 1;
	}

	printf("shellcode executed..\n");
	return 0;
}
