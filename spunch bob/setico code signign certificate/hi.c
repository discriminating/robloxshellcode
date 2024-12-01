#include <stdint.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#pragma warning (push, 0)
#include <winternl.h>
#include <stdio.h>

__declspec(noinline) void __stdcall shellcode()
{
    PEB* pProcessEnvironmentBlock = (PEB*)__readgsqword(0x60);
    LDR_DATA_TABLE_ENTRY* pKernel32TableEntry = CONTAINING_RECORD(pProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList.Flink->Flink->Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pKernel32TableEntry->DllBase;
    IMAGE_NT_HEADERS* pNtHeader = (IMAGE_NT_HEADERS*)((size_t)pDosHeader + pDosHeader->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* pExports = (IMAGE_EXPORT_DIRECTORY*)((size_t)pDosHeader + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    const int32_t* pNameOffsets = (const int32_t*)((size_t)pDosHeader + pExports->AddressOfNames);

    struct
    {
		uint64_t text0, text1, text2, text3;
    } x;

    x.text0 = 0x41636F7250746547; // `GetProcA`

    INT i = 0;

    while (*(uint64_t*)((size_t)pDosHeader + pNameOffsets[i]) != x.text0)
        ++i;

    const int16_t* pFunctionNameOrdinalOffsets = (const int16_t*)((size_t)pDosHeader + pExports->AddressOfNameOrdinals);
    const int32_t* pFunctionOffsets = (const int32_t*)((size_t)pDosHeader + pExports->AddressOfFunctions);
    
    typedef FARPROC(*GetProcAddressFunc)(HMODULE, const char*);
    GetProcAddressFunc pGetProcAddress = (GetProcAddressFunc)(const void*)((size_t)pDosHeader + pFunctionOffsets[pFunctionNameOrdinalOffsets[i]]);

    HMODULE kernel32Dll = (HMODULE)pDosHeader;

    x.text0 = 0x7262694C64616F4C; // `LoadLibr`
    x.text1 = 0x0000000041797261; // `aryA\0\0\0\0`

    typedef HMODULE(*LoadLibraryAFunc)(const char*);
    LoadLibraryAFunc pLoadLibraryA = (LoadLibraryAFunc)pGetProcAddress(kernel32Dll, (const char*)&x.text0);

    x.text0 = 0x642E323372657375; // `user32.d`
    x.text1 = 0x0000000000006C6C; // `ll\0\0\0\0\0\0`
    HMODULE user32Dll = pLoadLibraryA((const char*)&x.text0);

    x.text0 = 0x426567617373654D; // `MessageB`
    x.text1 = 0x000000000041786F; // `oxA\0\0\0\0\0`

    typedef int32_t(*MessageBoxAFunc)(HWND, const char*, const char*, uint32_t);
    MessageBoxAFunc pMessageBoxA = (MessageBoxAFunc)pGetProcAddress(user32Dll, (const char*)&x.text0);

	x.text0 = 0x7379756720796568; // `hey guys`
	x.text1 = 0x0000000000002121; // `!!\0\0\0\0\0\0`

    pMessageBoxA(NULL, (const char*)&x.text0, (const char*)&x.text0, MB_OK);
}

#pragma warning (pop)

int main()
{
    printf("shellcode ptr: %p\n", shellcode);
	printf("dumping shellcode...\n\n");

	unsigned char* ptr = (unsigned char*)shellcode;

	printf("unsigned char Shellcode[] = { ");

	INT i = 0;

    while (ptr[0] != 0xC3 || ptr[1] != 0xCC)
	{
		if (i % 12 == 0)
			printf("\n\t");
		printf("0x%02X, ", *ptr);
		ptr++;
        i++;
	}

	printf("0x%02X };\n", ptr[0]);

	getchar();

	return 0;
}