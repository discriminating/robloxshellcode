#include <stdint.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#pragma warning (push, 0)
#include <winternl.h>
#include <stdio.h>

#define STR64(a, b, c, d, e, f, g, h) \
    ((uint64_t)(a) | ((uint64_t)(b) << 8) | ((uint64_t)(c) << 16) | ((uint64_t)(d) << 24) | \
     ((uint64_t)(e) << 32) | ((uint64_t)(f) << 40) | ((uint64_t)(g) << 48) | ((uint64_t)(h) << 56))

// shellcode section and no crt :(
__pragma(section(".shellcode", execute, read))

__forceinline void __stdcall popConsole(HMODULE hKernel32, DWORD64 pGetProcAddressAddress)
{
	struct
	{
		uint64_t text0, text1, text2, text3;
	} x;

	// define getprocaddress
	typedef FARPROC(*GetProcAddressFunc)(HMODULE, const char*);
	GetProcAddressFunc pGetProcAddress = (GetProcAddressFunc)pGetProcAddressAddress;

	x.text0 = STR64('A', 'l', 'l', 'o', 'c', 'C', 'o', 'n');
	x.text1 = STR64('s', 'o', 'l', 'e', 0, 0, 0, 0);

	typedef HANDLE(*AllocConsoleFunc)();
	AllocConsoleFunc pAllocConsole = (AllocConsoleFunc)pGetProcAddress(hKernel32, (const char*)&x.text0);

	pAllocConsole();

	x.text0 = STR64('G', 'e', 't', 'S', 't', 'd', 'H', 'a');
	x.text1 = STR64('n', 'd', 'l', 'e', 0, 0, 0, 0);

	typedef HANDLE(*GetStdHandleFunc)(DWORD);
	GetStdHandleFunc pGetStdHandle = (GetStdHandleFunc)pGetProcAddress(hKernel32, (const char*)&x.text0);

	HANDLE hStdOut = pGetStdHandle(STD_OUTPUT_HANDLE);

	// get WriteConsoleA
	x.text0 = STR64('W', 'r', 'i', 't', 'e', 'C', 'o', 'n');
	x.text1 = STR64('s', 'o', 'l', 'e', 'A', 0, 0, 0);

	typedef BOOL(*WriteConsoleAFunc)(HANDLE, const void*, DWORD, LPDWORD, LPVOID);
	WriteConsoleAFunc pWriteConsoleA = (WriteConsoleAFunc)pGetProcAddress(hKernel32, (const char*)&x.text0);

	DWORD dwWritten;

	x.text0 = STR64('H', 'e', 'l', 'l', 'o', ' ', 'R', 'O');
	x.text1 = STR64('B', 'L', 'O', 'X', '!', '\n', 0, 0);

	pWriteConsoleA(hStdOut, (const void*)&x.text0, sizeof("Hello ROBLOX!\n") - 1, &dwWritten, NULL);

	x.text0 = STR64('H', 'o', 'w', ' ', 'a', 'r', 'e', ' ');
	x.text1 = STR64('y', 'a', '?', '?', ' ', ':', 'p', 0);

	pWriteConsoleA(hStdOut, (const void*)&x.text0, sizeof("How are ya?? :p") - 1, &dwWritten, NULL);
}

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

	x.text0 = STR64('G', 'e', 't', 'P', 'r', 'o', 'c', 'A');

    INT i = 0;

    while (*(uint64_t*)((size_t)pDosHeader + pNameOffsets[i]) != x.text0)
        ++i;

    const int16_t* pFunctionNameOrdinalOffsets = (const int16_t*)((size_t)pDosHeader + pExports->AddressOfNameOrdinals);
    const int32_t* pFunctionOffsets = (const int32_t*)((size_t)pDosHeader + pExports->AddressOfFunctions);
    
    typedef FARPROC(*GetProcAddressFunc)(HMODULE, const char*);
    GetProcAddressFunc pGetProcAddress = (GetProcAddressFunc)(const void*)((size_t)pDosHeader + pFunctionOffsets[pFunctionNameOrdinalOffsets[i]]);

    HMODULE kernel32Dll = (HMODULE)pDosHeader;

	x.text0 = STR64('L', 'o', 'a', 'd', 'L', 'i', 'b', 'r');
	x.text1 = STR64('a', 'r', 'y', 'A', 0, 0, 0, 0);

    typedef HMODULE(*LoadLibraryAFunc)(const char*);
    LoadLibraryAFunc pLoadLibraryA = (LoadLibraryAFunc)pGetProcAddress(kernel32Dll, (const char*)&x.text0);

	x.text0 = STR64('u', 's', 'e', 'r', '3', '2', '.', 'd');
	x.text1 = STR64('l', 'l', 0, 0, 0, 0, 0, 0);
    HMODULE user32Dll = pLoadLibraryA((const char*)&x.text0);

	x.text0 = STR64('M', 'e', 's', 's', 'a', 'g', 'e', 'B');
	x.text1 = STR64('o', 'x', 'A', 0, 0, 0, 0, 0);

    typedef int32_t(*MessageBoxAFunc)(HWND, const char*, const char*, uint32_t);
    MessageBoxAFunc pMessageBoxA = (MessageBoxAFunc)pGetProcAddress(user32Dll, (const char*)&x.text0);

	x.text0 = STR64('h', 'e', 'y', ' ', 'g', 'u', 'y', 's');
	x.text1 = STR64('!', '!', 0, 0, 0, 0, 0, 0);

    pMessageBoxA(NULL, (const char*)&x.text0, (const char*)&x.text0, MB_OK);

	x.text0 = STR64('w', 'o', 'n', 'd', 'e', 'r', 'f', 'u');
	x.text1 = STR64('l', ' ', 'w', 'e', 'a', 't', 'h', 'e');
	x.text2 = STR64('r', 0, 0, 0, 0, 0, 0, 0);

	pMessageBoxA(NULL, (const char*)&x.text0, (const char*)&x.text1 + 2, MB_OK);

	//popConsole(kernel32Dll, (DWORD64)pGetProcAddress);

#define GetRaw(addr) (addr + (DWORD64)*(PVOID*)(__readgsqword(0x60) + 0x10) - 0x400000); // PEB->ImageBaseAddress

	typedef int(__cdecl* RobloxPrint)(int, const char*, ...);
	typedef RobloxPrint RobloxPrintFunc;

	RobloxPrintFunc pRobloxPrint = (RobloxPrintFunc)GetRaw(0x016DB520);

	x.text0 = STR64('H', 'e', 'l', 'l', 'o', ' ', 'R', 'O');
	x.text1 = STR64('B', 'L', 'O', 'X', '!', '\n', 0, 0);

	// call directly -- unsafe ! you will be banned !
	pRobloxPrint(0, (const char*)&x.text0); // normal print
	pRobloxPrint(1, (const char*)&x.text0); // information print
	pRobloxPrint(2, (const char*)&x.text0); // warning print
	pRobloxPrint(3, (const char*)&x.text0); // error print

	x.text0 = STR64('c', 'l', 'i', 'c', 'k', ' ', 'm', 'e');
	x.text1 = STR64(' ', 't', 'o', ' ', 'c', 'r', 'a', 's');
	x.text2 = STR64('h', '!', 0, 0, 0, 0, 0, 0);

	pMessageBoxA(NULL, (const char*)&x.text0, (const char*)&x.text1 + 4, MB_OK);
}

#pragma warning (pop)

// back to .text section and crt!
__pragma(section(".text", execute, read, write))

int main()
{
    printf("shellcode ptr: %p\n", shellcode);
	printf("dumping shellcode...\n\n");

	unsigned char* ptr = (unsigned char*)shellcode;

	printf("unsigned char Shellcode[] = { ");

	INT i = 0;

	while (ptr[0] != 0xC3 || ptr[1] != 0x48)
	{
		if (i % 10 == 0)
			printf("\n\t");
		printf("0x%02X, ", *ptr);
		ptr++;
        i++;
	}

	printf("0x%02X };\n", ptr[0]);

	printf("\n\nunsigned int ShellcodeSize = %d;\n", i);

	getchar();

	shellcode();

	getchar();

	return 0;
}