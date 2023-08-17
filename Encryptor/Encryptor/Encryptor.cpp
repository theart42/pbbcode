#include <windows.h>
#include <Winbase.h>
#include <iostream>
#include <string>
#include "shellcode.h"

#pragma warning(disable:4996)

using namespace std;

#define MAXSHELLCODESIZE 4096

// Function prototype for SystemFunction033
typedef NTSTATUS(WINAPI* _SystemFunction033)(
	struct ustring* memoryRegion,
	struct ustring* keyPointer);

struct ustring {
	DWORD Length;
	DWORD MaximumLength;
	PVOID Buffer;
} _data, key, _data2;

int main(int argc, char **argv)
{

	unsigned char sSystemFunction033[] = { 'S','y','s','t','e','m','F','u','n','c','t','i','o','n','0','3','3', 0x0 };
	unsigned char sadvapi32[] = { 'a','d','v','a','p','i','3','2',0x0 };
	unsigned char buf[MAXSHELLCODESIZE + 1];
	unsigned int  bytesread;
	FILE *fp;
	int i;

	if (argc < 2 || argc > 4) {
		fprintf(stderr, "Wrong number of arguments: %s INPUTFILENAME (e.g. shellcode.bin) OUTPUTFILENAME (e.g. shellcode.enc)\n", argv[0]);
		return 0;
	}

	char *infile = argv[1];
	char *outfile = argv[2];

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

	_SystemFunction033 SystemFunction033 = (_SystemFunction033)GetProcAddress(LoadLibrary((LPCSTR)sadvapi32), (LPCSTR)sSystemFunction033);

	char _key[] = "advapi32.dll";

	// int shellcode_size = sizeof(shellcode);

	printf("key length is %d\n", sizeof _key);
	printf("shellcode length is %d, %d\n", bytesread, sizeof buf);

	PVOID buffer = VirtualAlloc(NULL, sizeof(shellcode), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	// Copy the character array to the allocated memory using memcpy.
	std::memcpy(buffer, buf, bytesread);

	//just setting null values at shellcode, cause why not 
	//memset(shellcode, 0, shellcode_size);

	//Setting key values
	key.Buffer = (&_key);
	key.Length = sizeof _key;
	key.MaximumLength = sizeof _key;

	//Setting shellcode in the struct for Systemfunction033
	_data.Buffer = buf;
	_data.Length = bytesread;
	_data.MaximumLength = bytesread;

	fprintf(stderr, "unencrypted data:\n");
	for (i = 0; i < bytesread; i++) {
		fprintf(stderr, "0x%02x ", ((unsigned char *)buf)[i]);
	}
	fprintf(stderr, "\n");

	//Calling Systemfunction033
	SystemFunction033(&_data, &key);

	fprintf(stderr, "encrypted data:\n");
	for (i = 0; i < bytesread; i++) {
		fprintf(stderr, "0x%02x ", ((unsigned char *)buf)[i]);
	}
	fprintf(stderr, "\n");

	//Writing encrypted shellcode to bin file
	if ((fp = fopen(outfile, "wb")) == NULL) {
		fprintf(stderr, "Cannot create outputfile %s\n", outfile);
		exit(1);
	}

	// Write the contents of the pvoid pointer to the file. They contents should be encrypted
	fwrite(buf, bytesread, 1, fp);

	// Close the file
	fclose(fp);

	//Calling Systemfunction033 again
	SystemFunction033(&_data, &key);

	fprintf(stderr, "decrypted data:\n");
	for (i = 0; i < bytesread; i++) {
		fprintf(stderr, "0x%02x ", ((unsigned char *)buf)[i]);
	}
	fprintf(stderr, "\n");


	//instead if you want to print out the mem contents 
	/*
	for (unsigned int i = 0; i < _data.Length; i++)
	{
		cout << std::hex << (unsigned int)*((unsigned char*)buffer + i) << " ";
	}
	*/

	return 0;
}
