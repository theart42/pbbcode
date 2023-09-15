#pragma once

typedef VOID(KNORMAL_ROUTINE) (
	IN PVOID NormalContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2);

typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;

// Define function pointers with the correct signatures

typedef NTSTATUS(WINAPI* NtAllocateVirtualMemoryFunc)(
	HANDLE ProcessHandle,
	OUT PVOID* BaseAddress,
	ULONG ZeroBits,
	OUT PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
	);

typedef NTSTATUS(WINAPI* NtWriteVirtualMemoryFunc)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	SIZE_T NumberOfBytesToWrite,
	PSIZE_T NumberOfBytesWritten OPTIONAL
	);

typedef NTSTATUS(WINAPI* NtProtectVirtualMemoryFunc)(
	HANDLE ProcessHandle,
	OUT PVOID* BaseAddress,
	OUT PSIZE_T RegionSize,
	ULONG NewProtect,
	PULONG OldProtect
	);

typedef NTSTATUS(WINAPI* NtQueueApcThreadFunc)(
	HANDLE ThreadHandle,
	PKNORMAL_ROUTINE ApcRoutine,
	PVOID ApcArgument1 OPTIONAL,
	PVOID ApcArgument2 OPTIONAL,
	PVOID ApcArgument3 OPTIONAL
	);

typedef NTSTATUS(WINAPI* NtResumeThreadFunc)(
	HANDLE ThreadHandle,
	OUT PULONG PreviousSuspendCount OPTIONAL
	);

#define ORD_NtAllocateVirtualMemory		0xe2
#define ORD_NtProtectVirtualMemory		0x1d5
#define ORD_NtWriteVirtualMemory		0x2a5
#define ORD_NtQueueApcThread			0x212
#define ORD_NtResumeThread				0x237