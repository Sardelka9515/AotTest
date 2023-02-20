// CppRun.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <winternl.h>	
#include <MinHook.h>
#include <string>
#include <map>
#include <vector>

using namespace std;

typedef NTSTATUS(WINAPI* pNtQIT)(HANDLE, LONG, PVOID, ULONG, PULONG);
#define _WIN32_WINNT 0x0500 
#define STATUS_SUCCESS    ((NTSTATUS)0x00000000L)
#define ThreadQuerySetWin32StartAddress 9
#define NativeAOT
#ifdef NativeAOT
const LPCWSTR DllName = L"AOT.dll";
const LPCSTR EntryPoint = "Hello";
#else
const LPCWSTR DllName = L"CppDll.dll";
const LPCSTR EntryPoint = "?Hello@@YAXXZ";
#endif

template<class C, typename T>
bool contains(C&& c, T e) { return find(begin(c), end(c), e) != end(c); };

map<PVOID, PVECTORED_EXCEPTION_HANDLER> VectoredExceptionHandlers;

DWORD FlsAllocIndecies[256] = { 0 };
int FlsCount = 0;
HMODULE AotModule;

#pragma region HOOK PROC

typedef PTP_POOL(WINAPI* CreateTP)(LPVOID);
CreateTP CreateThreadpoolOrg = NULL;
PTP_POOL CreateThreadPoolHook(LPVOID reserved) {
	auto result = CreateThreadpoolOrg(reserved);
	cout << "CreateThreadPool invoked: " << result << endl;
	return result;
}

typedef BOOL(WINAPI* GetModHExW)(DWORD, LPCWSTR, HMODULE*);
GetModHExW GetModuleHandleExWOrg = NULL;
BOOL GetModuleHandleExWHook(DWORD   dwFlags, LPCWSTR  lpModuleName, HMODULE* phModule) {
	if (dwFlags & GET_MODULE_HANDLE_EX_FLAG_PIN) {
		dwFlags &= ~(GET_MODULE_HANDLE_EX_FLAG_PIN);
		dwFlags |= GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT;
		cout << "GetModuleHandleEx flag modified for module " << lpModuleName << endl;
	}
	return GetModuleHandleExWOrg(dwFlags, lpModuleName, phModule);
}

typedef HANDLE(WINAPI* CreateT)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
CreateT CreateThreadOrg = NULL;
HANDLE CreateThreadHook(LPSECURITY_ATTRIBUTES   lpThreadAttributes, SIZE_T  dwStackSize, LPTHREAD_START_ROUTINE  lpStartAddress, PVOID lpParameter, DWORD  dwCreationFlags, LPDWORD lpThreadId) {
	auto result = CreateThreadOrg(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
	cout << "CreateThread invoked: " << result << endl << flush;
	return result;
}

typedef DWORD(WINAPI* FLSALLOC)(PFLS_CALLBACK_FUNCTION);
FLSALLOC FlsAllocOrg = NULL;
DWORD FlsAllocHook(PFLS_CALLBACK_FUNCTION lpCallback) {
	return FlsAllocIndecies[FlsCount++] = FlsAllocOrg(lpCallback);
}

typedef PVOID(WINAPI* ADDVECEXHAND)(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
ADDVECEXHAND AddVecExHandOrg = NULL;
PVOID AddVectoredExceptionHandlerHook(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler)
{
	HMODULE module;
	GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)Handler, &module);
	auto hHandler = AddVecExHandOrg(First, Handler);
	cout << "Exception handler registered: " << (LPVOID)Handler;
	cout << ", module: " << module;
	cout << ", handle: " << hHandler << endl;
	VectoredExceptionHandlers[hHandler] = Handler;
	return hHandler;
}
#pragma endregion

LPVOID WINAPI GetThreadStartAddress(HANDLE hThread)
{
	NTSTATUS ntStatus;
	HANDLE hDupHandle;
	LPVOID dwStartAddress;

	pNtQIT NtQueryInformationThread = (pNtQIT)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationThread");

	if (NtQueryInformationThread == NULL)
		return 0;

	HANDLE hCurrentProcess = GetCurrentProcess();
	if (!DuplicateHandle(hCurrentProcess, hThread, hCurrentProcess, &hDupHandle, THREAD_QUERY_INFORMATION, FALSE, 0)) {
		SetLastError(ERROR_ACCESS_DENIED);

		return 0;
	}

	ntStatus = NtQueryInformationThread(hDupHandle, ThreadQuerySetWin32StartAddress, &dwStartAddress, sizeof(LPVOID), NULL);
	CloseHandle(hDupHandle);
	if (ntStatus != STATUS_SUCCESS)
		return 0;

	return dwStartAddress;

}
BOOL ListProcessThreads(DWORD dwOwnerPID, DWORD results[] = NULL, LPCWSTR terminateIfMatch = NULL, BOOL print = TRUE)
{
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	// Take a snapshot of all running threads  
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return(FALSE);

	// Fill in the size of the structure before using it. 
	te32.dwSize = sizeof(THREADENTRY32);

	// Retrieve information about the first thread,
	// and exit if unsuccessful
	if (!Thread32First(hThreadSnap, &te32))
	{
		_tprintf(TEXT("Thread32First failed"));  // Show cause of failure
		CloseHandle(hThreadSnap);     // Must clean up the snapshot object!
		return(FALSE);
	}
	int threadCount = 0;
	do
	{
		if (te32.th32OwnerProcessID == dwOwnerPID)
		{
			if (results) {
				results[threadCount] = te32.th32ThreadID;
			}
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, te32.th32ThreadID);
			if (hThread == NULL) throw new exception("Failed to open thread");
			auto startAddr = GetThreadStartAddress(hThread);
			HMODULE threadModule;
			GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
				(LPCWSTR)startAddr,
				&threadModule);

			TCHAR modulePath[256] = { 0 };
			GetModuleFileName(threadModule, modulePath, sizeof(modulePath));
			auto sModulePath = wstring(modulePath);
			auto moduleName = sModulePath.substr(sModulePath.find_last_of(L"/\\") + 1);
			if (terminateIfMatch && !moduleName.compare(terminateIfMatch)) {
				if (TerminateThread(hThread, 0)) {
					cout << "Thread terminated: " << te32.th32ThreadID;
				}
			}
			if (DWORD error = GetLastError()) {
				if (print) {
					cout << "Error: " << error;
				}
				SetLastError(0);
			}
			if (print) {
				cout << "Id: " << te32.th32ThreadID << endl;
				cout << "Start address: " << startAddr << endl;
				wcout << "Module: " << threadModule << " => " << moduleName << endl;
				cout << endl;
			}
			CloseHandle(hThread);
			threadCount++;
		}
	} while (Thread32Next(hThreadSnap, &te32));

	_tprintf(TEXT("\n"));

	//  Don't forget to clean up the snapshot object.
	CloseHandle(hThreadSnap);
	return(TRUE);
}
int main()
{
	if (MH_Initialize() != MH_OK)
	{
		return 1;
	}

	// Not required, just notify when .NET created a thread
	cout << MH_CreateHook(&CreateThread, &CreateThreadHook, (LPVOID*)&CreateThreadOrg) << endl;
	cout << MH_EnableHook(&CreateThread) << endl;

	// Intercept .NET's API call to prevent the module from being pinned in memory, rendering it not unloadable
	cout << MH_CreateHook(&GetModuleHandleExW, &GetModuleHandleExWHook, (LPVOID*)&GetModuleHandleExWOrg) << endl;
	cout << MH_EnableHook(&GetModuleHandleExW) << endl;

	// Intercept FLS creation and manually free them later to prevent access violation crash on process exit
	cout << MH_CreateHook(&FlsAlloc, &FlsAllocHook, (LPVOID*)&FlsAllocOrg) << endl;
	cout << MH_EnableHook(&FlsAlloc) << endl;

	cout << MH_CreateHook(&AddVectoredExceptionHandler, &AddVectoredExceptionHandlerHook, (LPVOID*)&AddVecExHandOrg) << endl;
	cout << MH_EnableHook(&AddVectoredExceptionHandler) << endl;


	cout << "Process module is " << GetModuleHandle(NULL) << endl;
	cout << "press enter to load module" << endl;
	cin.ignore();

load:
	FlsCount = 0;
	AotModule = LoadLibraryW(DllName);
	if (AotModule == NULL) {
		cout << "Invalid dll" << endl;
		return -1;
	}

	cout << "Module loaded: " << AotModule << endl;

	auto proc = GetProcAddress(AotModule, EntryPoint);
	if (proc == NULL) {
		cout << "Invalid entry point" << endl;
		return -1;
	}
	proc();
	// cout << "Threads" << endl;
	// ListProcessThreads(GetCurrentProcessId(), threadsAfter);
	cout << "Press enter to unload" << endl;
	cin.ignore();
	cout << "Unloading module..." << endl;
	ListProcessThreads(GetCurrentProcessId(), NULL, DllName, FALSE);

	// Release all FLS(fiber-local storage) created by .NET
	for (int i = 0; i < FlsCount; i++) {
		cout << "Freeing Fls " << FlsAllocIndecies[i] << " : " << (FlsFree(FlsAllocIndecies[i]) ? "Success" : "Fail") << endl;
	}

	// Search for handlers to unregister
	map<PVOID, PVECTORED_EXCEPTION_HANDLER> toUnregister;
	for (const auto& pair : VectoredExceptionHandlers) {
		HMODULE module;
		GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)pair.second, &module);
		if (module == AotModule) {
			toUnregister[pair.first] = pair.second;
		}
	}


retry:
	if (!FreeLibrary(AotModule)) {
		cout << "Failed to unload module: " << GetLastError() << endl;
		return -1;
	}
	if (AotModule = GetModuleHandle(DllName)) {
		Sleep(20);
		cout << "Module not unloaded, retrying..." << endl;
		goto retry;
	}

	// Remove exception handlers
	for (const auto& pair : toUnregister) {
		bool fSuccess = RemoveVectoredExceptionHandler(pair.first);
		if (fSuccess) {
			cout << "Removed exception handler: " << pair.second << endl;
		}
		else {
			cout << "Failed to remove exception handler: " << pair.second << endl;
			cout << "Error: " << GetLastError() << endl;
		}
	}

	cout << "Unloaded module!" << endl;
	try {
		throw exception("argh");
	}
	catch (exception ex) {
		cout << "caught" << endl; // Handler never called
	}

	cout << "press enter to load again, type \"exit\" to quit" << endl;
	string response;
	getline(cin, response);
	if (response.compare("exit")) {
		goto load;
	}
}
