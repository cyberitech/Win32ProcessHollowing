// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


#include "BinaryExecutor.h"
#include <string.h>


int BinaryExecutor::RunPortableExecutable(const char* PackedExe)
{

	IMAGE_DOS_HEADER* DOSHeader = PIMAGE_DOS_HEADER(PackedExe);		//declare executable headers
	IMAGE_NT_HEADERS* NtHeader = PIMAGE_NT_HEADERS(DWORD(PackedExe) + DOSHeader->e_lfanew);
	IMAGE_SECTION_HEADER* sHeader;
	PROCESS_INFORMATION procInfo;
	STARTUPINFOA startupInfo;
	CONTEXT* processerState;
	DWORD* baseImg; 
	void* entryPointAddress; 
	int count;
	char CurrentFilePath[1024];



	GetModuleFileNameA(NULL, CurrentFilePath, 1024); // path to current executable
	ZeroMemory(&procInfo, sizeof(procInfo));
	ZeroMemory(&startupInfo, sizeof(startupInfo));
	if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
		return 1;

	

	if (!CreateProcessA(CurrentFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startupInfo, &procInfo))
		return 1;

	processerState = LPCONTEXT(VirtualAlloc(NULL, sizeof(processerState), MEM_COMMIT, PAGE_READWRITE));
	processerState->ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(procInfo.hThread, LPCONTEXT(processerState)))
		return 1;
	
	ReadProcessMemory(procInfo.hProcess, LPCVOID(processerState->Ebx + 8), LPVOID(&baseImg), 4, 0);
	entryPointAddress = VirtualAllocEx(procInfo.hProcess, LPVOID(NtHeader->OptionalHeader.ImageBase), NtHeader->OptionalHeader.SizeOfImage, 0x3000, PAGE_EXECUTE_READWRITE);

	/*	
	This is the function signature of interest that will be hooked:

		BOOL WriteProcessMemory
		(
			HANDLE  hProcess,
			LPVOID  lpBaseAddress,
			LPCVOID lpBuffer,
			SIZE_T  nSize,
			SIZE_T  *lpNumberOfBytesWritten
		);
	*/
	WriteProcessMemory(procInfo.hProcess, entryPointAddress, PackedExe, NtHeader->OptionalHeader.SizeOfHeaders, NULL);

	auto processHeader = [entryPointAddress, PackedExe, DOSHeader, sHeader, procInfo, count](auto entryPointAddress, auto PackedExe, auto DOSHeader, auto sHeader, auto procInfo, auto count)
	{
		sHeader = PIMAGE_SECTION_HEADER(DWORD(PackedExe) + DOSHeader->e_lfanew + 248 + (count * 40));
		WriteProcessMemory(procInfo.hProcess, LPVOID(DWORD(entryPointAddress) + sHeader->VirtualAddress), LPVOID(DWORD(PackedExe) + sHeader->PointerToRawData), sHeader->SizeOfRawData, 0);
	};

	for (count = 0; count < NtHeader->FileHeader.NumberOfSections; count++)
		processHeader(entryPointAddress, PackedExe, DOSHeader, sHeader, procInfo, count);

	WriteProcessMemory(procInfo.hProcess, LPVOID(processerState->Ebx + 8), LPVOID(&NtHeader->OptionalHeader.ImageBase), 4, 0);


	processerState->Eax = DWORD(entryPointAddress) + NtHeader->OptionalHeader.AddressOfEntryPoint;
	SetThreadContext(procInfo.hThread, LPCONTEXT(processerState));
	ResumeThread(procInfo.hThread);
	WaitForSingleObject(procInfo.hProcess, 1000);
	DWORD exitCode;
	GetExitCodeProcess(procInfo.hProcess, &exitCode);
	success = !exitCode;
	printf("Final PID: %d", procInfo.dwProcessId);
	return exitCode;
}



BinaryExecutor::BinaryExecutor(const char* packedExe)
{
	success = RunPortableExecutable(packedExe) == 0;
	return;


}

BinaryExecutor::~BinaryExecutor()
{
}







