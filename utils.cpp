#include "utils.h"

bool compLuid(LUID a, LUID b) {
	return (a.HighPart == b.HighPart && a.LowPart == b.LowPart);
}

bool setDebugPriv() {
	HANDLE processTokenHandle;
	LUID debugLuid;
	PTOKEN_PRIVILEGES privs;
	DWORD size = 0;

	//Open process token
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &processTokenHandle)) {
		printf("[!] Error: Cannot retrieve process token. Error code: %u\n", GetLastError());
		return 1;
	}

	//Get seDebugPrivilege Luid
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &debugLuid)) {
		printf("[!] Error: Cannot lookup privilege value. Error code: %u\n", GetLastError());
		CloseHandle(processTokenHandle);
		return FALSE;
	}

	//Get struct size
	GetTokenInformation(processTokenHandle, TokenPrivileges, NULL, 0, &size);
	
	//Allocate memory
	privs = (PTOKEN_PRIVILEGES)malloc(size);

	//Get token privileges
	if (!GetTokenInformation(processTokenHandle, TokenPrivileges, privs, size, &size)) {
		printf("[!] Error: Cannot retrieve token information. Error code: %u\n", GetLastError());
		CloseHandle(processTokenHandle);
		return FALSE;
	}

	//Iterate over token privileges looking for seDebugPrivilege
	BOOL isDebugPrivPresent = FALSE;
	for (DWORD i = 0; i < privs->PrivilegeCount; i++) {
		if (compLuid(privs->Privileges[i].Luid, debugLuid)) {
			isDebugPrivPresent = TRUE;
			break;
		}
	}

	free(privs);

	if (!isDebugPrivPresent) {
		printf("[!] seDebugPrivilege is not present and cannot be enabled\n");
		CloseHandle(processTokenHandle);
		return FALSE;
	}

	//Enable seDebugPrivilege
	TOKEN_PRIVILEGES debugPriv;
	debugPriv.PrivilegeCount = 1;
	debugPriv.Privileges[0].Luid = debugLuid;
	debugPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(processTokenHandle, FALSE, &debugPriv, 0, NULL, NULL)) {
		CloseHandle(processTokenHandle);
		return FALSE;
	}
	else {
		CloseHandle(processTokenHandle);
		return TRUE;
	}
}

void relaunchAsAdmin() {
	SHELLEXECUTEINFO shellExecInfo;
	WCHAR fileName[MAX_LENGTH];

	//Get process fully qualified path
	GetModuleFileName(NULL, fileName, (DWORD)MAX_LENGTH);

	shellExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
	shellExecInfo.fMask = SEE_MASK_DEFAULT;
	shellExecInfo.hwnd = NULL;
	shellExecInfo.lpVerb = L"runas";
	shellExecInfo.lpFile = fileName;
	shellExecInfo.lpParameters = NULL;
	shellExecInfo.lpDirectory = NULL;
	shellExecInfo.nShow = SW_SHOWDEFAULT;


	ShellExecuteEx(&shellExecInfo);

}
