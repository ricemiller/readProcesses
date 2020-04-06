#include <stdio.h>
#include <windows.h>
#include <wtsapi32.h>
#include <winuser.h>
#include <sddl.h>
#include <WinBase.h>
#include <tchar.h>
#include <winnt.h>
#include <securitybaseapi.h>
#include <processthreadsapi.h>

#pragma comment(lib, "wtsapi32.lib")

#define MAX_ACCOUNT_LEN 1024

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

int main() {
	HANDLE hServer = WTS_CURRENT_SERVER_HANDLE;
	DWORD pLevel = 1;
	DWORD SessionId = WTS_ANY_SESSION;
	PWTS_PROCESS_INFO_EX ppProcessInfo = NULL;
	DWORD pCount = 0;
	LPWSTR sid = NULL;
	PTOKEN_OWNER tOwner;
	DWORD error;
	TCHAR userName[MAX_ACCOUNT_LEN] = {NULL};
	DWORD nameLen = MAX_ACCOUNT_LEN;
	TCHAR domainName[MAX_ACCOUNT_LEN] = {NULL};
	DWORD domainLen = MAX_ACCOUNT_LEN;
	SID_NAME_USE accountType;

	if (!setDebugPriv()) {
		printf("[!] Error: Cannot set seDebugPrivilege\n");
		return 1;
	}

	//Obtain list of processes
	if (!WTSEnumerateProcessesEx(hServer, &pLevel, SessionId, (LPWSTR*)&ppProcessInfo, &pCount)) {
		printf("[!] Error: Cannot retrieve processes\n");
		return 1;
	}

	printf("Number of processes: %d\n\n", pCount);
	printf("PID\tProcess Name\tSID\tAccount\n");

	//List processes properties
	for (DWORD i = 0; i < pCount; i++) {
		wprintf(L"%d\t%s\t", ppProcessInfo[i].ProcessId, ppProcessInfo[i].pProcessName);


		if (ConvertSidToStringSid(ppProcessInfo[i].pUserSid, &sid)) {
			wprintf(L"%s\t", sid);
		}
		else {
			printf("-\t");
		}


		//Extract account from process SID
		LookupAccountSid(NULL, ppProcessInfo[i].pUserSid, userName, &nameLen, domainName, &domainLen, &accountType);
		wprintf(L"%s\\%s", domainName, userName);

		printf("\n");
	}

	//Cleanup
	WTSFreeMemoryEx(WTSTypeProcessInfoLevel1, ppProcessInfo, pCount);
	ppProcessInfo = NULL;
	LocalFree(sid);

	return 0;
}