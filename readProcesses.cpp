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

int main() {
	HANDLE hServer = WTS_CURRENT_SERVER_HANDLE;
	DWORD pLevel = 1;
	DWORD SessionId = WTS_ANY_SESSION;
	PWTS_PROCESS_INFO_EX ppProcessInfo = NULL;
	DWORD pCount = 0;
	LPWSTR sid = NULL;
	PTOKEN_OWNER tOwner;
	DWORD error;
	TCHAR userName[MAX_ACCOUNT_LEN];
	DWORD nameLen = MAX_ACCOUNT_LEN;
	TCHAR domainName[MAX_ACCOUNT_LEN];
	DWORD domainLen = MAX_ACCOUNT_LEN;
	SID_NAME_USE accountType;

	//Attempt to set SeDebugPrivilege
	HANDLE processTokenHandle;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &processTokenHandle)) {
		printf("[!] Error: Cannot retrieve process token. Error code: %u\n", GetLastError());
		return 1;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
		printf("[!] Error: Cannot lookup privilege value. Error code: %u\n", GetLastError());
		CloseHandle(processTokenHandle);
		return 1;
	}

	TOKEN_PRIVILEGES privs;
	privs.PrivilegeCount = 1;
	privs.Privileges[0].Luid = luid;
	privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(processTokenHandle, FALSE, &privs, 0, NULL, NULL)) {
		printf("[!] Error: Cannot set SeDebugPrivilege in process token. Error code: %u\n\n", GetLastError());
	}
	else {
		printf("[*] SeDebugPrivilege enabled\n\n");
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
	CloseHandle(processTokenHandle);
	WTSFreeMemoryEx(WTSTypeProcessInfoLevel1, ppProcessInfo, pCount);
	ppProcessInfo = NULL;
	LocalFree(sid);

	getchar();
	return 0;
}