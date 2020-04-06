#include "utils.h"

int main() {
	HANDLE hServer = WTS_CURRENT_SERVER_HANDLE;
	DWORD pLevel = 1;
	DWORD SessionId = WTS_ANY_SESSION;
	PWTS_PROCESS_INFO_EX ppProcessInfo = NULL;
	DWORD pCount = 0;
	LPWSTR sid = NULL;
	PTOKEN_OWNER tOwner;
	DWORD error;
	TCHAR userName[MAX_LENGTH] = {NULL};
	DWORD nameLen = MAX_LENGTH;
	TCHAR domainName[MAX_LENGTH] = {NULL};
	DWORD domainLen = MAX_LENGTH;
	SID_NAME_USE accountType;

	if (!setDebugPriv()) {
		printf("[!] Error: Cannot set seDebugPrivilege. Relaunching process as Administrator.\n");
		relaunchAsAdmin();
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

	getchar();
	return 0;
}