#include <stdio.h>
#include <windows.h>
#include <wtsapi32.h>
#include <winuser.h>
#include <sddl.h>
#include <WinBase.h>
#include <tchar.h>
#include <winnt.h>

#pragma comment(lib, "wtsapi32.lib")

#define MAX_ACCOUNT_LEN 1024

int main() {
    HANDLE hServer = WTS_CURRENT_SERVER_HANDLE;
    DWORD pLevel = 1;
    DWORD SessionId = WTS_ANY_SESSION;
    PWTS_PROCESS_INFO_EX ppProcessInfo = NULL;
    DWORD pCount = 0;
	LPWSTR sid = NULL;

    if (!WTSEnumerateProcessesEx(hServer, &pLevel, SessionId, (LPWSTR*)&ppProcessInfo, &pCount)) {
        printf("[!] Error: Cannot retrieve processes\n");
        return 1;
    }

    printf("Number of processes: %d\n\n", pCount);
    printf("PID\tProcess Name\tSID\tAccount\n");

    for (DWORD i = 0; i < pCount; i++) {
        wprintf(L"%d\t%s\t", ppProcessInfo[i].ProcessId, ppProcessInfo[i].pProcessName);


        if (ConvertSidToStringSid(ppProcessInfo[i].pUserSid, &sid)) {
            wprintf(L"%s\t", sid);
        }
        else {
            printf("-\t");
        }
       
        TCHAR userName[MAX_ACCOUNT_LEN];
        DWORD nameLen = MAX_ACCOUNT_LEN;
        TCHAR domainName[MAX_ACCOUNT_LEN];
        DWORD domainLen = MAX_ACCOUNT_LEN;
        SID_NAME_USE accountType;

        if (LookupAccountSid(NULL, ppProcessInfo[i].pUserSid, userName, &nameLen, domainName, &domainLen, &accountType)) {
            wprintf(L"%s\\%s", domainName, userName);
        }
        else {
            printf("-");
        }
		
        printf("\n");
    }

    WTSFreeMemoryEx(WTSTypeProcessInfoLevel1, ppProcessInfo, pCount);
    ppProcessInfo = NULL;
	LocalFree(sid);

    return 0;
}