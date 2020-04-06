#include <stdio.h>
#include <Windows.h>
#include <shellapi.h>
#include <wtsapi32.h>
#include <winuser.h>
#include <sddl.h>
#include <WinBase.h>
#include <tchar.h>
#include <securitybaseapi.h>
#include <processthreadsapi.h>
#include <winnt.h>
#include <libloaderapi.h>

#pragma comment(lib, "wtsapi32.lib")

#define MAX_LENGTH 1024

bool compLuid(LUID a, LUID b);

bool setDebugPriv();

void relaunchAsAdmin();
