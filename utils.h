#include <stdio.h>
#include <Windows.h>
#include <winuser.h>
#include <WinBase.h>
#include <tchar.h>
#include <securitybaseapi.h>
#include <processthreadsapi.h>
#include <winnt.h>
#include <shellapi.h>
#include <libloaderapi.h>

#define MAX_LENGTH 1024

bool compLuid(LUID a, LUID b);

bool setDebugPriv();

void relaunchAsAdmin();
