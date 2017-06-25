#include <string>
#include <windows.h>
#include <stdio.h>
#include "MinHook.h"

#if defined _M_X64
#pragma comment(lib, "libMinHook.x64.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook.x86.lib")
#endif

// Helper function for MH_CreateHookApi().

template <typename T>
inline MH_STATUS MH_CreateHookApiEx(LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, T** ppOriginal)
{
	return MH_CreateHookApi(pszModule, pszProcName, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}

typedef NTSTATUS (WINAPI *BCRYPTVERIFYSIGNATURE)(BCRYPT_KEY_HANDLE, LPVOID, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);

BCRYPTVERIFYSIGNATURE fpBCryptVerifySignature = NULL;


NTSTATUS WINAPI DetourBCryptVerifySignature(BCRYPT_KEY_HANDLE hKey, LPVOID pPaddingInfo, PUCHAR pbHash, ULONG cbHash, PUCHAR pbSignature, ULONG cbSignature, ULONG dwFlags)
{
	return 0x00000000;
}

DWORD WINAPI MainThread(LPVOID param)
{
	if (MH_Initialize() != MH_OK)
	{
		return 1;
	}

	int ret0 = MH_CreateHookApiEx(L"Bcrypt", "BCryptVerifySignature", &DetourBCryptVerifySignature, &fpBCryptVerifySignature);
	if (ret0 != MH_OK)
	{
		std::string test1 = std::to_string(ret0);
		MessageBoxW(NULL, (LPCWSTR)test1.c_str(), L"Failed", MB_OK);
		return 1;
	}
	MessageBoxW(NULL, L"Hook should work...", L"Hook should work...", MB_OK);

	int ret1 = MH_EnableHook(MH_ALL_HOOKS);
	if (ret1 != MH_OK)
	{
		std::string test1 = std::to_string(ret1);
		MessageBoxW(NULL, (LPCWSTR)test1.c_str(), L"3", MB_OK);
		return 1;
	}


	while (!GetAsyncKeyState(VK_END))
	{
		Sleep(100);
	}

	MessageBoxW(NULL, L"Unhooked", L"Unhooked", MB_OK);

	if (MH_DisableHook(MH_ALL_HOOKS) != MH_OK)
	{
		return 1;
	}

	// Uninitialize MinHook.
	if (MH_Uninitialize() != MH_OK)
	{
		return 1;
	}

	FreeLibraryAndExitThread((HMODULE)param, 0);
	return 0;
}


BOOL APIENTRY DllMain(HINSTANCE hInst     /* Library instance handle. */,
	DWORD reason        /* Reason this function is being called. */,
	LPVOID reserved     /* Not used. */)
{
	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
		CreateThread(0, 0, MainThread, hInst, 0, 0);
		break;
	default:
		break;
	}

	return TRUE;
}
