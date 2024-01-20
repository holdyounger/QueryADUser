#pragma once

#include <windows.h>

//ACTIVEDS
typedef HRESULT(WINAPI* _ADsOpenObject)(
	LPCWSTR lpszPathName,
	LPCWSTR lpszUserName,
	LPCWSTR lpszPassword,
	DWORD dwReserved,
	REFIID riid,
	void** ppObject
	);

typedef BOOL(WINAPI* _FreeADsMem)(
	LPVOID pMem
	);


class SprayADUtils
{

};

HRESULT SearchDirectory1(LPCWSTR lpwSprayPasswd, LPCWSTR lpwFilter, BOOL bLdapAuth, LPCWSTR lpwMaxBadPwdCount);
