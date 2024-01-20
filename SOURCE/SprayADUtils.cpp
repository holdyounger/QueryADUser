#define SECURITY_WIN32 
#include "SprayADUtils.h"

#include <activeds.h>
#include <dsgetdc.h>
#include <lm.h>
#include <security.h>
#include <sddl.h>

#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>
#include <atlstr.h>
#include <atltime.h>

#pragma comment(lib, "ADSIid.lib")


#define BUF_SIZE 512
#define MAXTOKENSIZE 48000

static PDOMAIN_CONTROLLER_INFOW pdcInfo = (PDOMAIN_CONTROLLER_INFOW)1;

HRESULT SearchDirectory1(_In_ LPCWSTR lpwSprayPasswd, _In_ LPCWSTR lpwFilter, _In_ BOOL bLdapAuth, _In_ LPCWSTR lpwMaxBadPwdCount)
{
	HRESULT hr = S_OK;
	HINSTANCE hModule = NULL;
	IADs* pRoot = NULL;
	IDirectorySearch* pContainerToSearch = NULL;
	IID IADsIID, IDirectorySearchIID;

	WCHAR wcPathName[BUF_SIZE] = { 0 };
	VARIANT var;
	VARIANT varHostName;

	hModule = LoadLibraryA("Activeds.dll");
	_ADsOpenObject ADsOpenObject = (_ADsOpenObject)
		GetProcAddress(hModule, "ADsOpenObject");
	if (ADsOpenObject == NULL) {
		return hr;
	}

	DWORD dwRet = DsGetDcNameW(NULL, NULL, NULL, NULL, 0, &pdcInfo);
	if (dwRet != ERROR_SUCCESS) {
		// BeaconPrintf(CALLBACK_ERROR, "Failed to get domain/dns info.");
		goto CleanUp;
	}

	// Initialize COM.
	hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
	if (FAILED(hr)) {
		goto CleanUp;
	}

	// Resolve IID from GUID string.
	LPCOLESTR pIADsIID = L"{FD8256D0-FD15-11CE-ABC4-02608C9E7553}";
	LPCOLESTR pIDirectorySearchIID = L"{109BA8EC-92F0-11D0-A790-00C04FD8D5A8}";

	hr = IIDFromString(pIADsIID, &IADsIID);
	hr = IIDFromString(pIDirectorySearchIID, &IDirectorySearchIID);

	// Get rootDSE and the current user's domain container DN.
	hr = ADsOpenObject(L"LDAP://rootDSE",
		NULL,
		NULL,
		ADS_USE_SEALING | ADS_USE_SIGNING | ADS_SECURE_AUTHENTICATION, // Use Kerberos encryption
		IADsIID,
		(void**)&pRoot);
	if (FAILED(hr)) {
		// BeaconPrintf(CALLBACK_ERROR, "Failed to get rootDSE.\n");
		goto CleanUp;
	}

	VariantInit(&var);
	hr = pRoot->Get((BSTR)L"defaultNamingContext", &var);
	if (FAILED(hr)) {
		// BeaconPrintf(CALLBACK_ERROR, "Failed to get defaultNamingContext.");
		goto CleanUp;
	}

	VariantInit(&varHostName);
	hr = pRoot->Get((BSTR)L"dnsHostName", &varHostName);
	if (FAILED(hr)) {
		// BeaconPrintf(CALLBACK_ERROR, "Failed to get dnsHostName.");
		goto CleanUp;
	}

	wcscpy_s(wcPathName, _countof(wcPathName), L"LDAP://");
	wcscat_s(wcPathName, _countof(wcPathName), var.bstrVal);

	hr = ADsOpenObject((LPCWSTR)wcPathName,
		NULL,
		NULL,
		ADS_USE_SEALING | ADS_USE_SIGNING | ADS_SECURE_AUTHENTICATION, // Use Kerberos encryption
		IDirectorySearchIID,
		(void**)&pContainerToSearch);
	if (FAILED(hr)) {
		// BeaconPrintf(CALLBACK_ERROR, "ADsOpenObject failed.\n");
		goto CleanUp;
	}

	// hr = SprayUsers(pContainerToSearch, lpwSprayPasswd, lpwFilter, bLdapAuth, lpwMaxBadPwdCount);

CleanUp:

	if (pdcInfo != NULL) {
		NetApiBufferFree(pdcInfo);
	}

	if (pContainerToSearch != NULL) {
		pContainerToSearch->Release();
		pContainerToSearch = NULL;
	}

	if (pRoot != NULL) {
		pRoot->Release();
		pRoot = NULL;
	}

	CoUninitialize();

	return hr;
}