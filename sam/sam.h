/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by-nc-sa/3.0/
	This file  : http://creativecommons.org/licenses/by/3.0/
*/
#pragma once
#include <sstream>
#include <string>
#include <iomanip>
#include <iostream>
#include <Windows.h>
#include <lsalookup.h>
#include <Ntsecapi.h>

#include "mod_text.h"


#define NT_SUCCESS(Status)			(((NTSTATUS)(Status)) >= 0)
#define NT_INFORMATION(Status)		((((ULONG)(Status)) >> 30) == 1)
#define NT_WARNING(Status)			((((ULONG)(Status)) >> 30) == 2)
#define NT_ERROR(Status)			((((ULONG)(Status)) >> 30) == 3)

#define STATUS_SUCCESS				((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH	((NTSTATUS)0xc0000004L)
#define STATUS_MORE_ENTRIES			((NTSTATUS)0x00000105L)


using namespace std;


#define __kextdll extern "C" __declspec(dllexport)


bool searchSAMFuncs();
__kextdll bool __cdecl getSAMFunctions();
__kextdll bool __cdecl getLocalAccounts();

#define SAM_SERVER_CONNECT							0x00000001
#define DOMAIN_ALL_ACCESS							0x000F07FF	
#define USER_ALL_ACCESS								0x000F07FF	

#define USER_ACCOUNT_DISABLED						0x00000001
#define USER_PASSWORD_NOT_REQUIRED					0x00000004
#define USER_NORMAL_ACCOUNT							0x00000010
#define USER_WORKSTATION_TRUST_ACCOUNT				0x00000080
#define USER_SERVER_TRUST_ACCOUNT					0x00000100
#define USER_DONT_EXPIRE_PASSWORD					0x00000200
#define USER_ACCOUNT_AUTO_LOCKED					0x00000400
#define USER_SMARTCARD_REQUIRED						0x00001000
#define USER_TRUSTED_FOR_DELEGATION					0x00002000
#define USER_PASSWORD_EXPIRED						0x00020000

typedef struct _WUserAllInformation
{
	unsigned long UserId;
	wstring UserName;
	wstring DomaineName;
	wstring FullName;
	bool isActif;
	bool isLocked;
	wstring TypeCompte;
	wstring UserComment;
	wstring AdminComment;
	wstring AccountExpires;
	wstring AccountExpires_strict;
	wstring WorkStations;

	wstring HomeDirectory;
	wstring HomeDirectoryDrive;
	wstring ProfilePath;
	wstring ScriptPath;

	unsigned short LogonCount;
	unsigned short BadPasswordCount;
	wstring LastLogon;
	wstring LastLogon_strict;
	wstring LastLogoff;
	wstring LastLogoff_strict;

	wstring PasswordLastSet;
	wstring PasswordLastSet_strict;
	bool isPasswordNotExpire;
	bool isPasswordNotRequired;
	bool isPasswordExpired;
	wstring PasswordCanChange;
	wstring PasswordCanChange_strict;
	wstring PasswordMustChange;
	wstring PasswordMustChange_strict;

	bool LmPasswordPresent;
	wstring LmOwfPassword;
	bool NtPasswordPresent;
	wstring NtOwfPassword;
} WUserAllInformation, * PUserAllInformation;

typedef struct _WHashHistory
{
	DWORD unkVersion;
	unsigned short currentLMsize;
	unsigned short unkCurrentLMsize;
	DWORD unkCurLM;
	BYTE EncLMhash[16];

	unsigned short currentNTLMsize;
	unsigned short unkCurrentNTLMsize;
	DWORD unkCurNTLM;
	BYTE EncNTLMhash[16];

	unsigned short histLMsize;
	unsigned short unkhistLMsize;
	DWORD unkHistLM;

	unsigned short histNTLMsize;
	unsigned short unkhistNTLMsize;
	DWORD unkHistNTLM;
	BYTE hashs[24][16];
} WHashHistory, * PWHashHistory;

DECLARE_HANDLE(HUSER);
DECLARE_HANDLE(HSAM);
DECLARE_HANDLE(HDOMAIN);

typedef struct _SAMPR_RID_ENUMERATION
{
	unsigned long RelativeId;
	LSA_UNICODE_STRING Name;
} SAMPR_RID_ENUMERATION, * PSAMPR_RID_ENUMERATION;

typedef struct _SAMPR_ENUMERATION_BUFFER
{
	unsigned long EntriesRead;
	PSAMPR_RID_ENUMERATION Buffer;
	// [size_is(EntriesRead)] PSAMPR_RID_ENUMERATION Buffer;
} SAMPR_ENUMERATION_BUFFER, * PSAMPR_ENUMERATION_BUFFER;

typedef enum _USER_INFORMATION_CLASS
{
	UserInternal1Information = 18,
	UserAllInformation = 21,
} USER_INFORMATION_CLASS, * PUSER_INFORMATION_CLASS;

typedef struct _ENCRYPTED_LM_OWF_PASSWORD
{
	BYTE data[16];
} ENCRYPTED_LM_OWF_PASSWORD, * PENCRYPTED_LM_OWF_PASSWORD, ENCRYPTED_NT_OWF_PASSWORD, * PENCRYPTED_NT_OWF_PASSWORD;

typedef struct _SAMPR_USER_INTERNAL1_INFORMATION
{
	ENCRYPTED_NT_OWF_PASSWORD EncryptedNtOwfPassword;
	ENCRYPTED_LM_OWF_PASSWORD EncryptedLmOwfPassword;
	unsigned char NtPasswordPresent;
	unsigned char LmPasswordPresent;
	unsigned char PasswordExpired;
} SAMPR_USER_INTERNAL1_INFORMATION, * PSAMPR_USER_INTERNAL1_INFORMATION;

typedef struct _OLD_LARGE_INTEGER {
	unsigned long LowPart;
	long HighPart;
} OLD_LARGE_INTEGER, * POLD_LARGE_INTEGER;

typedef struct _SAMPR_SR_SECURITY_DESCRIPTOR {
	// [range(0, 256 * 1024)] unsigned long Length;
	unsigned long Length;
	unsigned char* SecurityDescriptor;
} SAMPR_SR_SECURITY_DESCRIPTOR, * PSAMPR_SR_SECURITY_DESCRIPTOR;

typedef struct _SAMPR_LOGON_HOURS {
	unsigned short UnitsPerWeek;
	unsigned char* LogonHours;
} SAMPR_LOGON_HOURS, * PSAMPR_LOGON_HOURS;

typedef struct _SAMPR_USER_ALL_INFORMATION
{
	OLD_LARGE_INTEGER LastLogon;
	OLD_LARGE_INTEGER LastLogoff;
	OLD_LARGE_INTEGER PasswordLastSet;
	OLD_LARGE_INTEGER AccountExpires;
	OLD_LARGE_INTEGER PasswordCanChange;
	OLD_LARGE_INTEGER PasswordMustChange;
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING FullName;
	LSA_UNICODE_STRING HomeDirectory;
	LSA_UNICODE_STRING HomeDirectoryDrive;
	LSA_UNICODE_STRING ScriptPath;
	LSA_UNICODE_STRING ProfilePath;
	LSA_UNICODE_STRING AdminComment;
	LSA_UNICODE_STRING WorkStations;
	LSA_UNICODE_STRING UserComment;
	LSA_UNICODE_STRING Parameters;
	LSA_UNICODE_STRING LmOwfPassword;
	LSA_UNICODE_STRING NtOwfPassword;
	LSA_UNICODE_STRING PrivateData;
	SAMPR_SR_SECURITY_DESCRIPTOR SecurityDescriptor;
	unsigned long UserId;
	unsigned long PrimaryGroupId;
	unsigned long UserAccountControl;
	unsigned long WhichFields;
	SAMPR_LOGON_HOURS LogonHours;
	unsigned short BadPasswordCount;
	unsigned short LogonCount;
	unsigned short CountryCode;
	unsigned short CodePage;
	unsigned char LmPasswordPresent;
	unsigned char NtPasswordPresent;
	unsigned char PasswordExpired;
	unsigned char PrivateDataSensitive;
} SAMPR_USER_ALL_INFORMATION, * PSAMPR_USER_ALL_INFORMATION;

typedef union _SAMPR_USER_INFO_BUFFER	/* http://msdn.microsoft.com/en-us/library/cc211885.aspx */
{
	SAMPR_USER_INTERNAL1_INFORMATION Internal1;
	SAMPR_USER_ALL_INFORMATION All;
} SAMPR_USER_INFO_BUFFER, * PSAMPR_USER_INFO_BUFFER;

WUserAllInformation	UserInformationsToStruct(USER_INFORMATION_CLASS type, PSAMPR_USER_INFO_BUFFER& monPtr);
bool				descrToPipeInformations(USER_INFORMATION_CLASS type, WUserAllInformation& mesInfos, bool isCSV = false);
bool				descrUserHistoryToPipe(DWORD rid, wstring monUserName, wstring domainName, HUSER handleUser, USER_INFORMATION_CLASS type, bool isCSV = false);
wstring				toTimeFromOLD_LARGE_INTEGER(OLD_LARGE_INTEGER& monInt, bool isStrict = false);
wstring				protectMe(wstring& maChaine);
void				correctMe(wstring& maChaine);

typedef NTSTATUS(WINAPI* PSAM_I_CONNECT) (DWORD, HSAM*, DWORD, DWORD);
typedef NTSTATUS(WINAPI* PSAM_R_OPEN_DOMAIN) (HSAM, DWORD dwAccess, PSID, HDOMAIN*);
typedef NTSTATUS(WINAPI* PSAM_R_OPEN_USER) (HDOMAIN, DWORD dwAccess, DWORD, HUSER*);
typedef NTSTATUS(WINAPI* PSAM_R_ENUMERATE_USERS_IN_DOMAIN) (HDOMAIN, DWORD*, DWORD, PSAMPR_ENUMERATION_BUFFER*, DWORD, PVOID);
typedef NTSTATUS(WINAPI* PSAM_R_QUERY_INFORMATION_USER) (HUSER, DWORD, PSAMPR_USER_INFO_BUFFER*);
typedef HLOCAL(WINAPI* PSAM_I_FREE_SAMPR_USER_INFO_BUFFER) (PVOID, DWORD);
typedef HLOCAL(WINAPI* PSAM_I_FREE_SAMPR_ENUMERATION_BUFFER) (PSAMPR_ENUMERATION_BUFFER);
typedef HLOCAL(WINAPI* PSAM_I_FREE_MEMORY) (PVOID);
typedef NTSTATUS(WINAPI* PSAM_R_CLOSE_HANDLE) (PHANDLE);
typedef NTSTATUS(WINAPI* PSAM_I_GET_PRIVATE_DATA) (HUSER, DWORD*, DWORD*, DWORD*, PWHashHistory*);