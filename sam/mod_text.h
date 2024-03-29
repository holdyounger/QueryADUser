/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by-nc-sa/3.0/
*/
#pragma once
#include <sstream>
#include <iomanip>
#include <iostream>
#include <Windows.h>
#include <lsalookup.h>
#include <NTSecAPI.h>

using namespace std;

typedef VOID(WINAPI* PRTL_INIT_STRING)								(PSTRING DestinationString, PCSTR SourceString);
typedef VOID(WINAPI* PRTL_INIT_UNICODESTRING)						(PUNICODE_STRING DestinationString, PCWSTR SourceString);

class mod_text
{
public:
	static PRTL_INIT_STRING RtlInitString;
	static PRTL_INIT_UNICODESTRING RtlInitUnicodeString;

	static wstring stringOfHex(const BYTE monTab[], DWORD maTaille, DWORD longueur = 0);
	static wstring stringOrHex(const BYTE monTab[], DWORD maTaille, DWORD longueur = 32);
	static void wstringHexToByte(wstring& maChaine, BYTE monTab[]);

	static wstring stringOfSTRING(UNICODE_STRING maString);
	static string stringOfSTRING(STRING maString);

	static bool wstr_ends_with(const wchar_t* str, const wchar_t* suffix);
	static bool wstr_ends_with(const wchar_t* str, size_t str_len, const wchar_t* suffix, size_t suffix_len);

	static void InitLsaStringToBuffer(LSA_UNICODE_STRING* LsaString, wstring& maDonnee, wchar_t monBuffer[]);
	static LUID wstringsToLUID(wstring& highPart, wstring& lowPart);
};