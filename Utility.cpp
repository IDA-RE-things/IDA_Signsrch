
// ****************************************************************************
// File: Utility.cpp
// Desc: Utility stuff
//
// ****************************************************************************
#include "stdafx.h"
#include <mmsystem.h>

#define I2TIME(_int) ((double) (_int) * (double) ((double) 1.0 / (double) 1000.0))

// Single heap instance
INSTANCE_EZHeap(Heap);

// ****************************************************************************
// Func: GetTimeSamp()
// Desc: Get elapsed factional seconds
//
// ****************************************************************************
TIMESTAMP GetTimeStamp()
{
	LARGE_INTEGER tLarge;
	QueryPerformanceCounter(&tLarge);

	static ALIGN(16) TIMESTAMP s_ClockFreq;
	if(s_ClockFreq == 0.0)
	{
		LARGE_INTEGER tLarge;
		QueryPerformanceFrequency(&tLarge);
		s_ClockFreq = (TIMESTAMP) tLarge.QuadPart;
	}

	return((TIMESTAMP) tLarge.QuadPart / s_ClockFreq);
}

// Get delta time stamp, lower precision but much less overhead
TIMESTAMP GetTimeStampLow()
{
	static ALIGN(16) double s_fTimeStampHolder = 0;
	static DWORD s_dwLastTimeRead = 0;

	// Time with ms precision
	DWORD dwTime = timeGetTime();

	// Get delta time
	DWORD dwDelta;
	if(dwTime >= s_dwLastTimeRead)
		dwDelta = (dwTime - s_dwLastTimeRead);
	else
		// Rolled over.. (happens every ~49.71 days of computer time)
		dwDelta = (s_dwLastTimeRead - dwTime);

	s_dwLastTimeRead = dwTime;
	s_fTimeStampHolder += I2TIME(dwDelta);
	return(s_fTimeStampHolder);
}

// ****************************************************************************
// Func: Log()
// Desc: Send text to a log file.
//
// ****************************************************************************
void Log(FILE *pLogFile, const char *format, ...)
{
	if(pLogFile && format)
	{
		// Format string
		va_list vl;
        char	str[2048] = {0};

		va_start(vl, format);
		_vsnprintf(str, (sizeof(str) - 1), format, vl);
		va_end(vl);

		// Out to file
		qfputs(str, pLogFile);
        qflush(pLogFile);
	}
}

void Trace(LPCSTR format, ...)
{
	if(format)
	{
		va_list vl;
		char str[4096];

		va_start(vl, format);
		_vsnprintf(str, (sizeof(str) - 1), format, vl);
		str[(sizeof(str) - 1)] = 0;
		va_end(vl);
		OutputDebugString(str);
	}
}


// Get size of stream file
long qfsize(FILE *fp)
{
	long psave, endpos;
	long result = -1;

	if((psave = qftell(fp)) != -1L)
	{
		if(qfseek(fp, 0, SEEK_END) == 0)
		{
			if((endpos = qftell(fp)) != -1L)
			{
				qfseek(fp, psave, SEEK_SET);
				result = endpos;
			}
		}
	}

	return(result);
}

long fsize(FILE *fp)
{
	long psave, endpos;
	long result = -1;

	if((psave = ftell(fp)) != -1L)
	{
		if(fseek(fp, 0, SEEK_END) == 0)
		{
			if((endpos = ftell(fp)) != -1L)
			{
				fseek(fp, psave, SEEK_SET);
				result = endpos;
			}
		}
	}

	return(result);
}

// Common hash type
UINT DJBHash(const BYTE *pData, int iSize)
{
	register UINT uHash = 5381;

	for(int i = 0; i < iSize; i++)
	{
		uHash = (((uHash << 5) + uHash) + (UINT) *pData);
		pData++;
	}

	return(uHash);
}

char *ReplaceNameInPath(char *pszPath, char *pszNewName)
{
	char szDrive[_MAX_DRIVE];
	char szDir[_MAX_DIR];
	_splitpath(pszPath, szDrive, szDir, NULL, NULL);
	_makepath(pszPath, szDrive, szDir, pszNewName, NULL);
	return(pszPath);
}

LPSTR WINAPI AddressToMappedName(HANDLE hOwner, PVOID pAddress, LPSTR pszBuffer, int iSize)
{
	if(pszBuffer && (iSize > 2))
	{
		A_memset(pszBuffer, 0, iSize);

		// Faster?
		char szFullPath[MAX_PATH];
		if(GetMappedFileName(hOwner, pAddress, szFullPath, (sizeof(szFullPath) - 1)))
		{
			// Extract the base name from the path
			szFullPath[sizeof(szFullPath) - 1] = 0;
			char szFileName[_MAX_FNAME + _MAX_EXT], szExtension[_MAX_EXT];
			_splitpath(szFullPath, NULL, NULL, szFileName, szExtension);
			_snprintf(pszBuffer, (iSize - 1), "%s%s", szFileName, szExtension);
			pszBuffer[(iSize - 1)] = 0;
			return(pszBuffer);
		}

		// Try alternate way, if the first failed
		{
			HMODULE hModule = NULL;
			if(pAddress)
			{
				// Try it as a module handle first
				GetModuleHandleEx((GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS), (LPCTSTR) pAddress, &hModule);
				if(!hModule) hModule = (HMODULE) pAddress;
			}

			if(GetModuleBaseName(hOwner, hModule, pszBuffer, (iSize - 1)) > 0)
				return(pszBuffer);
			else
				// Fix bug where GetModuleBaseName() puts a random char in [0] on failure
				pszBuffer[0] = 0;
		}
	}

	return(NULL);
}

BOOL ReportException(LPCTSTR pszFunction, LPEXCEPTION_POINTERS pExceptionInfo)
{
	char szModule[_MAX_PATH] = {"Unknown"};
	AddressToMappedName(GetCurrentProcess(), pExceptionInfo->ExceptionRecord->ExceptionAddress, szModule, sizeof(szModule));
	msg("DLL: ** Exception: %08X, @  %08X, in \"%s\", from Module: \"%s\", Base: %08X **\n", pExceptionInfo->ExceptionRecord->ExceptionCode, pExceptionInfo->ExceptionRecord->ExceptionAddress, pszFunction, szModule, GetModuleHandle(szModule));
	return(TRUE);
}

void DumpData(LPCVOID pData, int iSize)
{
	#define RUN 16

	if(pData && (iSize > 0))
	{
		__try
		{
			BYTE *pSrc = (BYTE *) pData;
			char szLine[256] = {0};
			int  uOffset = 0;

			// Create offset string based on input size
			char szOffset[16];
			int iDigits = (int) strlen(_itoa(iSize, szOffset, 16));
			sprintf(szOffset, "[%%0%dX]: ", max(iDigits, 2));

			// Do runs
			char szValue[(RUN + 1) * 3];
			while(iSize >= RUN)
			{
				sprintf(szLine, szOffset, uOffset);

				// Hex
				BYTE *pLine = pSrc;
				for(int i = 0; i < RUN; i++)
				{
					sprintf(szValue, "%02X ", *pLine);
					strcat(szLine, szValue);
					++pLine;
				}

				strcat(szLine, "  ");

				// ASCII
				pLine = pSrc;
				for(int i = 0; i < RUN; i++)
				{
					sprintf(szValue, "%c", (*pLine >= ' ') ? *pLine : '.');
					strcat(szLine, szValue);
					++pLine;
				}

				msg("%s\n", szLine);
				uOffset += RUN, pSrc += RUN, iSize -= RUN;
			};

			// Final if not an even run line
			if(iSize > 0)
			{
				sprintf(szLine, szOffset, uOffset);

				// Hex
				BYTE *pLine = pSrc;
				for(int i = 0; i < iSize; i++)
				{
					sprintf(szValue, "%02X ", *pLine);
					strcat(szLine, szValue);
					++pLine;
				}

				// Pad out line
				for(int i = 0; i < (RUN - iSize); i++) strcat(szLine, "   ");
				strcat(szLine, "  ");

				// ASCII
				pLine = pSrc;
				for(int i = 0; i < iSize; i++)
				{
					sprintf(szValue, "%c", (*pLine >= ' ') ? *pLine : '.');
					strcat(szLine, szValue);
					++pLine;
				}

				msg("%s\n", szLine);
			}

		}__except(TRUE){}
	}

	#undef RUN
}

// Return a comma formated string for a given number
LPSTR FormatUInt(UINT uNumber, __bcount(16) LPSTR pszBuffer)
{
	if(uNumber > 1000)
	{
		LPSTR pStr = pszBuffer;
		#define STRCAT(x) { int len = A_strlen(x); memcpy(pStr, x, len); pStr += len; }

		UINT n = 1000;
		for (;(uNumber / (1000 * n)) > 0; n *= 1000);

		while(n > 0)
		{
			UINT uNum2 = (uNumber / n);
			char szTemp[16];
			_ultoa(uNum2, szTemp, 10);
			STRCAT(szTemp)
			uNumber -= (n * uNum2);

			if((n /= 1000) > 0)
			{
				if((uNumber / n) < 10)
					STRCAT(",00")
				else
				if((uNumber / n) < 100)
					STRCAT(",0")
				else
					STRCAT(",")
			}
		};

		*pStr = 0;
		#undef STRCAT
	}
	else
		_ultoa(uNumber, pszBuffer, 10);

	return(pszBuffer);
}

// Get a pretty time string for output
LPCTSTR TimeString(TIMESTAMP Time)
{
	static char szBuff[64];
	szBuff[0] =	szBuff[SIZESTR(szBuff)] = 0;

	if(Time >= HOUR)
		_snprintf(szBuff, SIZESTR(szBuff), "%.2f hours", (Time / (TIMESTAMP) HOUR));
	else
	if(Time >= MINUTE)
		_snprintf(szBuff, SIZESTR(szBuff), "%.2f minutes", (Time / (TIMESTAMP) MINUTE));
	else
	if(Time < (TIMESTAMP) 0.01)
		//return("Less then 100 milliseconds");
		_snprintf(szBuff, SIZESTR(szBuff), "%.2f milliseconds", (Time * (TIMESTAMP) 1000.0));
	else
		_snprintf(szBuff, SIZESTR(szBuff), "%.2f seconds", Time);

	return(szBuff);
}

// Returns a pretty factional byte size string for given input size
LPCTSTR ByteSizeString(UINT64 uSize)
{
	static const UINT64 KILLOBYTE = 1024;
	static const UINT64 MEGABYTE  = (KILLOBYTE * 1024); // 1048576
	static const UINT64 GIGABYTE  = (MEGABYTE  * 1024); // 1073741824
	static const UINT64 TERABYTE  = (GIGABYTE  * 1024); // 1099511627776

	#define BYTESTR(_Size, _Suffix) \
	double fSize = ((double) uSize / (double) _Size); \
	double fIntegral; double fFractional = modf(fSize, &fIntegral); \
	if(fFractional > 0.05) \
		_snprintf(szBuff, SIZESTR(szBuff), ("%.1f " ## _Suffix), fSize); \
	else \
		_snprintf(szBuff, SIZESTR(szBuff), ("%.0f " ## _Suffix), fIntegral);

	static char szBuff[32] = {0};
	if(uSize >= TERABYTE)
	{
		BYTESTR(TERABYTE, "TB");
	}
	else
	if(uSize >= GIGABYTE)
	{
		BYTESTR(GIGABYTE, "GB");
	}
	else
	if(uSize >= MEGABYTE)
	{
		BYTESTR(MEGABYTE, "MB");
	}
	else
	if(uSize >= KILLOBYTE)
	{
		BYTESTR(KILLOBYTE, "KB");
	}
	else
		_snprintf(szBuff, SIZESTR(szBuff), "%u byte%c", uSize, (uSize == 1) ? 0 : 's');

	return(szBuff);
}
