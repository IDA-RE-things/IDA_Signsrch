
// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//
#pragma once

#define WIN32_LEAN_AND_MEAN
#define WINVER       0x0502
#define _WIN32_WINNT 0x0502
#define _WIN32_WINDOWS 0x0502
#define _WIN32_IE 0x0601

// http://stackoverflow.com/questions/87096/stl-alternative
#ifndef _DEBUG
#define _SECURE_SCL 0
#define _HAS_ITERATOR_DEBUGGING 0
#endif

// If SSE2 /arch::SSE2
#if (defined(_M_IX86_FP) && (_M_IX86_FP >= 2))
#ifndef _M_X64
#define _SSE2
#endif
#endif

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <limits.h>
#include <math.h>
#include <float.h>
#include <crtdbg.h>
#include <mmsystem.h>
#include <new>
#include <Psapi.h>
#include <vector>
#include <algorithm>
#include <intrin.h>

#pragma intrinsic(memset, memcmp, memcpy, strcat, strcmp, strcpy, strlen, abs, fabs, labs, atan, atan2, tan, sqrt, sin, cos, _rotl)

// IDA libs
#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <auto.hpp>
#include <bytes.hpp>
#include <entry.hpp>
#include <expr.hpp>
#include <bytes.hpp>
#include <ua.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <diskio.hpp>
#include <funcs.hpp>
#include <search.hpp>
#include <struct.hpp>
#include <kernwin.hpp>
#include <typeinf.hpp>
#include <demangle.hpp>
#include <nalt.hpp>
#include <err.h>
#include <allins.hpp>

#include <asmlib.h>
#include "AlignNewDelete.h"
#include "Utility.h"
#include "EZHeapAlloc.h"

#define XML_STATIC 1
#include <expat.h>


#define PLUGIN_VERSION "1.02"

