
// ****************************************************************************
// File: Main.cpp
// Desc: Plugin main
// Auth: Sirmabus 2012
//
// ****************************************************************************
#include "stdafx.h"
#include "resource.h"

// Signature container
#pragma pack(1)
typedef struct _SIG
{
	LPSTR pszTitle;
	PBYTE pData;
	UINT  uSize;
	WORD  wBits;
	WORD  wFlags;
} SIG, *LPSIG;
#pragma pack()
typedef std::vector<SIG, EZHeapAlloc<SIG>> SIGLIST;

// Match container
typedef struct _MATCH
{
	ea_t eaAddress;
	UINT uIndex;
	bool operator()(_MATCH const &a, _MATCH const &b){ return(a.eaAddress < b.eaAddress); }
} MATCH, *LPMATCH;
typedef std::vector<MATCH, EZHeapAlloc<MATCH>> MATCHLIST;

// wFlag defs
const WORD BIGENDIAN = (1 << 0); // 0 = little endian, 1 = big endian ** Don't change, this must be '1' **
const WORD REVERSE   = (1 << 1); // Reverse/reflect
const WORD AND       = (1 << 2); // And bits

#define SIGFILE "signsrch.xml"

// === Function Prototypes ===
static int  PlugIn_init();
static void PlugIn_term();
static void PlugIn_run(int arg);
static void FreeSignatureData();
static void ClearProcessSegmentBuffer();
extern void ClearPatternSearchData();
static void ClearMatchData();

// === Data ===
static const char PlugIn_szComment[] = "An IDA plugin of Luigi Auriemma's Signsrch signature search tool. ";
static const char PlugIn_szHelp[] 	 = "Use hotkey to activate. ";
static const char PlugIn_szName[] 	 = "IDA Signsrch";
static const char PlugIn_szHotkey[]  = "Ctrl-0";
//
ALIGN(16) static SIGLIST   Siglist;
ALIGN(16) static MATCHLIST MatchList;
//
static HMODULE hMyModule = NULL;

#include "WaitBoxExCustom.h"
#include "HelpURLCustom.h"

static cWaitBoxEx WaitBox;
static UINT uSigDataBytes = 0;
static UINT uTotalMatches = 0;
static BOOL bListWindowUp = FALSE;
// UI options bit flags
// *** Must be same sequence as check box options
static SBITFLAG BitF;
const static WORD OPT_ALTENDIAN  = BitF.Next();
const static WORD OPT_DEBUGOUT   = BitF.Next();
const static WORD OPT_CODESEGS   = BitF.Next();
const static WORD OPT_COMMENTS   = BitF.Next();
static BOOL bAltEndianSearch     = FALSE;
static BOOL bDebugOutput	     = FALSE;
static BOOL bIncludeCodeSegments = TRUE;
static BOOL bPlaceComments       = TRUE;

// Plug-in description block
extern "C" ALIGN(16) plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_PROC,
	PlugIn_init,
	PlugIn_term,
	PlugIn_run,
	PlugIn_szComment,
	PlugIn_szHelp,
	PlugIn_szName,
	PlugIn_szHotkey
};

ALIGN(16) static const char szMainForm[] =
{
	"BUTTON YES* Continue\n" // 'Continue' instead of 'okay'

	// Help block
	"HELP\n"
	"IDA Signsrch, an IDA plugin of Luigi Auriemma's Signsrch signature search\ntool, by Sirmabus.\n"
	"See help file for more information.\n"
	"Plugin support page: http://goo.gl/WOf8k\n\n"
	"Luigi Auriemma's Signsrch page: http://goo.gl/byJ8N\n\n"

	"Copyright(c) 2012 Sirmabus. All rights reserved.\n"
	"Released under a multi-license.\n"
	"Signsrch source Copyright 2007-2012 Luigi Auriemma.\n"
	"License: \"GNU General Public License 2 or later.\"\n"
	"See \"Licenses.txt\" for a more detailed license description.\n"
	"ENDHELP\n"

	// Title
	"IDA Signsrch\n"

	// Message text
	"IDA Signsrch plugin.\n"
	"Version: %A, build: %A, by Sirmabus\n\n"

	// checkbox -> bAltEndianSearch
	"<#Do alternate endian search in addition to the IDB's native endian.\nSearching will take about twice as long but can find additional matches in some cases. #Alternate endian search.:C>\n"

	// checkbox -> bDebugOutput
	"<#Output matches to the debugging channel so they can be viewed \nand logged by Sysinternals \"DebugView\", etc.#Output to debug channel.:C>\n"

	// checkbox -> bIncludeCodeSegments
	"<#Search code segments in addition to data segments. #Include code segments.:C>\n"

	// checkbox -> bPlaceComments
	"<#Automatically place label comments for located signatures.#Place signature comments. :C>>\n"

	// * Maintain button names hard coded in "HelpURL.h"
	"\n\n\n  <#Click to open plugin support page.#Open support forum:B:2:16::>   "
	"<#Click to open Luigi Auriemma's Signsrch page.#Signsrch page:B:2:16::>\n"
};


// ======================================================================================
static int PlugIn_init()
{
	// SIG struct should be align 16
	C_ASSERT((sizeof(SIG) & (16-1)) == 0);

	int iPeriod = 1;
	while(iPeriod < 100)
	{
		if(timeBeginPeriod(iPeriod++) == TIMERR_NOERROR)
			break;
	};

	bListWindowUp = FALSE;
	return(PLUGIN_OK);
}

// ======================================================================================
static void PlugIn_term()
{
	// Just in case..
	ClearMatchData();
	ClearPatternSearchData();
	FreeSignatureData();
}

// ======================================================================================



// Load signature XML file
static LPSTR pszXMLValue = NULL;
static int   iXMLValueBufferSize = 0;
static void XMLCALL characterHandler(PVOID lParm, LPCSTR pszData, int iLen)
{
	MYTRY();
	{
		if(iXMLValueBufferSize)
		{
			// Increase buffer size as needed
			int iAdjLen = (iLen + 1);
			if(iXMLValueBufferSize < iAdjLen)
			{
				if(pszXMLValue = TRealloc<char>(pszXMLValue, iAdjLen))
					iXMLValueBufferSize = iAdjLen;
				else
				{
					msg("** Failed to realloc() XML data bufferr! Size wanted: %d **\n", iAdjLen);
					iXMLValueBufferSize = 0;
				}
			}

			// Save contents
			if(iXMLValueBufferSize)
			{
				A_memcpy(pszXMLValue, pszData, iLen);
				pszXMLValue[iLen] = 0;
				//msg("D: \"%s\"\n", pszXMLValue);
			}
		}
	}
	MYEXCEPT();
}
//
ALIGN(16) static char szTitle[1024] = {0};
static void XMLCALL startElement(PVOID lParm, LPCTSTR pszName, LPCTSTR *pszAttrib)
{
	MYTRY();
	{
		if(iXMLValueBufferSize)
		{
			if(*((PWORD) pszName) == MAKEWORD('p',0))
			{
				if(LPCSTR pszTag = pszAttrib[0])
				{
					if(*((PWORD) pszTag) == MAKEWORD('t',0))
					{
						if(LPCSTR pszTitle = pszAttrib[1])
							strncpy(szTitle, pszTitle, SIZESTR(szTitle));
					}
				}
			}
		}

		pszXMLValue[0] = 0;
	}
	MYEXCEPT();
}
//
static void XMLCALL endElement(PVOID lParm, LPCSTR pszName)
{
	MYTRY();
	{
		if(iXMLValueBufferSize)
		{
			if(*((PWORD) pszName) == MAKEWORD('p',0))
			{
				STACKALIGN(Sig, SIG);
				Sig.pszTitle = Heap().strdup(szTitle);
				Sig.pData    = NULL;

				if(Sig.pszTitle)
				{
					//== Parse data out of the title
					// Find the last start brace
					LPSTR pszStr       = szTitle;
					LPSTR pszLastBrace = NULL;
					while(LPSTR pszBrace = strchr(pszStr, '['))
					{
						pszLastBrace = pszBrace;
						pszStr       = (pszBrace + 1);
					};

					if(pszLastBrace)
					{
						// Largest section seen is 16 chars
						int iLen = A_strlen(++pszLastBrace);
						pszLastBrace[iLen - 1] = 0;

						// And flag?
						WORD wAnd = 0;
						if(pszLastBrace[iLen - 2] == '&')
						{
							//msg("And: \"%s\"\n", Sig.pszTitle);
							pszLastBrace[iLen - 2] = 0;
							wAnd = AND;
						}

						// First is the optional bits
						int iSteps = 0;
						BOOL bEndianBail = FALSE;
						LPSTR pszBits = pszLastBrace;
						if(LPSTR pszEnd = strchr(pszLastBrace, '.'))
						{
							*pszEnd = 0; ++iSteps;

							// AND type must have bits
							Sig.wBits = 0;
							if(wAnd)
							{
								if(pszBits[0])
								{
									if(strcmp(pszBits, "float") == 0)
										Sig.wBits = 32;
									else
									if(strcmp(pszBits, "double") == 0)
										Sig.wBits = 64;
									else
										Sig.wBits = atoi(pszBits);
								}

								if(Sig.wBits == 0)
									msg("** AND type missing bits! \"%s\" **\n", Sig.pszTitle);
							}

							// Next endian and reverse flag
							// Can be none for default of IDB endian
							LPSTR pszEndian = ++pszEnd;
							if(pszEnd = strchr(pszEnd, '.'))
							{
								*pszEnd = 0; ++iSteps;

								Sig.wFlags = 0;
								if(pszEndian[0])
								{
									if(*((PWORD) pszEndian) == MAKEWORD('b','e'))
										Sig.wFlags = BIGENDIAN;

									// Bail out if bAltEndianSearch off and opposite our endian
									if(!bAltEndianSearch && (inf.mf != (BYTE) Sig.wFlags))
									{
										//msg("B: \"%s\"\n", Sig.pszTitle);
										bEndianBail = TRUE;
									}
									else
									if(*((PWORD) (pszEndian + 2)) == MAKEWORD(' ','r'))
										Sig.wFlags |= REVERSE;
								}

								if(!bEndianBail)
								{
									Sig.wFlags |= wAnd;

									// Last, size
									LPSTR pszSize = (pszEnd + 1);
									Sig.uSize = atoi(pszSize);
									// Valid size required
									if((Sig.uSize > 0) && (Sig.uSize == (A_strlen(pszXMLValue) / 2)))
									{
										++iSteps;

										// Signature string to bytes
										Sig.pData = (PBYTE) _aligned_malloc(Sig.uSize, 16);
										if(Sig.pData)
										{
											// Hex string to byte data
											UINT  uSize = Sig.uSize;
											PBYTE pSrc  = (PBYTE) pszXMLValue;
											PBYTE pDst  = Sig.pData;

											do
											{
												BYTE hi = (pSrc[0] - '0');
												if(hi > 9) hi -= (('A' - '0') - 10);

												BYTE lo = (pSrc[1] - '0');
												if(lo > 9) lo -= (('A' - '0') - 10);

												*pDst = (lo | (hi << 4));
												pSrc += 2, pDst += 1;
											}while(--uSize);

											// Save signature
											//if(uSize == 0)
											{
												++iSteps;
												uSigDataBytes += A_strlen(Sig.pszTitle);
												uSigDataBytes += Sig.uSize;
												Siglist.push_back(Sig);
											}
											//else
											//	_aligned_free(Sig.pData);
										}
									}
									else
										msg("** Signature data parse size mismatch! Title: \"%s\" **\n", Sig.pszTitle);
								}
							}
						}

						if(iSteps != 4)
						{
							if(!bEndianBail)
								msg("** Failed to parse signature! Title: \"%s\" **\n", Sig.pszTitle);

							if(Sig.pszTitle)
								free(Sig.pszTitle);
						}
					}
					else
						msg("** Failed locate info section in title decode! \"%s\" **\n", Sig.pszTitle);
				}
				else
				{
					msg("** Failed to allocate XML title string copy! **\n");
					iXMLValueBufferSize = 0;
				}
			}
		}

		pszXMLValue[0] = szTitle[0] = 0;
	}
	MYEXCEPT();
}
//
static BOOL LoadSignatures()
{
	BOOL bResult = FALSE;
	uSigDataBytes = 0;

	MYTRY();
	{
		// Get my module full path replaced with XML file name
		char szPath[MAX_PATH]; szPath[0] = szPath[SIZESTR(szPath)] = 0;
		GetModuleFileNameEx(GetCurrentProcess(), hMyModule, szPath, SIZESTR(szPath));
		ReplaceNameInPath(szPath, SIGFILE);

		if(FILE *fp = fopen(szPath, "rb"))
		{
			long lSize = fsize(fp);
			if(lSize > 0)
			{
				if(LPSTR pszText = TAlloc<char>(lSize+1))
				{
					// Data value buffer
					// Largest seen data size 0xFFFF
					iXMLValueBufferSize = 69632;
					if(pszXMLValue = TAlloc<char>(iXMLValueBufferSize))
					{
						pszText[0] = pszText[lSize] = 0;
						if(fread(pszText, lSize, 1, fp) == 1)
						{
							if(XML_Parser p = XML_ParserCreate(NULL))
							{
								//  7/09/2012 element count: One endian 1,411, both 2278
								Siglist.reserve(2600);

								XML_SetUserData(p, p);
								XML_SetElementHandler(p, startElement, endElement);
								XML_SetCharacterDataHandler(p, characterHandler);

								if(XML_Parse(p, pszText, lSize, 1) != XML_STATUS_ERROR)
								{
									bResult = (iXMLValueBufferSize > 0);
									uSigDataBytes += (Siglist.size() * sizeof(SIG));
								}
								else
									msg("** Signature XML parse error: \"%s\" at line #%u! **\n", XML_ErrorString(XML_GetErrorCode(p)), XML_GetCurrentLineNumber(p));

								XML_ParserFree(p);
							}
						}

						Heap().Free(pszXMLValue);
					}

					iXMLValueBufferSize = 0;
					Heap().Free(pszText);
				}

			}

			fclose(fp);
		}
		else
			msg("** Signature file \"%s\" not found! **\n", SIGFILE);
	}
	MYEXCEPT();

	return(bResult);
}

// Free up signature container
static void FreeSignatureData()
{
	if(!Siglist.empty())
	{
		UINT  uCount = Siglist.size();
		LPSIG e = &Siglist[0];
		do
		{
			if(e->pszTitle) free(e->pszTitle);
			if(e->pData) _aligned_free(e->pData);
			e++, --uCount;
		}while(uCount);

		Siglist.clear();
	}
}

static void idaapi ForumBtnHandler(TView *fields[], int code){ cURLHelp::OpenSupportForum(); }
static void idaapi LuigiBtnHandler(TView *fields[], int code){ open_url("http://aluigi.org/mytoolz.htm#signsrch"); }

// Process a segment for signatures
extern UINT PatternSearch(PBYTE pSrc, int iSrcLen, PBYTE pPattern, int iPatternLen, int iAnd);
static PBYTE pPageBuffer     = NULL;
static UINT  uPageBufferSize = 0;

static void ClearProcessSegmentBuffer()
{
	if(pPageBuffer) Heap().Free(pPageBuffer);
	pPageBuffer     = NULL;
	uPageBufferSize = 0;
}

static void ClearMatchData()
{
	MatchList.clear();
}

static UINT ProcessSegment(segment_t *pSeg)
{
	UINT uMatches = 0;

	if(UINT uSize = pSeg->size())
	{
		if(!pPageBuffer)
		{
			// Usually less then 10mb
			uPageBufferSize = max(uSize, (10 * (1024 * 1024)));
			pPageBuffer     = TAlloc<BYTE>(uPageBufferSize);
			if(!pPageBuffer)
			{
				msg("** Failed to allocate segment bufferr! **\n");
				uPageBufferSize = 0;
				return(0);
			}
		}

		//== Copy IDB bytes to buffer
		// Expand buffer as needed
		if(uSize > uPageBufferSize)
		{
			if(pPageBuffer = TRealloc<BYTE>(pPageBuffer, uSize))
				uPageBufferSize = uSize;
			else
			{
				msg("** Failed to expand segment buffer! **\n");
				return(0);
			}
		}

		// Copy speed appears to be constant regardless of what accessor
		// 7-10-2012 About .3 seconds for every 7mb
		// Note: Padded bytes (that don't exist in the source?) will be all 0xFF
		{
			ea_t  eaCurrent = pSeg->startEA;
			ea_t  eaEnd     = pSeg->endEA;
			PBYTE pBuffer   = pPageBuffer;
			UINT  uCount    = uSize;

			do
			{
				*pBuffer = get_db_byte(eaCurrent);
				++eaCurrent, ++pBuffer, --uCount;

			}while(uCount);
			//DumpData(pPageBuffer, 256);
			//DumpData(pPageBuffer + (uSize - 256), 256);
		}

		// Scan signatures
		{
			// 7-10-2012 about 2 seconds per 6.5mb
			UINT  uCount = Siglist.size();
			LPSIG e      = &Siglist[0];
			char szName[64] = {0};
			get_true_segm_name(pSeg, szName, SIZESTR(szName));

			const int SPINCOUNT = 20;
			const TIMESTAMP MINTIME = ((TIMESTAMP) 1.0 / (TIMESTAMP) 8);
			int iSpinCount = 0;
			TIMESTAMP LastTime = GetTimeStampLow();

			for(UINT i = 0; i < uCount; i++, e++)
			{
				UINT uOffset = PatternSearch(pPageBuffer, uSize, e->pData, e->uSize, e->wBits);
				if(uOffset != -1)
				{
					// Get item address points too for code addresses
					// TOOD: Is there ever data cases too?
					ea_t eaAddress = get_item_head(pSeg->startEA + uOffset);
					//msg("Match %08X \"%s\"\n", eaAddress, e->pszTitle);

					// Optional output to debug channel
					if(bDebugOutput)
						Trace("%08X \"%s\"\n", eaAddress, e->pszTitle);

					// Optional place comment
					if(bPlaceComments)
					{
						const char szPrefix[] = {"<$ignsrch> "};
						char szComment[1024]; szComment[0] = szComment[SIZESTR(szComment)] = 0;

						// Already has one?
						int iSize = get_cmt(eaAddress, TRUE, szComment, SIZESTR(szComment));
						if(iSize > 0)
						{
							// Skip if already Signsrch comment
							if((iSize > sizeof(szPrefix)) && (A_strstr(szComment, szPrefix) != NULL))
								iSize = -1;

							if(iSize != -1)
							{
								// Skip if not enough space
								if((iSize + A_strlen(e->pszTitle) + sizeof("\n")) >= SIZESTR(szComment))
									iSize = -1;

								if(iSize != -1)
								{
									// If big add a line break, else just a space
									if(iSize >= 54)
									{
										strcpy(szComment + iSize, "\n");
										iSize += SIZESTR("\n");
									}
									else
									{
										szComment[iSize] = ' ';
										iSize += SIZESTR(" ");
									}
								}
							}
						}
						else
							iSize = 0;

						if(iSize >= 0)
						{
							sprintf(szComment + iSize, "%s\"%s\" ", szPrefix, e->pszTitle);
							set_cmt(eaAddress, szComment, TRUE);
						}
					}

					MATCH Match = {eaAddress, i};
					MatchList.push_back(Match);
					uMatches++;
				}

				// Periodically update progress display
				// Balanced to cause little overhead
				if(--iSpinCount <= 0)
				{
					TIMESTAMP Time = GetTimeStampLow();
					if((Time - LastTime) >= MINTIME)
					{
						if(WaitBox.IsBreakProgress((int) (((float) i / (float) uCount) * 100.0f), szName))
							return(-1);
						iSpinCount = SPINCOUNT;
						LastTime = Time;
					}
					else
						iSpinCount = (SPINCOUNT / 4);
				}
			}
		}
	}

	return(uMatches);
}


// ============================================================================
// Matches list window stuff
const LPCSTR aColumnHeader[] =
{
	"Address",
	"Size",
	"Label",
};
const int LBCOLUMNCOUNT = (sizeof(aColumnHeader) / sizeof(LPCSTR));
static int aListBColumnWidth[LBCOLUMNCOUNT] = {15, 4, 52}; // (9 | CHCOL_HEX)

UINT CALLBACK LB_OnGetLineCount(PVOID lpParm)
{
	return(MatchList.size());
}

void CALLBACK LB_OnMakeLine(PVOID lpParm, UINT n, char * const *ppCell)
{
	MYTRY()
	{
		// Set column header labels
		if(n == 0)
		{
			for(UINT i = 0; i < LBCOLUMNCOUNT; i++)
				strcpy(ppCell[i], aColumnHeader[i]);
		}
		else
		// Set line strings
		{
			ea_t eaAddress = MatchList[n - 1].eaAddress;
			if(segment_t *pSeg = getseg(eaAddress))
			{
				char szName[32]; szName[SIZESTR(szName)] = 0;
				get_true_segm_name(pSeg, szName, SIZESTR(szName));
				sprintf(ppCell[0], "%s:%08X", szName, eaAddress);
			}
			else
				sprintf(ppCell[0], "unknown:%08X", eaAddress);
			//sprintf(ppCell[0], "%08X", MatchList[n - 1].eaAddress);

			sprintf(ppCell[1], "%04X", Siglist[MatchList[n - 1].uIndex].uSize);
			A_strcpy(ppCell[2], Siglist[MatchList[n - 1].uIndex].pszTitle);
		}
	}
	MYEXCEPT()
}

void CALLBACK LB_OnSelect(PVOID lpParm, UINT n)
{
	MYTRY()
	{
		jumpto(MatchList[n - 1].eaAddress);
	}
	MYEXCEPT()
}

void CALLBACK LB_OnClose(PVOID lpParm)
{
	// Clean up
	ClearMatchData();
	ClearPatternSearchData();
	FreeSignatureData();
	bListWindowUp = FALSE;
}


static void PlugIn_run(int iArg)
{
	if(!bListWindowUp)
	{
		msg("\n== IDA Signsrch plugin: v: %s, BD: %s, By Sirmabus ==\n", PLUGIN_VERSION, __DATE__);
		GetModuleHandleEx((GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS), (LPCTSTR) &PlugIn_run, &hMyModule);

		if(autoIsOk())
		{
			// Currently we only supports8bit byte processors
			if((ph.cnbits != 8) || (ph.dnbits != 8))
			{
				msg("** Sorry only 8bit byte processors are currently supported by the plugin. **\n");
				msg("  The processor for this IDB is %d bit code and %d bit data.\n  Please report this issue on the IDA Signsrch support forum.\n", ph.cnbits, ph.dnbits);
				msg("** Aborted **\n\n");
				return;
			}

			// Do main dialog
			bAltEndianSearch     = FALSE;
			bDebugOutput	     = FALSE;
			bIncludeCodeSegments = TRUE;
			bPlaceComments       = TRUE;
			WORD wOptionFlags = 0;
			if(bAltEndianSearch)     wOptionFlags |= OPT_ALTENDIAN;
			if(bDebugOutput)		 wOptionFlags |= OPT_DEBUGOUT;
			if(bIncludeCodeSegments) wOptionFlags |= OPT_CODESEGS;
			if(bPlaceComments)       wOptionFlags |= OPT_COMMENTS;

			cURLHelp cURLBtn("http://www.macromonkey.com/bb/viewtopic.php?f=65&t=886");
			int iUIResult = AskUsingForm_c(szMainForm, PLUGIN_VERSION, __DATE__, &wOptionFlags, ForumBtnHandler, LuigiBtnHandler);
			if(!iUIResult)
			{
				// User canceled, or no options selected, bail out
				msg(" - Canceled -\n");
				return;
			}

			bAltEndianSearch     = ((wOptionFlags & OPT_ALTENDIAN) != 0);
			bDebugOutput		 = ((wOptionFlags & OPT_DEBUGOUT) != 0);
			bIncludeCodeSegments = ((wOptionFlags & OPT_CODESEGS) != 0);
			bPlaceComments       = ((wOptionFlags & OPT_COMMENTS) != 0);

			if(WaitBox.IsQtQUI())
				WaitBox.Begin("<Signsrch plugin> working...");
			else
				WaitBox.Begin("<Signsrch plugin> working...\n\n\n<Press Pause/Break key to abort>");
			WaitBox.IsBreakProgress(0);

			msg("IDB: %s endian.\n", ((inf.mf == 0) ? "Little" : "Big"));
			TIMESTAMP StartTime = GetTimeStamp();
			if(LoadSignatures())
			{
				BOOL bAborted = WaitBox.IsBreakProgress(50);
				char szNumBuffer[16];
				msg("%s signatures loaded, size: %s.\n\n", FormatUInt(Siglist.size(), szNumBuffer), ByteSizeString(uSigDataBytes));

				// Typical matches less then 200, and this is small
				MatchList.reserve(256);

				if(!Siglist.empty())
				{
					uTotalMatches = 0;

					// Walk segments
					int iCount = get_segm_qty();
					for(int i = 0; (i < iCount) && !bAborted; i++)
					{
						if(segment_t *pSeg = getnseg(i))
						{
							char szName[64] = {0};
							get_true_segm_name(pSeg, szName, SIZESTR(szName));
							char szClass[16] = {0};
							get_segm_class(pSeg, szClass, SIZESTR(szClass));

							switch(pSeg->type)
							{
								// Types to skip
								case SEG_XTRN:
								case SEG_GRP:
								case SEG_NULL:
								case SEG_UNDF:
								case SEG_ABSSYM:
								case SEG_COMM:
								case SEG_IMEM:
								case SEG_CODE:
								if(!((pSeg->type == SEG_CODE) && bIncludeCodeSegments))
								{
									msg("Skipping segment: \"%s\", \"%s\", %d, %08X - %08X, %s\n", szName, szClass, pSeg->type, pSeg->startEA,pSeg->endEA, ByteSizeString(pSeg->size()));
									break;
								}

								default:
								{
									msg("Processing segment: \"%s\", \"%s\", %d, %08X - %08X, %s\n", szName, szClass, pSeg->type, pSeg->startEA,pSeg->endEA, ByteSizeString(pSeg->size()));
									UINT uMatches = ProcessSegment(pSeg);
									if(uMatches> 0)
									{
										if(uMatches != -1)
										{
											uTotalMatches += uMatches;
											msg("%u matches here.\n", uMatches);
										}
										else
											bAborted = TRUE;
									}
								}
								break;
							};
						}
					}

					// Sort match list by address
					if(!bAborted)
						std::sort(MatchList.begin(), MatchList.end(), MATCH());

					ClearPatternSearchData();
					ClearProcessSegmentBuffer();
				}
				else
					msg("** No loaded signitures!, Aborted **\n");

				if(!bAborted)
				{
					WaitBox.IsBreakProgress(100);
					msg("\nDone: Found %u matches in %s.\n\n", uTotalMatches, TimeString(GetTimeStamp() - StartTime));

					if(bDebugOutput)
						Trace("%u signature matches.\n", uTotalMatches);

					if(!MatchList.empty())
					{
						// Create list view window
						bListWindowUp = !choose2(0,	// Non-modal window
							-1, -1, -1, -1,			// Window position
							&MatchList,				// Pass data
							LBCOLUMNCOUNT,			// Number of columns
							aListBColumnWidth,		// Widths of columns
							LB_OnGetLineCount,		// Function that returns number of lines
							LB_OnMakeLine,  		// Function that generates a line
							"[ Signsrch matches ]",	// Window title
						    -1,	 					// Icon for the window
							0,						// Starting line
							NULL,					// "kill" callback
							NULL,					// "new" callback
							NULL,					// "update" callback
							NULL,					// "edit" callback
							LB_OnSelect,			// Function to call when the user pressed Enter
							LB_OnClose,				// Function to call when the window is closed
							NULL,					// Popup menu items
							NULL);	    			// Line icon function
					}
					else
					{
						ClearMatchData();
						FreeSignatureData();
					}
				}
				else
				{
					msg("** Plugin aborted **\n\n");
					ClearMatchData();
					FreeSignatureData();
				}
			}
			else
				msg("** Failed to load signitures, Aborted **\n");
		}
		else
			msg("** Please wait for autoanalysis finish first!, Aborted **\n");

		refresh_idaview_anyway();
		WaitBox.End();
	}
	else
		PlaySound((LPCSTR) SND_ALIAS_SYSTEMEXCLAMATION, NULL, (SND_ALIAS_ID | SND_ASYNC));
}

