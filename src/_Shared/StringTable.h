#pragma once

#include "base64.h"
#include "StdString.h"


#define _STRING_Winsock32_dll			0x00000000
#define _STRING_WSCEnumProtocols		0x00000001
#define _STRING_WSAStartup				0x00000002
#define _STRING_WSACleanup				0x00000003
#define _STRING_WSCInstallProvider		0x00000004
#define _STRING_WSCWriteProviderOrder	0x00000005
#define _STRING_WSCDeinstallProvider	0x00000006
#define _STRING_WSPStartup				0x00000007
#define _STRING_WPUCompleteOverlappedRequest 0x00000008
#define _STRING_WSCGetProviderPath		0x00000009
#define _STRING_WSASetLastError			0x0000000A
#define _STRING_WSAGetLastError			0x0000000B


#define _STRING_Kernel32_dll		0x00010000
#define _STRING_GetModuleHandleA	0x00010001
#define _STRING_LoadLibraryA		0x00010002
#define _STRING_FreeLibrary			0x00010003
#define _STRING_GetProcAddress		0x00010004
#define _STRING_CopyFileA			0x00010005
#define _STRING_QueueUserAPC		0x00010006
#define _STRING_GetModuleFileNameA	0x00010007
#define _STRING_ExpandEnvironmentStringsA	0x00010008
#define _STRING_CheckRemoteDebuggerPresent	0x00010009
#define _STRING_IsDebuggerPresent			0x0001000A
#define _STRING_ExitProcess					0x0001000B
#define _STRING_GetVolumeInformationA		0x0001000C
#define _STRING_CreateMutexA				0x0001000D
#define _STRING_GetLastError				0x0001000E

#define _STRING_WaitForDebugEvent		0x0001000F
#define _STRING_DebugActiveProcess		0x00010010
#define _STRING_ContinueDebugEvent	    0x00010011
#define _STRING_DebugSetProcessKillOnExit 0x00010012	
#define _STRING_GetThreadContext		0x00010013
#define _STRING_SetThreadContext		0x00010014
#define _STRING_SuspendThread			0x00010015
#define _STRING_ResumeThread			0x00010016
#define _STRING_ReadProcessMemory		0x00010017
#define _STRING_WriteProcessMemory		0x00010018
#define _STRING_FlushInstructionCache	0x00010019
#define _STRING_DebugActiveProcessStop	0x0001001A
#define _STRING_CreateProcessA			0x0001001B
#define _STRING_CloseHandle				0x0001001C
#define _STRING_SleepEx					0x0001001D
#define _STRING_Sleep					0x0001001E


#define _STRING_LordOfMU_LspDllName			0x00020000
#define _STRING_LordOfMU_LspDllInstallPath	0x00020001
#define _STRING_PERCENT_TEMP_PERCENT		0x00020002
#define _STRING_LordOfMU_BootstrapperName	0x00020003
#define _STRING_WzAudio_dll					0x00020004
#define _STRING_MoveReq_bmd_path			0x00020005

#define _STRING_Dive_C						0x00020009
#define _STRING_RegisterUrl					0x0002000A
#define _STRING_RegDebugUrl					0x0002000B
#define _STRING_MuAutoClickerExecMutex		0x0002000C
#define _STRING_SerialFormat				0x0002000D
#define _STRING_MUAutoClicker_exe			0x0002000E


#define _STRING_Shlwapi_dll			0x00030000
#define _STRING_PathFileExistsA		0x00030001
#define _STRING_PathFindFileNameA	0x00030002
#define _STRING_PathAddBackslashA	0x00030003


#define _STRING_Ole32_dll		0x00040000
#define _STRING_StringFromGUID2	0x00040001

#define _STRING_Wininet_dll			0x00050000
#define _STRING_InternetOpenUrlA	0x00050001
#define _STRING_InternetReadFile	0x00050002
#define _STRING_InternetOpenA		0x00050003
#define _STRING_InternetCloseHandle 0x00050004
#define _STRING_InternetGetLastResponseInfoA 0x00050005
#define _STRING_InternetCanonicalizeUrlA 0x00050006

#define _STRING_Rpcrt4_dll				0x00060000
#define _STRING_UuidCreateSequential	0x00060001

#define _STRING_User32_dll					0x00070000
#define _STRING_DispatchMessageA			0x00070001
#define _STRING_DispatchMessageW			0x00070002
#define _STRING_CreateDialogParamA			0x00070003
#define _STRING_GetMessageA					0x00070004
#define _STRING_IsDialogMessageA			0x00070005
#define _STRING_TranslateMessage			0x00070006


/**  
 * \brief 
 */
class CStringTable
{
private:
	struct StringTableEntry
	{
		const char* str;
	};

	/**  
	 * \brief 
	 */
	struct StringTableSection
	{
		const char* contents[255];	
	};


public:
	/**  
	 * \brief 
	 */
	static CStdString GetString(int id)
	{
		StringTableSection* pTable = CStringTable::GetTablePtr();
		return base64_decode(pTable[CStringTable::GetSection(id)].contents[CStringTable::GetIndex(id)]);
	}


private:
	/**  
	 * \brief 
	 */
	static int GetSection(int id)
	{
		return (id & 0xFFFF0000) >> 16; 
	}

	/**  
	 * \brief 
	 */
	static int GetIndex(int id)
	{
		return (id & 0x0000FFFF); 
	}


	/**  
	 * \brief 
	 */
	static StringTableSection* GetTablePtr()
	{
		static StringTableSection table[] =
		{
			// 0x0000-
			{
				"d3MyXzMyLmRsbA==",				// 0x00000000 - ws2_32.dll
				"V1NDRW51bVByb3RvY29scw==",		// 0x00000001 - WSCEnumProtocols
				"V1NBU3RhcnR1cA==",				// 0x00000002 - WSAStartup
				"V1NBQ2xlYW51cA==",				// 0x00000003 - WSACleanup
				"V1NDSW5zdGFsbFByb3ZpZGVyVw==",	// 0x00000004 - WSCInstallProviderW
				"V1NDV3JpdGVQcm92aWRlck9yZGVy",	// 0x00000005 - WSCWriteProviderOrder
				"V1NDRGVpbnN0YWxsUHJvdmlkZXI=", // 0x00000006 - WSCDeinstallProvider
				"V1NQU3RhcnR1cA==",				// 0x00000007 - WSPStartup <- _STRING_WSPStartup
				"V1BVQ29tcGxldGVPdmVybGFwcGVkUmVxdWVzdA==",	// 0x00000008 - WPUCompleteOverlappedRequest
				"V1NDR2V0UHJvdmlkZXJQYXRo",		// 0x00000009 - WSCGetProviderPath
				"V1NBU2V0TGFzdEVycm9y",			// 0x0000000A - WSASetLastError
				"V1NBR2V0TGFzdEVycm9y",			// 0x0000000B - WSAGetLastError
				0
			},

			// 0x0001-
			{
				"a2VybmVsMzIuZGxs",			// 0x00010000 - kernel32.dll
				"R2V0TW9kdWxlSGFuZGxlQQ==", // 0x00010001 - GetModuleHandleA
				"TG9hZExpYnJhcnlB",			// 0x00010002 - LoadLibraryA
				"RnJlZUxpYnJhcnk=",			// 0x00010003 - FreeLibrary
				"R2V0UHJvY0FkZHJlc3M=",		// 0x00010004 - GetProcAddress
				"Q29weUZpbGVB",				// 0x00010005 - CopyFileA
				"UXVldWVVc2VyQVBD",			// 0x00010006 - QueueUserAPC
				"R2V0TW9kdWxlRmlsZU5hbWVB", // 0x00010007 - GetModuleFileNameA
				"RXhwYW5kRW52aXJvbm1lbnRTdHJpbmdzQQ==", // 0x00010008 - ExpandEnvironmentStringsA
				"Q2hlY2tSZW1vdGVEZWJ1Z2dlclByZXNlbnQ=", // 0x00010009 - CheckRemoteDebuggerPresent
				"SXNEZWJ1Z2dlclByZXNlbnQ=",				// 0x0001000A - IsDebuggerPresent
				"RXhpdFByb2Nlc3M=",						// 0x0001000B - ExitProcess
				"R2V0Vm9sdW1lSW5mb3JtYXRpb25B",			// 0x0001000C - GetVolumeInformationA
				"Q3JlYXRlTXV0ZXhB",						// 0x0001000D - CreateMutexA
				"R2V0TGFzdEVycm9y",						// 0x0001000E - GetLastError
				"V2FpdEZvckRlYnVnRXZlbnQ=",				// 0x0001000F - WaitForDebugEvent		
				"RGVidWdBY3RpdmVQcm9jZXNz",				// 0x00010010 - DebugActiveProcess				
				"Q29udGludWVEZWJ1Z0V2ZW50",				// 0x00010011 - ContinueDebugEvent	    
				"RGVidWdTZXRQcm9jZXNzS2lsbE9uRXhpdA==", // 0x00010012 - DebugSetProcessKillOnExit 	
				"R2V0VGhyZWFkQ29udGV4dA==",				// 0x00010013 - GetThreadContext		
				"U2V0VGhyZWFkQ29udGV4dA==",				// 0x00010014 - SetThreadContext		
				"U3VzcGVuZFRocmVhZA==",					// 0x00010015 - SuspendThread			
				"UmVzdW1lVGhyZWFk",						// 0x00010016 - ResumeThread			
				"UmVhZFByb2Nlc3NNZW1vcnk=",				// 0x00010017 - ReadProcessMemory		
				"V3JpdGVQcm9jZXNzTWVtb3J5",				// 0x00010018 - WriteProcessMemory		
				"Rmx1c2hJbnN0cnVjdGlvbkNhY2hl",			// 0x00010019 - FlushInstructionCache	
				"RGVidWdBY3RpdmVQcm9jZXNzU3RvcA==",		// 0x0001001A - DebugActiveProcessStop	
				"Q3JlYXRlUHJvY2Vzc0E=",					// 0x0001001B - CreateProcessA	
				"Q2xvc2VIYW5kbGU=",						// 0x0001001C - CloseHandle	
				"U2xlZXBFeA==",							// 0x0001001D - SleepEx
				"U2xlZXA=",								// 0x0001001E - Sleep
				0
			},

			// 0x0002-
			{
				"TUFDTG9jYXRvci5kbGw=",								// 0x00020000 - MACLocator.dll <- _STRING_LordOfMU_LspDllName
				"JVN5c3RlbVJvb3QlXHN5c3RlbTMyXE1BQ0xvY2F0b3IuZGxs", // 0x00020001 - %SystemRoot%\system32\MACLocator.dll <- _STRING_LordOfMU_LspDllInstallPath
				"JVRFTVAl",											// 0x00020002 - %TEMP% <- _STRING_PERCENT_TEMP_PERCENT
				"Qm9vdHN0cmFwcGVyLmRsbA==",							// 0x00020003 - Bootstrapper.dll <- _STRING_LordOfMU_BootstrapperName
				"V3pBdWRpby5kbGw=",									// 0x00020004 - WzAudio.dll
				"RGF0YVxMb2NhbFxtb3ZlcmVxLmJtZA==",					// 0x00020005 - Data\Local\movereq.bmd
				"dXNlcjMyLmRsbA==",									// 0x00020006 - user32.dll
				"RGlzcGF0Y2hNZXNzYWdlQQ==",							// 0x00020007 - DispatchMessageA
				"RGlzcGF0Y2hNZXNzYWdlVw==",							// 0x00020008 - DispatchMessageW
				"Qzpc",												// 0x00020009 - "C:\"
				"",				// 0x0002000A - (removed external license URL)
				"", // 0x0002000B - (removed external license URL)
				"X19NdUF1dG9DbGlja2VyRXhlY011dGV4X18=",				// 0x0002000C - __MuAutoClickerExecMutex__
				"JTA4WC0lMDJYLSUwMlgtJTAyWC0lMDJYLSUwMlgtJTAyWA==", // 0x0002000D - %08X-%02X-%02X-%02X-%02X-%02X-%02X
				"TVVBdXRvQ2xpY2tlci5leGU=",							// 0x0002000E - MUAutoClicker.exe
				0
			},

			// 0x0003-
			{
				"c2hsd2FwaS5kbGw=",			// 0x00030000 - shlwapi.dll
				"UGF0aEZpbGVFeGlzdHNB",		// 0x00030001 - PathFileExistsA
				"UGF0aEZpbmRGaWxlTmFtZUE=", // 0x00030002 - PathFindFileNameA
				"UGF0aEFkZEJhY2tzbGFzaEE=", // 0x00030003 - PathAddBackslashA
				0
			},

			// 0x0004-
			{
				"b2xlMzIuZGxs",			// 0x00040000 - ole32.dll
				"U3RyaW5nRnJvbUdVSUQy", // 0x00040001 - StringFromGUID2
				0
			},

			// 0x0005-
			{
				"V2luaW5ldC5kbGw=",				// 0x00050000 - Wininet.dll
				"SW50ZXJuZXRPcGVuVXJsQQ==",		// 0x00050001 - InternetOpenUrlA
				"SW50ZXJuZXRSZWFkRmlsZQ==",		// 0x00050002 - InternetReadFile
				"SW50ZXJuZXRPcGVuQQ==",			// 0x00050003 - InternetOpenA
				"SW50ZXJuZXRDbG9zZUhhbmRsZQ==",	// 0x00050004 - InternetCloseHandle
				"SW50ZXJuZXRHZXRMYXN0UmVzcG9uc2VJbmZvQQ==", // 0x00050005 - InternetGetLastResponseInfoA
				"SW50ZXJuZXRDYW5vbmljYWxpemVVcmxB", // 0x00050006 - InternetCanonicalizeUrlA
				0
			},

			// 0x0006-
			{
				"UnBjcnQ0LmRsbA==",					// 0x00060000 - Rpcrt4.dll
				"VXVpZENyZWF0ZVNlcXVlbnRpYWw=",		// 0x00060001 - UuidCreateSequential
				0
			},

			// 0x0007-
			{
				"dXNlcjMyLmRsbA==",			// 0x00070000 - user32.dll
				"RGlzcGF0Y2hNZXNzYWdlQQ==", // 0x00070001 - DispatchMessageA
				"RGlzcGF0Y2hNZXNzYWdlVw==", // 0x00070002 - DispatchMessageW
				"Q3JlYXRlRGlhbG9nUGFyYW1B", // 0x00070003 - CreateDialogParamA
				"R2V0TWVzc2FnZUE=",			// 0x00070004 - GetMessageA
				"SXNEaWFsb2dNZXNzYWdlQQ==", // 0x00070005 - IsDialogMessageA
				"VHJhbnNsYXRlTWVzc2FnZQ==", // 0x00070006 - TranslateMessage
				0,
			},
		};

		return table;
	}
};