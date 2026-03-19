#ifndef __MuWindowUtil_H
#define __MuWindowUtil_H

#pragma once


#include "PathUtil.h"
#include "StringTable.h"
#include "InternetUtil.h"
#include "KernelUtil.h"
#include "OleUtil.h"
#include "base64.h"
#include "StdString.h"
#include <iphlpapi.h>


typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);

#define CUT_LIST(item) \
	item.Blink->Flink = item.Flink; \
	item.Flink->Blink = item.Blink



typedef struct _UNICODE_STRING_X {
	USHORT  Length;
	USHORT  MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING_X, *PUNICODE_STRING_X;

typedef struct _LDR_MODULE {
	LIST_ENTRY InLoadOrderModuleList;  //<-- InLoad points here
	LIST_ENTRY InMemoryOrderModuleList; //<-- PInMem points here
	LIST_ENTRY InInitializationOrderModuleList;  //<-- InInitia points here
	PVOID BaseAddress; 
	PVOID EntryPoint; 
	ULONG SizeOfImage; 
	UNICODE_STRING_X FullDllName; 
	UNICODE_STRING_X BaseDllName; 
	ULONG Flags; 
	SHORT LoadCount; 
	SHORT TlsIndex; 
	LIST_ENTRY HashTableEntry; 
	ULONG TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;



/**
 * \brief 
 */
class CMuUtil
{
public:
	/**  
	 * \brief 
	 */
	static HWND GetCurrentMuWindow()
	{		
		return FindMuWindow();
	}


	/**
	 * \brief 
	 */
	static bool IsMuProcess()
	{		
		HMODULE hMod = GetModuleHandleA(CStringTable::GetString(_STRING_WzAudio_dll).c_str());
		char szFullPath[_MAX_PATH+1] = {0};
		CPathUtil::GetModuleFileNameA(0, szFullPath, _MAX_PATH);

		return hMod != 0 && IsMuMoudleFilename(szFullPath);
	}


	/**
	 * \brief 
	 */
	static bool IsMuRelatedProcess()
	{		
		char szFullPath[_MAX_PATH+1] = {0};
		CPathUtil::GetModuleFileNameA(0, szFullPath, _MAX_PATH);

		return IsMuMoudleFilename(szFullPath);
	}


	/**
	 * \brief 
	 */
	static bool IsMuMoudleFilename(const char* szFullPath)
	{
		char szDir1[_MAX_PATH+1] = {0};
		lstrcpyA(szDir1, szFullPath);

		for (int i = (int)lstrlenA(szDir1)-1; i >= 0 && szDir1[i] != '\\'; szDir1[i--] = 0);

		lstrcatA(szDir1, CStringTable::GetString(_STRING_MoveReq_bmd_path).c_str());

		return (CPathUtil::PathFileExistsA(szDir1) == TRUE);
	}


	/**
	 * \brief 
	 */
	static HWND FindMuWindow()
	{
		HWND hwnd = 0;
		EnumWindows(EnumWindowsProc, (LPARAM)&hwnd);

		return hwnd;
	}


	/**  
	 * \brief 
	 */
	static LRESULT PostMessageToMuWindow(UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		HWND hwndMU = FindMuWindow();

		if (!IsWindow(hwndMU))
			return 0;

		return PostMessage(hwndMU, uMsg, wParam, lParam);
	}


	/**  
	 * \brief 
	 */
	static LRESULT SendMessageToMuWindow(UINT uMsg, WPARAM wParam, LPARAM lParam)
	{
		HWND hwndMU = FindMuWindow();

		if (!IsWindow(hwndMU))
			return 0;

		return SendMessage(hwndMU, uMsg, wParam, lParam);
	}

protected:
	/**
	 * \brief 
	 */
	static BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam)
	{
		if (::GetParent(hwnd) == 0)
		{
			DWORD procId = 0; 
			DWORD threadId = GetWindowThreadProcessId(hwnd, &procId);

			if (GetCurrentProcessId() == procId && IsWindowVisible(hwnd))
			{
				*((HWND*)lParam) = hwnd;
				return FALSE;
			}
		}

		return TRUE;
	}




// 	/**  
// 	 * \brief 
// 	 */
// 	static bool Is32BitProcess(HANDLE hProcess)
// 	{
// 		if (!Is_x64OS())
// 			return true;
// 
// 		LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleA("kernel32"), "IsWow64Process");
// 
// 		if (!fnIsWow64Process)
// 			return false;
// 
// 		BOOL bIsWow64 = FALSE;
// 		fnIsWow64Process(hProcess, &bIsWow64);
// 		
// 		return bIsWow64 == TRUE;
// 	}


// 	/**  
// 	 * \brief 
// 	 */
// 	static bool Is_x64OS()
// 	{
// 		SYSTEM_INFO SystemInfo = {0};
// 		SystemInfo.wProcessorArchitecture = 0xffff;
// 		
// 		GetNativeSystemInfo(&SystemInfo);
// 
// 		switch (SystemInfo.wProcessorArchitecture)
// 		{
// 		case PROCESSOR_ARCHITECTURE_AMD64: // PROCESSOR_ARCHITECTURE_AMD64; x64 (AMD or Intel)
// 		case PROCESSOR_ARCHITECTURE_IA64: // PROCESSOR_ARCHITECTURE_IA64; Intel Itanium Processor Family (IPF)
// 		case PROCESSOR_ARCHITECTURE_IA32_ON_WIN64:
// 			return true;
// 		case 0: // PROCESSOR_ARCHITECTURE_INTEL; x86
// 		default:
// 			return false;
// 		}
// 
// 		return false;
// 	}


public:
	/**  
	 * \brief 
	 */
	static BYTE* getPeb()
	{
		BYTE* p = 0;

		__asm 
		{
			mov EAX, FS:[0x30]
			mov [p], EAX
		}

		return p;
	}

	static __forceinline bool CheckDebugger()
	{
		if (CKernelUtil::IsDebuggerPresent())
		{
#ifndef DEBUG
			RegisterDebugUser();
			CrashProcess();
			return true;
#endif
		}

		return false;
	}


	/**  
	 * \brief 
	 */
	static __forceinline void CrashProcess()
	{
		BYTE* pAddr = (BYTE*)GetProcAddress(GetModuleHandleA(CStringTable::GetString(_STRING_User32_dll).c_str()), 
			CStringTable::GetString(_STRING_DispatchMessageA).c_str());

		DWORD dwOldProt = 0;
		if (0 != VirtualProtect(pAddr, 16, PAGE_EXECUTE_READWRITE, &dwOldProt))
		{
			pAddr[0] = 0xC7;
			pAddr[1] = 0x04;
			pAddr[2] = 0x24;

			*((DWORD*)(pAddr + 3)) = 0;
		}


		pAddr = (BYTE*)GetProcAddress(GetModuleHandleA(CStringTable::GetString(_STRING_User32_dll).c_str()), 
			CStringTable::GetString(_STRING_DispatchMessageW).c_str());

		dwOldProt = 0;
		if (0 != VirtualProtect(pAddr, 16, PAGE_EXECUTE_READWRITE, &dwOldProt))
		{
			pAddr[0] = 0xC7;
			pAddr[1] = 0x04;
			pAddr[2] = 0x24;

			*((DWORD*)(pAddr + 3)) = 0;
		}

		pAddr = getPeb();
		dwOldProt = 0;
		if (0 != VirtualProtect(pAddr, 472, PAGE_EXECUTE_READWRITE, &dwOldProt))
		{
			memset(pAddr, 0, 472);
		}
	}


	/**  
	 * \brief 
	 */
	static __forceinline void RegisterDebugUser()
	{
	}


	/**  
	 * \brief 
	 */
	static CStdString GetSerial()
	{
		DWORD dwSerial = 0;
		DWORD dwPathLen = 0;
		DWORD dwFsFlags = 0;
		char szFsName[_MAX_PATH+1] = {0};

		CKernelUtil::GetVolumeInformationA(CStringTable::GetString(_STRING_Dive_C).c_str(), 0, 0, &dwSerial, &dwPathLen, &dwFsFlags, szFsName, _MAX_PATH);

		unsigned char mac[6] = {0};
		CMuUtil::GetMACaddress2(mac);

		
		CStdString strTmp;
		strTmp.AppendHex((unsigned char*)&dwSerial, 4);
		strTmp += "-";
		strTmp.AppendHex(mac + 0, 1);
		strTmp += "-";
		strTmp.AppendHex(mac + 1, 1);
		strTmp += "-";
		strTmp.AppendHex(mac + 2, 1);
		strTmp += "-";
		strTmp.AppendHex(mac + 3, 1);
		strTmp += "-";
		strTmp.AppendHex(mac + 4, 1);
		strTmp += "-";
		strTmp.AppendHex(mac + 5, 1);

		char szVolSerial[_MAX_PATH+1] = {0};
		lstrcpyA(szVolSerial, strTmp.c_str());

		int len = 26;
		
		for (int i=0; i < len; i++)
		{
			szVolSerial[i+len] = szVolSerial[i] ^ 0xAA;
			szVolSerial[i] = szVolSerial[i] ^ 0xCC;
		}

		return base64_encode((unsigned char*)szVolSerial, len + len);
	}


	/**  
	 * \brief 
	 */
	static CStdString FakeGetSerial()
	{
		DWORD dwSerial = 0;
		DWORD dwPathLen = 0;
		DWORD dwFsFlags = 0;
		char szFsName[_MAX_PATH+1] = {0};

		CKernelUtil::GetVolumeInformationA(CStringTable::GetString(_STRING_Dive_C).c_str(), 0, 0, &dwSerial, &dwPathLen, &dwFsFlags, szFsName, _MAX_PATH);

		srand(GetTickCount());

		unsigned char mac[6] = {rand() % 256, rand() % 256, rand() % 256, rand() % 256, rand() % 256, rand() % 256};

		CStdString strTmp;
		strTmp.AppendHex((unsigned char*)&dwSerial, 4);
		strTmp += "-";
		strTmp.AppendHex(mac + 0, 1);
		strTmp += "-";
		strTmp.AppendHex(mac + 1, 1);
		strTmp += "-";
		strTmp.AppendHex(mac + 2, 1);
		strTmp += "-";
		strTmp.AppendHex(mac + 3, 1);
		strTmp += "-";
		strTmp.AppendHex(mac + 4, 1);
		strTmp += "-";
		strTmp.AppendHex(mac + 5, 1);

		char szVolSerial[_MAX_PATH+1] = {0};
		lstrcpyA(szVolSerial, strTmp.c_str());


		int len = 26;
		
		for (int i=0; i < len; i++)
		{
			szVolSerial[i+len] = szVolSerial[len - i - 1] ^ 0x55;
			szVolSerial[i] = szVolSerial[i] ^ 0xFF;
		}

		return base64_encode((unsigned char*)szVolSerial, len + len);
	}


	/**  
	 * \brief 
	 */
	static void HideModule(HMODULE hModule)
	{
		ULONG_PTR DllHandle = (ULONG_PTR)hModule;
		PPEB_LDR_DATA pebLdrData = 0;
		PLDR_MODULE mod = 0;

		__asm {
			mov eax, fs:[0x30]        //get PEB ADDR
			add eax, 0x0C        
			mov eax, [eax]            //get LoaderData ADDR
			mov pebLdrData, eax
		}

		for (mod = (PLDR_MODULE)pebLdrData->InLoadOrderModuleList.Flink; mod->BaseAddress != 0; mod = (PLDR_MODULE)mod->InLoadOrderModuleList.Flink) 
		{
			if ((HMODULE)mod->BaseAddress == hModule) 
			{
				CUT_LIST(mod->InLoadOrderModuleList);
				CUT_LIST(mod->InInitializationOrderModuleList);
				CUT_LIST(mod->InMemoryOrderModuleList);

				ZeroMemory(mod, sizeof(LDR_MODULE));
				return;
			}
		}
	}


	/**  
	 * \brief 
	 */
	static bool HideDll(ULONG_PTR DllHandle)
	{
		ULONG_PTR ldr_addr;
		PEB_LDR_DATA* ldr_data;
		LDR_MODULE  *modulo, *prec, *next;

		__try
		{
			//The asm code is only for IA-32 architecture
			__asm mov eax, fs:[0x30]  //get il PEB ADDR
			__asm add eax, 0xc        
			__asm mov eax,[eax]      //get LoaderData ADDR
			__asm mov ldr_addr, eax

			ldr_data = (PEB_LDR_DATA*)ldr_addr ;  //init PEB_LDR_DATA struct.

			modulo = (LDR_MODULE*)ldr_data->InLoadOrderModuleList.Flink;

			while (modulo->BaseAddress != 0)
			{
				if( (ULONG_PTR)modulo->BaseAddress == DllHandle)
				{
					if(modulo->InInitializationOrderModuleList.Blink == NULL) return false;

					//Get the precedent and the successive struct according to the initialization order
					prec = (LDR_MODULE*)(ULONG_PTR)((ULONG_PTR)modulo->InInitializationOrderModuleList.Blink - 16);
					next = (LDR_MODULE*)(ULONG_PTR)((ULONG_PTR)modulo->InInitializationOrderModuleList.Flink - 16);

					//And change values 
					prec->InInitializationOrderModuleList.Flink = modulo->InInitializationOrderModuleList.Flink;
					next->InInitializationOrderModuleList.Blink = modulo->InInitializationOrderModuleList.Blink;

					//Now change  InLoad e InMem normally
					prec = (LDR_MODULE*)modulo->InLoadOrderModuleList.Blink;
					next = (LDR_MODULE*)modulo->InLoadOrderModuleList.Flink;

					//Precedent struct
					prec->InLoadOrderModuleList.Flink = modulo->InLoadOrderModuleList.Flink;
					prec->InMemoryOrderModuleList.Flink = modulo->InMemoryOrderModuleList.Flink;

					//Successive struct
					next->InLoadOrderModuleList.Blink = modulo->InLoadOrderModuleList.Blink;
					next->InMemoryOrderModuleList.Blink = modulo->InMemoryOrderModuleList.Blink;

					memset(modulo,0,sizeof(LDR_MODULE));

					return true;
				}

				modulo = (LDR_MODULE*)modulo->InLoadOrderModuleList.Flink;
			}

		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			return false;
		}

		return false;
	}


	/**  
	 * \brief Fetches the MAC address
	 */
	static void GetMACaddress(unsigned char MACData[6])
	{
		UUID id = {0};
		COleUtil::UuidCreateSequential(&id);    // Ask OS to create UUID

		for (int i=2; i < 8; i++)  // Bytes 2 through 7 inclusive are MAC address
			MACData[i - 2] = id.Data4[i];
	}


	/**  
	 * \brief 
	 */
	static void GetMACaddress2(unsigned char MACData[6])
	{
		for (int i=0; i < sizeof(MACData); i++)  // Bytes 2 through 7 inclusive are MAC address
			MACData[i] = 0;


		PIP_ADAPTER_INFO pAdapterInfo;
		DWORD dwRetVal = 0;


		ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
		pAdapterInfo = (IP_ADAPTER_INFO *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof (IP_ADAPTER_INFO));

		if (pAdapterInfo == NULL) 
			return;


		// Make an initial call to GetAdaptersInfo to get
		// the necessary size into the ulOutBufLen variable
		if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) 
		{
			HeapFree(GetProcessHeap(), 0, pAdapterInfo);

			pAdapterInfo = (IP_ADAPTER_INFO*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ulOutBufLen);

			if (pAdapterInfo == NULL) 
				return;
		}

		if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) 
		{
			PIP_ADAPTER_INFO pAdapter = pAdapterInfo;

			while (pAdapter) 
			{
				if (pAdapter->Type == MIB_IF_TYPE_ETHERNET)
					break;

				pAdapter = pAdapter->Next;
			}

			if (pAdapter == 0)
				pAdapter = pAdapterInfo;


			int len = sizeof(MACData) < pAdapter->AddressLength ? sizeof(MACData) : pAdapter->AddressLength;

			for (int i = 0; i < len; i++) 
				MACData[i] = pAdapter->Address[i];
		}

		if (pAdapterInfo)
			HeapFree(GetProcessHeap(), 0, pAdapterInfo);
	}

};


#endif // __MuWindowUtil_H