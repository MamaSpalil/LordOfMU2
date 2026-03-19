#include "stdafx.h"
#include "Application.h"
#include "DebugMonitor.h"
#include "MainWnd.h"
#include "Debugger.h"
#include "Loader.h"
#include "MSCorEE.h"
#include "../_Shared/version.h"
#include "../_Shared/MuUtil.h"


#include "../_Shared/UserUtil.h"

#include "HTMLWindow.h"


/**  
 * \brief 
 */
CApplication::CApplication()
{
	m_cSettings.Load();
}


/**  
 * \brief 
 */
CApplication::~CApplication()
{
}



/**  
 * \brief 
 */
int CApplication::Run()
{
	
	// Bind to the CLR runtime..
	ICLRRuntimeHost *pClrHost = NULL;

	HRESULT hr = CorBindToRuntimeEx(NULL, L"wks", 0, CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost, (PVOID*)&pClrHost);

	// Push the big START button shown above
	hr = pClrHost->Start();

	// Okay, the CLR is up and running in this (previously native) process.
	// Now call a method on our managed C# class library.

	CStdString strUrlUI = GetUrlForUI();


	wchar_t szUrl[1024];
	memset(szUrl, 0, sizeof(szUrl));
	AnsiToUnicode(szUrl, GetUrlForUI().c_str(), 1024);
	
	DWORD dwRet = 0;
	hr = pClrHost->ExecuteInDefaultAppDomain(L"MUAutoClickerUI.dll", L"MUAutoClickerUI.Program", L"MainEntry", szUrl, &dwRet);

	// Optionally stop the CLR runtime (we could also leave it running)
	hr = pClrHost->Stop();

	// Don't forget to clean up.
	pClrHost->Release();

/*
	HTMLWindow wnd("muonline.ktemelkov.info/ui/ui.php", "asdf", ghInstance, true);

	MSG msg = {0};

	while (CUserUtil::GetMessageA(&msg, 0, 0, 0) > 0)
	{
//		if (!CUserUtil::IsDialogMessageA(wnd.m_hWnd, &msg))
		{
			CUserUtil::TranslateMessage(&msg);
			CUserUtil::DispatchMessageA(&msg);
		}
	}


DWORD dwRet = 0;
*/

	if (dwRet == 1)
	{
#ifndef _DEBUG
		CDebugger dbg;
		dbg.Run();
#else
		CLoader::Load();
#endif
	}



/*
	CMainWnd wnd(m_cSettings);

	if (!wnd.Create())
		return -1;

	MSG msg = {0};

	while (CUserUtil::GetMessageA(&msg, 0, 0, 0) > 0)
	{
		if (!CUserUtil::IsDialogMessageA(wnd.m_hWnd, &msg))
		{
			CUserUtil::TranslateMessage(&msg);
			CUserUtil::DispatchMessageA(&msg);
		}
	}

	m_cSettings.Save();

	if (wnd.GetResult() == IDOK)
	{
#ifndef _DEBUG
		CDebugger dbg;
		dbg.Run();
#else
		CLoader::Load();
#endif
	}
*/

	return 0;
}



/**  
 * \brief 
 */
CStdString CApplication::GetUrlForUI()
{
	return CStdString("");
}



/**  
 * \brief 
 */
void CApplication::AnsiToUnicode(wchar_t* pszDst, const char* pszSrc, int dstSize, int srcSize)
{
	int len = (srcSize > -1) ? srcSize : (lstrlenA(pszSrc) + 1);

	if (len > dstSize)
	{
		len = dstSize-1;

		if (dstSize > 0)
			pszDst[len] = 0;
	}

	for (int i=0; i < len; i++)
		pszDst[i] = (wchar_t)pszSrc[i];
}
