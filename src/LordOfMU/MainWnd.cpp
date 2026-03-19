#include "stdafx.h"
#include "MainWnd.h"
#include "Loader.h"
#include "../_Shared/version.h"
#include "resource.h"
#include "../_Shared/UserUtil.h"
#include "../_Shared/MuUtil.h"


#include <CommDlg.h>
#include <shellapi.h>
#include <commctrl.h>


/**  
 * \brief 
 */
CMainWnd::CMainWnd(CProtocolSettings& settings)
	: m_iDlgResult(0), m_cSettings(settings)
{
	m_hBg = LoadBitmapA(ghInstance, MAKEINTRESOURCEA(IDB_BITMAP2));
}


/**  
 * \brief 
 */
CMainWnd::~CMainWnd()
{
	if (m_hBg)
		DeleteObject(m_hBg);
}


/**  
 * \brief 
 */
bool CMainWnd::Create()
{
	return (0 != CUserUtil::CreateDialogParamA(ghInstance, MAKEINTRESOURCEA(IDD_MAIN), 0, (DLGPROC)DlgProc, (LPARAM)this));
}



/**  
 * \brief 
 */
LRESULT CALLBACK CMainWnd::DlgProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	if (message == WM_INITDIALOG && lParam != 0)
	{
		((CMainWnd*)lParam)->m_hWnd = hWnd;
		SetPropA(hWnd, "1234", (HANDLE)lParam);

		Sleep(10);
	}

	CMainWnd* pThis = (CMainWnd*)GetPropA(hWnd, "1234");
	LRESULT ret = pThis ? pThis->HandleMessage(message, wParam, lParam) : 0;

	if (message == WM_NCDESTROY)
		RemovePropA(hWnd, "1234");

	return ret;
}


/**  
 * \brief 
 */
LRESULT CMainWnd::HandleMessage(UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_INITDIALOG:
		return HandleInit();
	case WM_DRAWITEM:
		return HandleDrawItem(wParam, lParam);
	case WM_ERASEBKGND:
		return HandleErase(wParam, lParam);
	case WM_CTLCOLORBTN:
		return (LRESULT)GetStockObject(NULL_BRUSH);
	case WM_COMMAND:
		return HandleCommand(wParam, lParam);
	case WM_DESTROY:
		return HandleDestroy();
	}

	return 0;
}


/**  
 * \brief 
 */
LRESULT CMainWnd::HandleInit()
{
	INITCOMMONCONTROLSEX iccex = {0};
	iccex.dwSize = sizeof(INITCOMMONCONTROLSEX);
	iccex.dwICC = 0xFFFF;
	InitCommonControlsEx(&iccex);

	SetDlgItemTextA(m_hWnd, IDC_EDIT1, m_cSettings.data.szMuPath);
	CheckRadioButton(m_hWnd, IDC_RADIO1, IDC_RADIO3, IDC_RADIO1 + m_cSettings.data.dwClientType);
	CheckRadioButton(m_hWnd, IDC_RADIO4, IDC_RADIO6, IDC_RADIO4 + m_cSettings.data.dwProtocolType - 1);

	SendDlgItemMessage(m_hWnd, IDC_DONATE, BM_SETIMAGE, (WPARAM)IMAGE_BITMAP, (LPARAM)LoadBitmap(ghInstance, MAKEINTRESOURCE(IDB_BITMAP1)));

	SetWindowText(m_hWnd, __SOFTWARE_VERSION_ABOUT);

	BITMAPINFO bmi = {0};
	GetObjectA(m_hBg, sizeof(bmi), &bmi);

	RECT rcWnd = {0};
	RECT rcClient = {0};
	GetWindowRect(m_hWnd, &rcWnd);
	GetClientRect(m_hWnd, &rcClient);

	int xOffs = bmi.bmiHeader.biWidth - (rcClient.right-rcClient.left);
	int yOffs = bmi.bmiHeader.biHeight - (rcClient.bottom-rcClient.top);

	rcWnd.bottom += yOffs;
	rcWnd.right += xOffs;

	int cy = rcWnd.bottom - rcWnd.top;
	int cx = rcWnd.right - rcWnd.left;
	int x0 = (GetSystemMetrics(SM_CXSCREEN) - cx)/2;
	int y0 = (GetSystemMetrics(SM_CYSCREEN) - cy)/2;

	MoveWindow(m_hWnd, x0, y0, cx, cy, TRUE);


	HWND hChild = GetWindow(m_hWnd, GW_CHILD);
	HBRUSH hBrush = CreateSolidBrush(RGB(0,0,0));
	HCURSOR hCursor = LoadCursor(0, IDC_HAND);

	for (hChild; hChild != 0; hChild = GetWindow(hChild, GW_HWNDNEXT))
	{
		RECT rc1 = {0};
		GetWindowRect(hChild, &rc1);
		ScreenToClient(m_hWnd, (LPPOINT)&rc1);
		ScreenToClient(m_hWnd, (LPPOINT)&rc1+1);

		MoveWindow(hChild, rc1.left + xOffs/2, rc1.top + yOffs, rc1.right - rc1.left, rc1.bottom - rc1.top, TRUE);
		SetClassLongPtr(hChild, GCL_HCURSOR, (LONG)hCursor);

		UINT uID = (UINT)GetWindowLongPtr(hChild, GWL_ID);

		if (uID >= IDC_RADIO1 && uID <= IDC_RADIO6)
			SetWindowLongPtr(hChild, GWL_USERDATA, SetWindowLongPtr(hChild, GWL_WNDPROC, (LONG)MyCtrlProc));
	}

	CreateWindowExA(0, "BUTTON", "", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_OWNERDRAW, 91, 411, 176, 20, m_hWnd, (HMENU)IDC_URL, ghInstance, 0);

	SetWindowTextA(m_hWnd, "MU AutoClicker (Elite) V" __SOFTWARE_VERSION_STR);
	ShowWindow(m_hWnd, SW_SHOW);
	return TRUE;
}



/**  
 * \brief 
 */
LRESULT CMainWnd::HandleCommand(WPARAM wParam, LPARAM lParam)
{
	WORD wmId    = LOWORD(wParam);
	WORD wmEvent = HIWORD(wParam);

	if (wmEvent != BN_CLICKED)
		return 0;

	switch (wmId)
	{
	case IDOK: 
	case IDCANCEL:
		GetDlgItemTextA(m_hWnd, IDC_EDIT1, m_cSettings.data.szMuPath, _MAX_PATH);

		EnableWindow(GetDlgItem(m_hWnd, wmId), FALSE);
		m_iDlgResult = (int)wmId;

		DestroyWindow(m_hWnd);
		break;
	case IDC_HELP2:
		{
			TCHAR pszFile[] = _T("file:///");
			TCHAR szFileName[_MAX_PATH+1+sizeof(pszFile)] = {0};
			_tcscpy_s(szFileName, _MAX_PATH, pszFile);
			GetModuleFileName(ghInstance, szFileName+sizeof(pszFile), _MAX_PATH);

			for (int i=(int)_tcslen(szFileName)-1; i >= 0 && szFileName[i] != _T('\\'); --i)
			{
				szFileName[i] = 0;
			}

			_tcscat_s(szFileName, _MAX_PATH, _T("help\\index.html"));

			ShellExecute(m_hWnd, _T("Open"), szFileName, _T(""), _T(""), SW_SHOWNORMAL);
		}
		break;
	case IDC_RADIO1: case IDC_RADIO2: case IDC_RADIO3:
		m_cSettings.data.dwClientType = (DWORD)(wmId - 1000);
		break;
	case IDC_RADIO4: case IDC_RADIO5: case IDC_RADIO6:
		m_cSettings.data.dwProtocolType = (DWORD)(wmId - 1002);
		break;
	case IDC_BROWSE:
		{
			OPENFILENAMEA of = {0};
			of.lStructSize = sizeof(OPENFILENAMEA);
			of.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_LONGNAMES | OFN_NODEREFERENCELINKS;
			of.hInstance = ghInstance;
			of.lpstrFile = m_cSettings.data.szMuPath;
			of.nMaxFile = _MAX_PATH;
			of.lpstrTitle = "Path to MU Launcher or Main.exe";
			of.lpstrFilter = "Executable Files (*.exe)\0*.exe\0";
			of.hwndOwner = m_hWnd;

			GetOpenFileNameA(&of);
			SetDlgItemTextA(m_hWnd, IDC_EDIT1, m_cSettings.data.szMuPath);
		}
		break;
	case IDC_DONATE:
		break;
	case IDC_URL:
		break;
	}

	return 0;
}



/**  
 * \brief 
 */
LRESULT CMainWnd::HandleDrawItem(WPARAM wParam, LPARAM lParam)
{
	if (wParam == IDC_DONATE)
	{
		LPDRAWITEMSTRUCT lpDrawItem = (LPDRAWITEMSTRUCT)lParam;

		HDC hDC = lpDrawItem->hDC;
		HDC hMemDC = CreateCompatibleDC(hDC);	
		HBITMAP hBmp = (HBITMAP)SendDlgItemMessage(m_hWnd, IDC_DONATE, BM_GETIMAGE, IMAGE_BITMAP, 0);
		HGDIOBJ hOldBmp = SelectObject(hMemDC, hBmp);

		BITMAPINFO bmi = {0};
		GetObjectA(hBmp, sizeof(bmi), &bmi);

		BitBlt(hDC, lpDrawItem->rcItem.left + (lpDrawItem->rcItem.right - lpDrawItem->rcItem.left - bmi.bmiHeader.biWidth)/2, 
			lpDrawItem->rcItem.top + (lpDrawItem->rcItem.bottom - lpDrawItem->rcItem.top - bmi.bmiHeader.biHeight)/2,  
			bmi.bmiHeader.biWidth, bmi.bmiHeader.biHeight, hMemDC, 0, 0, SRCCOPY);

		SelectObject(hMemDC, hOldBmp);
		DeleteDC(hMemDC);
	}

	return 0;
}



/**  
 * \brief 
 */
LRESULT CMainWnd::HandleErase(WPARAM wParam, LPARAM)
{
	HDC hDC = (HDC)wParam;
	HDC hMemDC = CreateCompatibleDC(hDC);			
	HGDIOBJ hOldBmp = SelectObject(hMemDC, m_hBg);

	RECT rc = {0};
	GetClientRect(m_hWnd, &rc);

	int cx = rc.right - rc.left + 1;
	int cy = rc.bottom - rc.top + 1;

	BitBlt(hDC, 0, 0, cx, cy, hMemDC, 0, 0, SRCCOPY);

	SelectObject(hMemDC, hOldBmp);
	DeleteDC(hMemDC);

	return TRUE;
}



/**  
 * \brief 
 */
LRESULT CMainWnd::HandleDestroy()
{	
	PostQuitMessage(0);
	return 0;
}


/**  
 * \brief 
 */
LRESULT CALLBACK CMainWnd::MyCtrlProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	WNDPROC oldWndProc = (WNDPROC)GetWindowLongPtr(hWnd, GWL_USERDATA);

	if (message == WM_PAINT)
	{
		RECT rc = {0};
		GetClientRect(hWnd, &rc);

		PAINTSTRUCT ps = {0};
		BeginPaint(hWnd, &ps);

		HDC hDC = ps.hdc;
		InflateRect(&rc, -2, -2);
		rc.left -= 2;
		rc.right = rc.left + rc.bottom - rc.top;

		UINT uChecked = 0;

		if (BST_CHECKED == IsDlgButtonChecked(GetParent(hWnd), (UINT)GetWindowLongPtr(hWnd, GWL_ID)))
			uChecked = DFCS_CHECKED;

		DrawFrameControl(hDC, &rc, DFC_BUTTON, DFCS_BUTTONRADIO | uChecked | DFCS_TRANSPARENT);

		EndPaint(hWnd, &ps);
		return 0;
	}

	return oldWndProc ? CallWindowProc(oldWndProc, hWnd, message, wParam, lParam) : 0;
}

