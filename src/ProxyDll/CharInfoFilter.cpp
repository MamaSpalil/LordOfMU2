#include "stdafx.h"
#include "CharInfoFilter.h"
#include "CommonPackets.h"
#include "version.h"
#include "LordOfMUdll.h"
#include "DebugOut.h"



/**
 * \brief 
 */
CCharInfoFilter::CCharInfoFilter(CProxy* pProxy)
	: CPacketFilter(pProxy)
{
	m_fShowSkill = false;

	m_wPlayerId = 0;
	m_wLevel = 0;
	m_bX = 0;
	m_bY = 0;
	m_fExit400 = false;
	m_fSuspended = false;
	m_fStealth = true;
	m_fMeetPlayerMessage = true;
	m_fLockAg = false;

	m_wAgility = 0;
	m_wFixLevel = 0;
	m_wStrength = 0;
	m_wEnergy = 0;
	m_wVitality = 0;

	m_wMaxAG = 100;
	memset(m_szCharName, 0, 16);

	LoadPartners();
}


/**
 * \brief 
 */
CCharInfoFilter::~CCharInfoFilter()
{
}


/**
 * \brief 
 */
int CCharInfoFilter::FilterRecvPacket(CPacket& pkt, CFilterContext& context)
{
	if (pkt == CGameServerHelloPacket::Type())
	{
		CGameServerHelloPacket& pktHelo = (CGameServerHelloPacket&)pkt;
		m_wPlayerId = pktHelo.GetPlayerId();

		CServerMessagePacket pkt2(">> %s ", (LPCSTR)CT2A(__SOFTWARE_VERSION_ABOUT));
		CServerMessagePacket pkt3(">> %s ", __SOFTWARE_COPYRIGHT);

		GetProxy()->recv_direct(pkt2);
		GetProxy()->recv_direct(pkt3);
	}
	else if (pkt == CCharListReplyPacket::Type())
	{
		CCharListReplyPacket& pkt2 = (CCharListReplyPacket&)pkt;

		int iCount = pkt2.GetCharCount();

		for (int i=0; i < iCount; i++)
		{
			CStringA strName = pkt2.GetCharName(i);
			WORD wLevel = pkt2.GetCharLevel(i);

			if (strName.GetLength() > 0)
			{
				m_vCharList.insert(std::pair<CStringA,WORD>(strName, wLevel));

				if (m_wFixLevel != 0)
					pkt2.SetCharLevel(i, m_wFixLevel);
			}
		}
	}
	else if (pkt == CCharCreateReplyPacket::Type())
	{
		CCharCreateReplyPacket& pkt2 = (CCharCreateReplyPacket&)pkt;
		CStringA strName = pkt2.GetCharName();

		if (strName.GetLength() > 0)
			m_vCharList.insert(std::pair<CStringA,WORD>(strName, 1));
	}
	else if (pkt == CCharStatsPacket::Type())
	{
		DWORD ver[] = {__SOFTWARE_VERSION};

		CStringA strMsg;
		strMsg.Format(" - MU AutoClicker V%d.%04d - ", ver[0], ver[1]);

		CGMMessagePacket pkt2(strMsg);
		CGMMessagePacket pkt3(" - " __SOFTWARE_COPYRIGHT " - ");

		GetProxy()->recv_direct(pkt2);
		GetProxy()->recv_direct(pkt3);

		CCharStatsPacket& pktStats = (CCharStatsPacket&)pkt;

		if (m_wAgility != 0)
			pktStats.SetAgility(m_wAgility);

		if (m_wStrength != 0)
			pktStats.SetStrength(m_wStrength);

		if (m_wVitality != 0)
			pktStats.SetVitality(m_wVitality);

		if (m_wEnergy != 0)
			pktStats.SetEnergy(m_wEnergy);
	}
	else if (pkt == CObjectMovedPacket::Type())
	{
		CObjectMovedPacket& pktMove = (CObjectMovedPacket&)pkt;

		if (pktMove.GetId() == m_wPlayerId)
		{
			m_bX = pktMove.GetX();
			m_bY = pktMove.GetY();
		}
	}
	else if (pkt == CWarpReplyPacket::Type())
	{
		CWarpReplyPacket& pkt2 = (CWarpReplyPacket&)pkt;

		m_bX = pkt2.GetX();
		m_bY = pkt2.GetY();

		m_vPlayers.clear();
		UpdateSuspendedFlag();

		GetProxy()->send_packet(CCharacterSayPacket(m_szCharName, "--afk off"));
	}
	else if (pkt == CCharRespawnPacket::Type())
	{
		CCharRespawnPacket& pkt2 = (CCharRespawnPacket&)pkt;

		BYTE xx = pkt2.GetX();
		BYTE yy = pkt2.GetY();

		if (abs((int)xx-m_bX) > 2 || abs((int)yy-m_bY) > 2)
		{
			GetProxy()->send_packet(CCharacterSayPacket(m_szCharName, "--afk off"));
		}

		m_bX = xx;
		m_bY = yy;

		m_vPlayers.clear();
		UpdateSuspendedFlag();
	}
	else if (pkt == CCharStatsPacket::Type())
	{
		CCharStatsPacket& pkt2 = (CCharStatsPacket&)pkt;

		m_bX = pkt2.GetX();
		m_bY = pkt2.GetY();
	}
	else if (pkt == CUpdatePosSTCPacket::Type())
	{
		CUpdatePosSTCPacket& pkt2 = (CUpdatePosSTCPacket&)pkt;

		if (pkt2.GetId() == m_wPlayerId)
		{
			m_bX = pkt2.GetX();
			m_bY = pkt2.GetY();
		}
	}
	else if (pkt == CLevelUpPacket::Type())
	{
		CLevelUpPacket& pkt2 = (CLevelUpPacket&)pkt;

		if (m_fExit400 && pkt2.GetLevel() >= 400)
		{
			if (CProxyClickerModule::GetInstance()->m_pLoader)
			{
				HWND hWnd = 0;
				CProxyClickerModule::GetInstance()->m_pLoader->SendCommand(_MODULE_LOADER_COMMAND_GET_MUWND, _MODULE_LOADER_TARGET_SELF, (void*)&hWnd, 0);

				if (hWnd)
					PostMessage(hWnd, WM_CLOSE, 0, 0);
			}
		}
	}
	else if (pkt == CSetMaxManaAGPacket::Type())
	{
		CSetMaxManaAGPacket& pkt2 = (CSetMaxManaAGPacket&)pkt;
		m_wMaxAG = pkt2.GetAG();
	}
	else if (pkt == CUpdateManaAGPacket::Type())
	{
		if (m_fLockAg)
		{
			CUpdateManaAGPacket& pkt2 = (CUpdateManaAGPacket&)pkt;
			pkt2.SetAG(m_wMaxAG);
		}
	}
	else 
	{
		if (pkt == CMeetPlayerPacket::Type())
		{
			CMeetPlayerPacket& pkt2 = (CMeetPlayerPacket&)pkt;

			for (int i=0; i < pkt2.GetPlayerCount(); i++)
			{
				CStringA strPlayerName = pkt2.GetPlayerName(i);
				WORD wPlayerId = pkt2.GetPlayerId(i);

				if (m_fMeetPlayerMessage)
				{
					CServerMessagePacket pktMsg(">> meet player %s", strPlayerName);
					GetProxy()->recv_direct(pktMsg);
				}

				if (strPlayerName.GetLength() > 0)
				{
					std::map<CStringA,WORD>::iterator it = m_vPartners.find(strPlayerName);

					if (it == m_vPartners.end())
					{
						m_vPlayers.insert(std::pair<WORD,CStringA>(wPlayerId, strPlayerName));
					}
					else
					{
						it->second = wPlayerId;
					}
				}
			}

			UpdateSuspendedFlag();
		}
		else if (pkt == CMeetDisguisedPlayerPacket::Type())
		{
			CMeetDisguisedPlayerPacket& pkt2 = (CMeetDisguisedPlayerPacket&)pkt;

			for (int i=0; i < pkt2.GetPlayerCount(); i++)
			{
				CStringA strPlayerName = pkt2.GetPlayerName(i);
				WORD wPlayerId = pkt2.GetPlayerId(i);


				if (m_fMeetPlayerMessage)
				{
					CServerMessagePacket pktMsg(">> meet player %s", strPlayerName);
					GetProxy()->recv_direct(pktMsg);
				}

				if (strPlayerName.GetLength() > 0)
				{
					std::map<CStringA,WORD>::iterator it = m_vPartners.find(strPlayerName);

					if (it == m_vPartners.end())
					{
						m_vPlayers.insert(std::pair<WORD,CStringA>(wPlayerId, strPlayerName));
					}
					else
					{
						it->second = wPlayerId;
					}
				}
			}

			UpdateSuspendedFlag();
		}
		else if (pkt == CForgetObjectPacket::Type())
		{
			CForgetObjectPacket& pkt2 = (CForgetObjectPacket)pkt;

			for (int i=0; i < pkt2.GetObjectCount(); i++)
				m_vPlayers.erase(pkt2.GetObjectId(i));

			UpdateSuspendedFlag();
		}
		else if (pkt == CObjectDeathPacket::Type())
		{
			CObjectDeathPacket& pkt2 = (CObjectDeathPacket&)pkt;
			m_vPlayers.erase(pkt2.GetObjectId());

			UpdateSuspendedFlag();
		}
	}

	return 0;
}


/**
 * \brief 
 */
int CCharInfoFilter::FilterSendPacket(CPacket& pkt, CFilterContext& context)
{
	if (pkt == CCharSelectedPacket::Type())
	{
		CCharSelectedPacket pktSel(pkt);

		m_wLevel = 1;
		memset(m_szCharName, 0, 16);


		std::map<CStringA, WORD>::iterator it = m_vCharList.find(pktSel.GetCharName());

		if (it != m_vCharList.end())
		{
			strncpy(m_szCharName, it->first, 10);
			m_wLevel = it->second;
		}

		if (m_szCharName[0] != 0)
			m_vPartners.insert(std::pair<CStringA,WORD>(pktSel.GetCharName(), m_wPlayerId));

		m_vPlayers.clear();
		UpdateSuspendedFlag();
	}	
	else if (pkt == CSingleSkillPacket::Type())
	{
		if (m_fShowSkill)
		{
			CSingleSkillPacket& pkt2 = (CSingleSkillPacket&)pkt;
			GetProxy()->recv_direct(CServerMessagePacket(">> attack skill id: %02X%04X", 0x19, pkt2.GetSkill()));
		}
	}
	else if (pkt == CMassiveSkillPacket::Type())
	{
		if (m_fShowSkill)
		{
			CMassiveSkillPacket& pkt2 = (CMassiveSkillPacket&)pkt;
			GetProxy()->recv_direct(CServerMessagePacket(">> attack skill id: %02X%04X", 0x1E, pkt2.GetSkill()));
		}
	}
	else if (pkt == CUpdatePosCTSPacket::Type())
	{
		CUpdatePosCTSPacket& pkt2 = (CUpdatePosCTSPacket&)pkt;

		m_bX = pkt2.GetX();
		m_bY = pkt2.GetY();
	}

	return 0;
}


/**
 * \brief 
 */
bool CCharInfoFilter::GetParam(const char* pszParam, void* pData)
{
	if (!pData || !pszParam)
		return false;

	if (_stricmp(pszParam, "X") == 0)
	{
		*((BYTE*)pData) = m_bX;
		return true;
	}
	
	if (_stricmp(pszParam, "Y") == 0)
	{
		*((BYTE*)pData) = m_bY;
		return true;
	}
	
	if (_stricmp(pszParam, "PlayerId") == 0)
	{
		*((WORD*)pData) = m_wPlayerId;
		return true;
	}

	if (_stricmp(pszParam, "Level") == 0)
	{
		*((WORD*)pData) = m_wLevel;
		return true;
	}

	if (_stricmp(pszParam, "CharName") == 0)
	{
		*((char**)pData) = m_szCharName;
		return true;
	}

	if (_stricmp(pszParam, "Players") == 0)
	{
		*((void**)pData) = (void*)&m_vPlayers;
		return true;
	}

	if (_stricmp(pszParam, "meetpl") == 0)
	{
		*((bool*)pData) = m_fMeetPlayerMessage;
		return true;		
	}

	return false;
}


/**
 * \brief 
 */
bool CCharInfoFilter::SetParam(const char* pszParam, void* pData)
{
	if (!pszParam)
		return false;

	if (pData)
	{
		if (_stricmp(pszParam, "exit400") == 0)
		{
			m_fExit400 = *((BOOL*)pData) != 0;
			return true;
		}
		else if (_stricmp(pszParam, "stealth") == 0)
		{
			bool fNewState = *((bool*)pData);

			if (fNewState != m_fStealth)
			{
				m_fStealth = fNewState;
				UpdateSuspendedFlag();
			}

			return true;
		}		
		else if (_stricmp(pszParam, "showskill") == 0)
		{
			m_fShowSkill = *((bool*)pData);
		}
		else if (_stricmp(pszParam, "lockag") == 0)
		{
			m_fLockAg = *((bool*)pData);
		}
		else if (_stricmp(pszParam, "meetpl") == 0)
		{
			m_fMeetPlayerMessage = *((bool*)pData);
			return true;
		}
		else if (_stricmp(pszParam, "fixagi") == 0)
		{
			m_wAgility = *((WORD*)pData);
			return true;
		}
		else if (_stricmp(pszParam, "fixlvl") == 0)
		{
			m_wFixLevel = *((WORD*)pData);
			return true;
		}
		else if (_stricmp(pszParam, "fixstr") == 0)
		{
			m_wStrength = *((WORD*)pData);
			return true;
		}
		else if (_stricmp(pszParam, "fixvit") == 0)
		{
			m_wVitality = *((WORD*)pData);
			return true;
		}
		else if (_stricmp(pszParam, "fixene") == 0)
		{
			m_wEnergy = *((WORD*)pData);
			return true;
		}
	}
	else 
	{
		if (_stricmp(pszParam, "listpl") == 0)
		{
			ListPlayers();
			return true;
		}
		else if (_stricmp(pszParam, "listpt") == 0)
		{
			ListPartners();
			return true;
		}
		else if (_stricmp(pszParam, "listch") == 0)
		{
			ListChars();
			return true;
		}
	}

	return false;
}


/**
 * \brief 
 */
void CCharInfoFilter::UpdateSuspendedFlag()
{
	bool fNewSuspended = (m_vPlayers.size() != 0) && m_fStealth;

	if (m_fSuspended != fNewSuspended)
	{
		m_fSuspended = fNewSuspended;

		const char* filters[] = 
		{
			"AutoPickupFilter",
			"MultihitFilter",
			"AutoKillFilter",
			"FastMoveFilter",
			"ScriptProcessorFilter",
		};

		for (int i=0; i < sizeof(filters)/sizeof(filters[0]); i++)
		{
			CPacketFilter* pFilter = GetProxy()->GetFilter(filters[i]);

			if (pFilter)
				pFilter->SetParam("suspended", &m_fSuspended);
		}
	}
}


/**
 * \brief 
 */
bool CCharInfoFilter::IsPartner(const CStringA& strName)
{
	return m_vPartners.find(strName) != m_vPartners.end();
}


/**
 * \brief 
 */
void CCharInfoFilter::LoadPartners()
{
	char szPath[_MAX_PATH+1] = {0};
	extern TCHAR g_szRoot[_MAX_PATH + 1];

	strcpy(szPath, CT2A(g_szRoot));
	strcat(szPath, "partners.txt");

	m_vPartners.clear();

	FILE* f = fopen(szPath, "r");

	if (!f)
		return;

	char szLine[256] = {0};
	char ch = 0;
	int pos = 0;

	while(1)
	{
		bool fStop = (1 != fread(&ch, 1, 1, f));

		if (fStop || ch == '\n' || pos >= 256)
		{
			if (szLine[0] != 0)
			{
				m_vPartners.insert(std::pair<CStringA,WORD>(CStringA(szLine),0));
			}

			pos = 0;
			memset(szLine, 0, 256);
		}
		else
		{
			szLine[pos++] = ch;
		}

		if (fStop)
			break;
	}

	fclose(f);
}


/**  
 * \brief 
 */
void CCharInfoFilter::ListPlayers()
{
	GetProxy()->recv_direct(CServerMessagePacket("  [player list]"));

	for (std::map<WORD,CStringA>::iterator it = m_vPlayers.begin(); it != m_vPlayers.end(); ++it)
	{
		GetProxy()->recv_direct(CServerMessagePacket("  %-10s (%04X)", it->second, it->first));
	}
}

/**  
 * \brief 
 */
void CCharInfoFilter::ListPartners()
{
	GetProxy()->recv_direct(CServerMessagePacket("  [partner list]"));
	
	for (std::map<CStringA,WORD>::iterator it = m_vPartners.begin(); it != m_vPartners.end(); ++it)
	{
		GetProxy()->recv_packet(CServerMessagePacket("  %-10s (%04X)", it->first, it->second));
	}
}


/**  
 * \brief 
 */
void CCharInfoFilter::ListChars()
{
	GetProxy()->recv_direct(CServerMessagePacket("  [character list]"));

	for (std::map<CStringA,WORD>::iterator it = m_vCharList.begin(); it != m_vCharList.end(); ++it)
	{
		GetProxy()->recv_packet(CServerMessagePacket("  %-10s (%d)", it->first, it->second));
	}	
}

