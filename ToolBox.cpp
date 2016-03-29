//////////////////////////////////////////
// ToolBox - Useful Code                //
// David Anson (DavidAns@Microsoft.com) //
//////////////////////////////////////////


#include <stdio.h>
#include "ToolBox.h"

// Safe string-copying, string-concatenation, and string-formatting implementations
char* strncpyz(char* const psDestination, const char* const psSource, const unsigned int uiDestinationLength)
	{
	if(0 < uiDestinationLength)
		{
		const size_t stSourceSength = strlen(psSource);
		strncpy(psDestination, psSource, min(stSourceSength+1, uiDestinationLength-1));
		psDestination[uiDestinationLength-1] = '\0';
		}
	return psDestination;
	}

// AnsiString implementation
AnsiString::AnsiString(const wchar_t* const psWide, const wchar_t pcStringTerminator)
	{
	m_psAnsi = 0;
	if(0 != psWide)
		{
		size_t stWideLength = 0;
		if(L'\0' == pcStringTerminator)
			{
			stWideLength = wcslen(psWide)+1;
			}
		else
			{
			const wchar_t* pcEndOfString = wcschr(psWide, pcStringTerminator);
			if(0 == pcEndOfString)
				{
				stWideLength = wcslen(psWide)+1;
				}
			else
				{
				stWideLength = pcEndOfString-psWide+1;
				}
			}
		if(0 != stWideLength)
			{
			int iAnsiLength = WideCharToMultiByte(CP_ACP, 0, psWide, stWideLength, 0, 0, 0, 0);
			if(0 < iAnsiLength)
				{
				m_psAnsi = (char*)LocalAlloc(0, iAnsiLength*sizeof(*m_psAnsi));
				if(0 != m_psAnsi)
					{
					int iReturnValue = WideCharToMultiByte(CP_ACP, 0, psWide, stWideLength, m_psAnsi, iAnsiLength, 0, 0);
					if(0 == iReturnValue)
						{
						LocalFree(m_psAnsi);
						m_psAnsi = 0;
						}
					else
						{
						m_psAnsi[iAnsiLength-1] = '\0';
						}
					}
				}
			}
		}
	}
AnsiString::AnsiString(const char* const psAnsi, const char pcStringTerminator)
	{
	m_psAnsi = 0;
	if(0 != psAnsi)
		{
		size_t stAnsiLength = 0;
		if('\0' == pcStringTerminator)
			{
			stAnsiLength = strlen(psAnsi)+1;
			}
		else
			{
			const char* pcEndOfString = strchr(psAnsi, pcStringTerminator);
			if(0 == pcEndOfString)
				{
				stAnsiLength = strlen(psAnsi)+1;
				}
			else
				{
				stAnsiLength = pcEndOfString-psAnsi+1;
				}
			}
		if(0 != stAnsiLength)
			{
			m_psAnsi = (char*)LocalAlloc(0, stAnsiLength*sizeof(*m_psAnsi));
			if(0 != m_psAnsi)
				{
				strncpy(m_psAnsi, psAnsi, stAnsiLength);
				m_psAnsi[stAnsiLength-1] = '\0';
				}
			}
		}
	}
AnsiString::~AnsiString()
	{
	if(0 != m_psAnsi)
		{
		LocalFree(m_psAnsi);
		}
	}
