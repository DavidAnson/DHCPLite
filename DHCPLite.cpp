#include <windows.h>
#include <iphlpapi.h>
#include <iprtrmib.h>
#include <stdio.h>
#include <vector>
#include "toolbox.h"

const TCHAR ptsCRLF[] = TEXT("\r\n");
const TCHAR ptsERRORPrefix[] = TEXT("ERROR %d: ");
#define OUTPUT(x) printf x; printf(ptsCRLF)
#define OUTPUT_ERROR(x) printf(ptsERRORPrefix, __LINE__); printf x; printf(ptsCRLF);
#define OUTPUT_WARNING(x) ASSERT(!x)
#define DWIP0(dw) (((dw)>> 0) & 0xff)
#define DWIP1(dw) (((dw)>> 8) & 0xff)
#define DWIP2(dw) (((dw)>>16) & 0xff)
#define DWIP3(dw) (((dw)>>24) & 0xff)
#define DWIPtoValue(dw) ((DWIP0(dw)<<24) | (DWIP1(dw)<<16) | (DWIP2(dw)<<8) | DWIP3(dw))
#define DWValuetoIP(dw) ((DWIP0(dw)<<24) | (DWIP1(dw)<<16) | (DWIP2(dw)<<8) | DWIP3(dw))

const char pcsServerName[] = "DHCPLite DHCP server";

// Maximum size of a UDP datagram (see RFC 768)
#define MAX_UDP_MESSAGE_SIZE ((65536)-8)
// DHCP constants (see RFC 2131 section 4.1)
#define DHCP_SERVER_PORT (67)
#define DHCP_CLIENT_PORT (68)
// Broadcast bit for flags field (RFC 2131 section 2)
#define BROADCAST_FLAG (0x80)
// For display of host name information
#define MAX_HOSTNAME_LENGTH (256)
// RFC 2131 section 2
enum op_values
{
	op_BOOTREQUEST = 1,
	op_BOOTREPLY = 2,
};
// RFC 2132 section 9.6
enum option_values
{
	option_PAD = 0,
	option_SUBNETMASK = 1,
	option_HOSTNAME = 12,
	option_REQUESTEDIPADDRESS = 50,
	option_IPADDRESSLEASETIME = 51,
	option_DHCPMESSAGETYPE = 53,
	option_SERVERIDENTIFIER = 54,
	option_CLIENTIDENTIFIER = 61,
	option_END = 255,
};
enum DHCPMessageTypes
{
	DHCPMessageType_DISCOVER = 1,
	DHCPMessageType_OFFER = 2,
	DHCPMessageType_REQUEST = 3,
	DHCPMessageType_DECLINE = 4,
	DHCPMessageType_ACK = 5,
	DHCPMessageType_NAK = 6,
	DHCPMessageType_RELEASE = 7,
	DHCPMessageType_INFORM = 8,
};

// DHCP magic cookie values
const BYTE pbDHCPMagicCookie[] = { 99, 130, 83, 99 };

struct AddressInUseInformation
{
	DWORD dwAddrValue;
	BYTE* pbClientIdentifier;
	DWORD dwClientIdentifierSize;
	// SYSTEMTIME stExpireTime;  // If lease timeouts are needed
};
typedef std::vector<AddressInUseInformation> VectorAddressInUseInformation;

typedef bool(*FindIndexOfFilter)(const AddressInUseInformation& raiui, const void* const pvFilterData);
int FindIndexOf(const VectorAddressInUseInformation* const pvAddressesInUse, const FindIndexOfFilter pFilter, const void* const pvFilterData)
{
	ASSERT((0 != pvAddressesInUse) && (0 != pFilter) && (0 != pvFilterData));
	for (size_t i = 0; i < pvAddressesInUse->size(); i++)
	{
		if (pFilter(pvAddressesInUse->at(i), pvFilterData))
		{
			return (int)i;
		}
	}
	return -1;
}
bool PushBack(VectorAddressInUseInformation* const pvAddressesInUse, const AddressInUseInformation* const paiui)
{
	ASSERT((0 != pvAddressesInUse) && (0 != paiui));
	try
	{
		pvAddressesInUse->push_back(*paiui);
	}
	catch (const std::bad_alloc)
	{
		return false;
	}
	return true;
}

// RFC 2131 section 2
#pragma warning(push)
#pragma warning(disable : 4200)
#pragma pack(push, 1)
struct DHCPMessage
{
	BYTE op;
	BYTE htype;
	BYTE hlen;
	BYTE hops;
	DWORD xid;
	WORD secs;
	WORD flags;
	DWORD ciaddr;
	DWORD yiaddr;
	DWORD siaddr;
	DWORD giaddr;
	BYTE chaddr[16];
	BYTE sname[64];
	BYTE file[128];
	BYTE options[];
};
struct DHCPServerOptions
{
	BYTE pbMagicCookie[4];
	BYTE pbMessageType[3];
	BYTE pbLeaseTime[6];
	BYTE pbSubnetMask[6];
	BYTE pbServerID[6];
	BYTE bEND;
};
#pragma pack(pop)
#pragma warning(pop)

bool GetIPAddressInformation(DWORD* const pdwAddr, DWORD* const pdwMask, DWORD* const pdwMinAddr, DWORD* const pdwMaxAddr)
{
	ASSERT((0 != pdwAddr) && (0 != pdwMask) && (0 != pdwMinAddr) && (0 != pdwMaxAddr));
	bool bSuccess = false;
	MIB_IPADDRTABLE miatIpAddrTable;
	ULONG ulIpAddrTableSize = sizeof(miatIpAddrTable);
	DWORD dwGetIpAddrTableResult = GetIpAddrTable(&miatIpAddrTable, &ulIpAddrTableSize, FALSE);
	if ((NO_ERROR == dwGetIpAddrTableResult) || (ERROR_INSUFFICIENT_BUFFER == dwGetIpAddrTableResult))  // Technically, if NO_ERROR was returned, we don't need to allocate a buffer - but it's easier to do so anyway - and because we need more data than fits in the default buffer, this would only be wasteful in the error case
	{
		const ULONG ulIpAddrTableSizeAllocated = ulIpAddrTableSize;
		BYTE* const pbIpAddrTableBuffer = (BYTE*)LocalAlloc(LMEM_FIXED, ulIpAddrTableSizeAllocated);
		if (0 != pbIpAddrTableBuffer)
		{
			dwGetIpAddrTableResult = GetIpAddrTable((MIB_IPADDRTABLE*)pbIpAddrTableBuffer, &ulIpAddrTableSize, FALSE);
			if ((NO_ERROR == dwGetIpAddrTableResult) && (ulIpAddrTableSizeAllocated <= ulIpAddrTableSize))
			{
				const MIB_IPADDRTABLE* const pmiatIpAddrTable = (MIB_IPADDRTABLE*)pbIpAddrTableBuffer;
				if (2 == pmiatIpAddrTable->dwNumEntries)
				{
					const bool loopbackAtIndex0 = DWValuetoIP(0x7f000001) == pmiatIpAddrTable->table[0].dwAddr;
					const bool loopbackAtIndex1 = DWValuetoIP(0x7f000001) == pmiatIpAddrTable->table[1].dwAddr;
					if (loopbackAtIndex0 ^ loopbackAtIndex1)
					{
						const int tableIndex = loopbackAtIndex1 ? 0 : 1;
						OUTPUT((TEXT("IP Address being used:")));
						const DWORD dwAddr = pmiatIpAddrTable->table[tableIndex].dwAddr;
						if (0 != dwAddr)
						{
							const DWORD dwMask = pmiatIpAddrTable->table[tableIndex].dwMask;
							const DWORD dwAddrValue = DWIPtoValue(dwAddr);
							const DWORD dwMaskValue = DWIPtoValue(dwMask);
							const DWORD dwMinAddrValue = ((dwAddrValue&dwMaskValue) | 2);  // Skip x.x.x.1 (default router address)
							const DWORD dwMaxAddrValue = ((dwAddrValue&dwMaskValue) | (~(dwMaskValue | 1)));
							const DWORD dwMinAddr = DWValuetoIP(dwMinAddrValue);
							const DWORD dwMaxAddr = DWValuetoIP(dwMaxAddrValue);
							OUTPUT((TEXT("%d.%d.%d.%d - Subnet:%d.%d.%d.%d - Range:[%d.%d.%d.%d-%d.%d.%d.%d]"),
								DWIP0(dwAddr), DWIP1(dwAddr), DWIP2(dwAddr), DWIP3(dwAddr),
								DWIP0(dwMask), DWIP1(dwMask), DWIP2(dwMask), DWIP3(dwMask),
								DWIP0(dwMinAddr), DWIP1(dwMinAddr), DWIP2(dwMinAddr), DWIP3(dwMinAddr),
								DWIP0(dwMaxAddr), DWIP1(dwMaxAddr), DWIP2(dwMaxAddr), DWIP3(dwMaxAddr)));
							if (dwMinAddrValue <= dwMaxAddrValue)
							{
								*pdwAddr = dwAddr;
								*pdwMask = dwMask;
								*pdwMinAddr = dwMinAddr;
								*pdwMaxAddr = dwMaxAddr;
								bSuccess = true;
							}
							else
							{
								OUTPUT_ERROR((TEXT("Not enough IP addresses available in the current subnet.")));
							}
						}
						else
						{
							OUTPUT_ERROR((TEXT("IP Address is 0.0.0.0 - no network is available on this machine.")));
							OUTPUT_ERROR((TEXT("[APIPA (Auto-IP) may not have assigned an IP address yet.]")));
						}
					}
					else
					{
						OUTPUT_ERROR((TEXT("Unsupported IP address configuration.")));
						OUTPUT_ERROR((TEXT("[Expected to find loopback address and one other.]")));
					}
				}
				else
				{
					OUTPUT_ERROR((TEXT("Too many or too few IP addresses are present on this machine.")));
					OUTPUT_ERROR((TEXT("[Routing can not be bypassed.]")));
				}
			}
			else
			{
				OUTPUT_ERROR((TEXT("Unable to query IP address table.")));
			}
			VERIFY(0 == LocalFree(pbIpAddrTableBuffer));
		}
		else
		{
			OUTPUT_ERROR((TEXT("Insufficient memory for IP address table.")));
		}
	}
	else
	{
		OUTPUT_ERROR((TEXT("Unable to query IP address table.")));
	}
	return bSuccess;
}

bool InitializeDHCPServer(SOCKET* const psServerSocket, const DWORD dwServerAddr, char* const pcsServerHostName, const size_t stServerHostNameLength)
{
	ASSERT((0 != psServerSocket) && (0 != dwServerAddr) && (0 != pcsServerHostName) && (1 <= stServerHostNameLength));
	bool bSuccess = false;
	// Determine server hostname
	if (0 != gethostname(pcsServerHostName, (int)stServerHostNameLength))
	{
		pcsServerHostName[0] = '\0';
	}
	// Open socket and set broadcast option on it
	*psServerSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (INVALID_SOCKET != *psServerSocket)
	{
		SOCKADDR_IN saServerAddress;
		saServerAddress.sin_family = AF_INET;
		saServerAddress.sin_addr.s_addr = dwServerAddr;  // Already in network byte order
		saServerAddress.sin_port = htons((u_short)DHCP_SERVER_PORT);
		const int iServerAddressSize = sizeof(saServerAddress);
		if (SOCKET_ERROR != bind(*psServerSocket, (SOCKADDR*)(&saServerAddress), iServerAddressSize))
		{
			int iBroadcastOption = TRUE;
			if (0 == setsockopt(*psServerSocket, SOL_SOCKET, SO_BROADCAST, (char*)(&iBroadcastOption), sizeof(iBroadcastOption)))
			{
				bSuccess = true;
			}
			else
			{
				OUTPUT_ERROR((TEXT("Unable to set socket options.")));
			}
		}
		else
		{
			OUTPUT_ERROR((TEXT("Unable to bind to server socket (port %d)."), DHCP_SERVER_PORT));
		}
	}
	else
	{
		OUTPUT_ERROR((TEXT("Unable to open server socket (port %d)."), DHCP_SERVER_PORT));
	}
	return bSuccess;
}

bool FindOptionData(const BYTE bOption, const BYTE* const pbOptions, const int iOptionsSize, const BYTE** const ppbOptionData, unsigned int* const piOptionDataSize)
{
	ASSERT(((0 == iOptionsSize) || (0 != pbOptions)) && (0 != ppbOptionData) && (0 != piOptionDataSize) &&
		(option_PAD != bOption) && (option_END != bOption));
	bool bSuccess = false;
	// RFC 2132
	bool bHitEND = false;
	const BYTE* pbCurrentOption = pbOptions;
	while (((pbCurrentOption - pbOptions) < iOptionsSize) && !bHitEND && !bSuccess)
	{
		const BYTE bCurrentOption = *pbCurrentOption;
		if (option_PAD == bCurrentOption)
		{
			pbCurrentOption++;
		}
		else if (option_END == bCurrentOption)
		{
			bHitEND = true;
		}
		else
		{
			pbCurrentOption++;
			if ((pbCurrentOption - pbOptions) < iOptionsSize)
			{
				const BYTE bCurrentOptionLen = *pbCurrentOption;
				pbCurrentOption++;
				if (bOption == bCurrentOption)
				{
					*ppbOptionData = pbCurrentOption;
					*piOptionDataSize = bCurrentOptionLen;
					bSuccess = true;
				}
				pbCurrentOption += bCurrentOptionLen;
			}
			else
			{
				OUTPUT_WARNING((TEXT("Invalid option data (not enough room for required length byte).")));
			}
		}
	}
	return bSuccess;
}

bool GetDHCPMessageType(const BYTE* const pbOptions, const int iOptionsSize, DHCPMessageTypes* const pdhcpmtMessageType)
{
	ASSERT(((0 == iOptionsSize) || (0 != pbOptions)) && (0 != pdhcpmtMessageType));
	bool bSuccess = false;
	const BYTE* pbDHCPMessageTypeData;
	unsigned int iDHCPMessageTypeDataSize;
	if (FindOptionData(option_DHCPMESSAGETYPE, pbOptions, iOptionsSize, &pbDHCPMessageTypeData, &iDHCPMessageTypeDataSize) &&
		(1 == iDHCPMessageTypeDataSize) && (1 <= *pbDHCPMessageTypeData) && (*pbDHCPMessageTypeData <= 8))
	{
		*pdhcpmtMessageType = (DHCPMessageTypes)(*pbDHCPMessageTypeData);
		bSuccess = true;
	}
	return bSuccess;
}

bool AddressInUseInformationAddrValueFilter(const AddressInUseInformation& raiui, const void* const pvFilterData)
{
	const DWORD* const pdwAddrValue = (DWORD*)pvFilterData;
	return (*pdwAddrValue == raiui.dwAddrValue);
}

struct ClientIdentifierData
{
	const BYTE* pbClientIdentifier;
	DWORD dwClientIdentifierSize;
};
bool AddressInUseInformationClientIdentifierFilter(const AddressInUseInformation& raiui, const void* const pvFilterData)
{
	const ClientIdentifierData* const pcid = (ClientIdentifierData*)pvFilterData;
	ASSERT(0 != pcid);
	return ((0 != raiui.dwClientIdentifierSize) && (pcid->dwClientIdentifierSize == raiui.dwClientIdentifierSize) && (0 == memcmp(pcid->pbClientIdentifier, raiui.pbClientIdentifier, pcid->dwClientIdentifierSize)));
}

void ProcessDHCPClientRequest(const SOCKET sServerSocket, const char* const pcsServerHostName, const BYTE* const pbData, const int iDataSize, VectorAddressInUseInformation* const pvAddressesInUse, const DWORD dwServerAddr, const DWORD dwMask, const DWORD dwMinAddr, const DWORD dwMaxAddr)
{
	ASSERT((INVALID_SOCKET != sServerSocket) && (0 != pcsServerHostName) && ((0 == iDataSize) || (0 != pbData)) && (0 != pvAddressesInUse) && (0 != dwServerAddr) && (0 != dwMask) && (0 != dwMinAddr) && (0 != dwMaxAddr));
	const DHCPMessage* const pdhcpmRequest = (DHCPMessage*)pbData;
	if ((((sizeof(*pdhcpmRequest) + sizeof(pbDHCPMagicCookie)) <= iDataSize) &&  // Take into account mandatory DHCP magic cookie values in options array (RFC 2131 section 3)
		(op_BOOTREQUEST == pdhcpmRequest->op) &&
		// (pdhcpmRequest->htype) && // Could also validate htype
		(0 == memcmp(pbDHCPMagicCookie, pdhcpmRequest->options, sizeof(pbDHCPMagicCookie))))
		)
	{
		const BYTE* const pbOptions = pdhcpmRequest->options + sizeof(pbDHCPMagicCookie);
		const int iOptionsSize = iDataSize - (int)sizeof(*pdhcpmRequest) - (int)sizeof(pbDHCPMagicCookie);
		DHCPMessageTypes dhcpmtMessageType;
		if (GetDHCPMessageType(pbOptions, iOptionsSize, &dhcpmtMessageType))
		{
			// Determine client host name
			char pcsClientHostName[MAX_HOSTNAME_LENGTH];
			pcsClientHostName[0] = '\0';
			const BYTE* pbRequestHostNameData;
			unsigned int iRequestHostNameDataSize;
			if (FindOptionData(option_HOSTNAME, pbOptions, iOptionsSize, &pbRequestHostNameData, &iRequestHostNameDataSize))
			{
				const size_t stHostNameCopySize = min(iRequestHostNameDataSize + 1, ARRAY_LENGTH(pcsClientHostName));
				_tcsncpy_s(pcsClientHostName, stHostNameCopySize, (char*)pbRequestHostNameData, _TRUNCATE);
			}
			if (('\0' == pcsServerHostName[0]) || (0 != _stricmp(pcsClientHostName, pcsServerHostName)))
			{
				// Determine client identifier in proper RFC 2131 order (client identifier option then chaddr)
				const BYTE* pbRequestClientIdentifierData;
				unsigned int iRequestClientIdentifierDataSize;
				if (!FindOptionData(option_CLIENTIDENTIFIER, pbOptions, iOptionsSize, &pbRequestClientIdentifierData, &iRequestClientIdentifierDataSize))
				{
					pbRequestClientIdentifierData = pdhcpmRequest->chaddr;
					iRequestClientIdentifierDataSize = sizeof(pdhcpmRequest->chaddr);
				}
				// Determine if we've seen this client before
				bool bSeenClientBefore = false;
				DWORD dwClientPreviousOfferAddr = (DWORD)INADDR_BROADCAST;  // Invalid IP address for later comparison
				const ClientIdentifierData cid = { pbRequestClientIdentifierData, (DWORD)iRequestClientIdentifierDataSize };
				const int iIndex = FindIndexOf(pvAddressesInUse, AddressInUseInformationClientIdentifierFilter, &cid);
				if (-1 != iIndex)
				{
					const AddressInUseInformation aiui = pvAddressesInUse->at((size_t)iIndex);
					dwClientPreviousOfferAddr = DWValuetoIP(aiui.dwAddrValue);
					bSeenClientBefore = true;
				}
				// Server message handling
				// RFC 2131 section 4.3
				BYTE bDHCPMessageBuffer[sizeof(DHCPMessage) + sizeof(DHCPServerOptions)];
				ZeroMemory(bDHCPMessageBuffer, sizeof(bDHCPMessageBuffer));
				DHCPMessage* const pdhcpmReply = (DHCPMessage*)&bDHCPMessageBuffer;
				pdhcpmReply->op = op_BOOTREPLY;
				pdhcpmReply->htype = pdhcpmRequest->htype;
				pdhcpmReply->hlen = pdhcpmRequest->hlen;
				// pdhcpmReply->hops = 0;
				pdhcpmReply->xid = pdhcpmRequest->xid;
				// pdhcpmReply->ciaddr = 0;
				// pdhcpmReply->yiaddr = 0;  Or changed below
				// pdhcpmReply->siaddr = 0;
				pdhcpmReply->flags = pdhcpmRequest->flags;
				pdhcpmReply->giaddr = pdhcpmRequest->giaddr;
				CopyMemory(pdhcpmReply->chaddr, pdhcpmRequest->chaddr, sizeof(pdhcpmReply->chaddr));
				strncpy_s((char*)(pdhcpmReply->sname), sizeof(pdhcpmReply->sname), pcsServerName, _TRUNCATE);
				// pdhcpmReply->file = 0;
				// pdhcpmReply->options below
				DHCPServerOptions* const pdhcpsoServerOptions = (DHCPServerOptions*)(pdhcpmReply->options);
				CopyMemory(pdhcpsoServerOptions->pbMagicCookie, pbDHCPMagicCookie, sizeof(pdhcpsoServerOptions->pbMagicCookie));
				// DHCP Message Type - RFC 2132 section 9.6
				pdhcpsoServerOptions->pbMessageType[0] = option_DHCPMESSAGETYPE;
				pdhcpsoServerOptions->pbMessageType[1] = 1;
				// pdhcpsoServerOptions->pbMessageType[2] set below
				// IP Address Lease Time - RFC 2132 section 9.2
				pdhcpsoServerOptions->pbLeaseTime[0] = option_IPADDRESSLEASETIME;
				pdhcpsoServerOptions->pbLeaseTime[1] = 4;
				C_ASSERT(sizeof(u_long) == 4);
				*((u_long*)(&(pdhcpsoServerOptions->pbLeaseTime[2]))) = htonl(1 * 60 * 60);  // One hour
				// Subnet Mask - RFC 2132 section 3.3
				pdhcpsoServerOptions->pbSubnetMask[0] = option_SUBNETMASK;
				pdhcpsoServerOptions->pbSubnetMask[1] = 4;
				C_ASSERT(sizeof(u_long) == 4);
				*((u_long*)(&(pdhcpsoServerOptions->pbSubnetMask[2]))) = dwMask;  // Already in network order
				// Server Identifier - RFC 2132 section 9.7
				pdhcpsoServerOptions->pbServerID[0] = option_SERVERIDENTIFIER;
				pdhcpsoServerOptions->pbServerID[1] = 4;
				C_ASSERT(sizeof(u_long) == 4);
				*((u_long*)(&(pdhcpsoServerOptions->pbServerID[2]))) = dwServerAddr;  // Already in network order
				pdhcpsoServerOptions->bEND = option_END;
				bool bSendDHCPMessage = false;
				switch (dhcpmtMessageType)
				{
				case DHCPMessageType_DISCOVER:
				{
					// RFC 2131 section 4.3.1
					// UNSUPPORTED: Requested IP Address option
					static DWORD dwServerLastOfferAddrValue = DWIPtoValue(dwMaxAddr);  // Initialize to max to wrap and offer min first
					const DWORD dwMinAddrValue = DWIPtoValue(dwMinAddr);
					const DWORD dwMaxAddrValue = DWIPtoValue(dwMaxAddr);
					DWORD dwOfferAddrValue;
					bool bOfferAddrValueValid = false;
					if (bSeenClientBefore)
					{
						dwOfferAddrValue = DWIPtoValue(dwClientPreviousOfferAddr);
						bOfferAddrValueValid = true;
					}
					else
					{
						dwOfferAddrValue = dwServerLastOfferAddrValue + 1;
					}
					// Search for an available address if necessary
					const DWORD dwInitialOfferAddrValue = dwOfferAddrValue;
					bool bOfferedInitialValue = false;
					while (!bOfferAddrValueValid && !(bOfferedInitialValue && (dwInitialOfferAddrValue == dwOfferAddrValue)))  // Detect address exhaustion
					{
						if (dwMaxAddrValue < dwOfferAddrValue)
						{
							ASSERT(dwMaxAddrValue + 1 == dwOfferAddrValue);
							dwOfferAddrValue = dwMinAddrValue;
						}
						bOfferAddrValueValid = (-1 == FindIndexOf(pvAddressesInUse, AddressInUseInformationAddrValueFilter, &dwOfferAddrValue));
						bOfferedInitialValue = true;
						if (!bOfferAddrValueValid)
						{
							dwOfferAddrValue++;
						}
					}
					if (bOfferAddrValueValid)
					{
						dwServerLastOfferAddrValue = dwOfferAddrValue;
						const DWORD dwOfferAddr = DWValuetoIP(dwOfferAddrValue);
						ASSERT((0 != iRequestClientIdentifierDataSize) && (0 != pbRequestClientIdentifierData));
						AddressInUseInformation aiuiClientAddress;
						aiuiClientAddress.dwAddrValue = dwOfferAddrValue;
						aiuiClientAddress.pbClientIdentifier = (BYTE*)LocalAlloc(LMEM_FIXED, iRequestClientIdentifierDataSize);
						if (0 != aiuiClientAddress.pbClientIdentifier)
						{
							CopyMemory(aiuiClientAddress.pbClientIdentifier, pbRequestClientIdentifierData, iRequestClientIdentifierDataSize);
							aiuiClientAddress.dwClientIdentifierSize = iRequestClientIdentifierDataSize;
							if (bSeenClientBefore || PushBack(pvAddressesInUse, &aiuiClientAddress))
							{
								pdhcpmReply->yiaddr = dwOfferAddr;
								pdhcpsoServerOptions->pbMessageType[2] = DHCPMessageType_OFFER;
								bSendDHCPMessage = true;
								OUTPUT((TEXT("Offering client \"%hs\" IP address %d.%d.%d.%d"), pcsClientHostName, DWIP0(dwOfferAddr), DWIP1(dwOfferAddr), DWIP2(dwOfferAddr), DWIP3(dwOfferAddr)));
							}
							else
							{
								VERIFY(0 == LocalFree(aiuiClientAddress.pbClientIdentifier));
								OUTPUT_ERROR((TEXT("Insufficient memory to add client address.")));
							}
							if (bSeenClientBefore)
							{
								VERIFY(0 == LocalFree(aiuiClientAddress.pbClientIdentifier));
							}
						}
						else
						{
							OUTPUT_ERROR((TEXT("Insufficient memory to add client address.")));
						}
					}
					else
					{
						OUTPUT_ERROR((TEXT("No more IP addresses available for client \"%hs\""), pcsClientHostName));
					}
				}
				break;
				case DHCPMessageType_REQUEST:
				{
					// RFC 2131 section 4.3.2
					// Determine requested IP address
					DWORD dwRequestedIPAddress = INADDR_BROADCAST;  // Invalid IP address for later comparison
					const BYTE* pbRequestRequestedIPAddressData = 0;
					unsigned int iRequestRequestedIPAddressDataSize = 0;
					if (FindOptionData(option_REQUESTEDIPADDRESS, pbOptions, iOptionsSize, &pbRequestRequestedIPAddressData, &iRequestRequestedIPAddressDataSize) && (sizeof(dwRequestedIPAddress) == iRequestRequestedIPAddressDataSize))
					{
						dwRequestedIPAddress = *((DWORD*)pbRequestRequestedIPAddressData);
					}
					// Determine server identifier
					const BYTE* pbRequestServerIdentifierData = 0;
					unsigned int iRequestServerIdentifierDataSize = 0;
					if (FindOptionData(option_SERVERIDENTIFIER, pbOptions, iOptionsSize, &pbRequestServerIdentifierData, &iRequestServerIdentifierDataSize) &&
						(sizeof(dwServerAddr) == iRequestServerIdentifierDataSize) && (dwServerAddr == *((DWORD*)pbRequestServerIdentifierData)))
					{
						// Response to OFFER
						// DHCPREQUEST generated during SELECTING state
						ASSERT(0 == pdhcpmRequest->ciaddr);
						if (bSeenClientBefore)
						{
							// Already have an IP address for this client - ACK it
							pdhcpsoServerOptions->pbMessageType[2] = DHCPMessageType_ACK;
							// Will set other options below
						}
						else
						{
							// Haven't seen this client before - NAK it
							pdhcpsoServerOptions->pbMessageType[2] = DHCPMessageType_NAK;
							// Will clear invalid options and prepare to send message below
						}
					}
					else
					{
						// Request to verify or extend
						if (((INADDR_BROADCAST != dwRequestedIPAddress) /*&& (0 == pdhcpmRequest->ciaddr)*/) ||  // DHCPREQUEST generated during INIT-REBOOT state - Some clients set ciaddr in this case, so deviate from the spec by allowing it
							((INADDR_BROADCAST == dwRequestedIPAddress) && (0 != pdhcpmRequest->ciaddr)))  // Unicast -> DHCPREQUEST generated during RENEWING state / Broadcast -> DHCPREQUEST generated during REBINDING state
						{
							if (bSeenClientBefore && ((dwClientPreviousOfferAddr == dwRequestedIPAddress) || (dwClientPreviousOfferAddr == pdhcpmRequest->ciaddr)))
							{
								// Already have an IP address for this client - ACK it
								pdhcpsoServerOptions->pbMessageType[2] = DHCPMessageType_ACK;
								// Will set other options below
							}
							else
							{
								// Haven't seen this client before or requested IP address is invalid
								pdhcpsoServerOptions->pbMessageType[2] = DHCPMessageType_NAK;
								// Will clear invalid options and prepare to send message below
							}
						}
						else
						{
							OUTPUT_WARNING((TEXT("Invalid DHCP message (invalid data).")));
						}
					}
					switch (pdhcpsoServerOptions->pbMessageType[2])
					{
					case DHCPMessageType_ACK:
						ASSERT(INADDR_BROADCAST != dwClientPreviousOfferAddr);
						pdhcpmReply->ciaddr = dwClientPreviousOfferAddr;
						pdhcpmReply->yiaddr = dwClientPreviousOfferAddr;
						bSendDHCPMessage = true;
						OUTPUT((TEXT("Acknowledging client \"%hs\" has IP address %d.%d.%d.%d"), pcsClientHostName, DWIP0(dwClientPreviousOfferAddr), DWIP1(dwClientPreviousOfferAddr), DWIP2(dwClientPreviousOfferAddr), DWIP3(dwClientPreviousOfferAddr)));
						break;
					case DHCPMessageType_NAK:
						C_ASSERT(0 == option_PAD);
						ZeroMemory(pdhcpsoServerOptions->pbLeaseTime, sizeof(pdhcpsoServerOptions->pbLeaseTime));
						ZeroMemory(pdhcpsoServerOptions->pbSubnetMask, sizeof(pdhcpsoServerOptions->pbSubnetMask));
						bSendDHCPMessage = true;
						OUTPUT((TEXT("Denying client \"%hs\" unoffered IP address."), pcsClientHostName));
						break;
					default:
						// Nothing to do
						break;
					}
				}
				break;
				case DHCPMessageType_DECLINE:
					// Fall-through
				case DHCPMessageType_RELEASE:
					// UNSUPPORTED: Mark address as unused
					break;
				case DHCPMessageType_INFORM:
					// Unsupported DHCP message type - fail silently
					break;
				case DHCPMessageType_OFFER:
				case DHCPMessageType_ACK:
				case DHCPMessageType_NAK:
					OUTPUT_WARNING((TEXT("Unexpected DHCP message type.")));
					break;
				default:
					ASSERT(!"Invalid DHCPMessageType");
					break;
				}
				if (bSendDHCPMessage)
				{
					ASSERT(0 != pdhcpsoServerOptions->pbMessageType[2]);  // Must have set an option if we're going to be sending this message
					// Determine how to send the reply
					// RFC 2131 section 4.1
					u_long ulAddr = INADDR_LOOPBACK;  // Invalid value
					if (0 == pdhcpmRequest->giaddr)
					{
						switch (pdhcpsoServerOptions->pbMessageType[2])
						{
						case DHCPMessageType_OFFER:
							// Fall-through
						case DHCPMessageType_ACK:
						{
							if (0 == pdhcpmRequest->ciaddr)
							{
								if (0 != (BROADCAST_FLAG & pdhcpmRequest->flags))
								{
									ulAddr = INADDR_BROADCAST;
								}
								else
								{
									ulAddr = pdhcpmRequest->yiaddr;  // Already in network order
									if (0 == ulAddr)
									{
										// UNSUPPORTED: Unicast to hardware address
										// Instead, broadcast the response and rely on other DHCP clients to ignore it
										ulAddr = INADDR_BROADCAST;
									}
								}
							}
							else
							{
								ulAddr = pdhcpmRequest->ciaddr;  // Already in network order
							}
						}
						break;
						case DHCPMessageType_NAK:
						{
							ulAddr = INADDR_BROADCAST;
						}
						break;
						default:
							ASSERT(!"Invalid DHCPMessageType");
							break;
						}
					}
					else
					{
						ulAddr = pdhcpmRequest->giaddr;  // Already in network order
						pdhcpmReply->flags |= BROADCAST_FLAG;  // Indicate to the relay agent that it must broadcast
					}
					ASSERT((INADDR_LOOPBACK != ulAddr) && (0 != ulAddr));
					SOCKADDR_IN saClientAddress;
					saClientAddress.sin_family = AF_INET;
					saClientAddress.sin_addr.s_addr = ulAddr;
					saClientAddress.sin_port = htons((u_short)DHCP_CLIENT_PORT);
					VERIFY(SOCKET_ERROR != sendto(sServerSocket, (char*)pdhcpmReply, sizeof(bDHCPMessageBuffer), 0, (SOCKADDR*)&saClientAddress, sizeof(saClientAddress)));
				}
			}
			else
			{
				// Ignore attempts by the DHCP server to obtain a DHCP address (possible if its current address was obtained by auto-IP) because this would invalidate dwServerAddr
			}
		}
		else
		{
			OUTPUT_WARNING((TEXT("Invalid DHCP message (invalid or missing DHCP message type).")));
		}
	}
	else
	{
		OUTPUT_WARNING((TEXT("Invalid DHCP message (failed initial checks).")));
	}
}

bool ReadDHCPClientRequests(const SOCKET sServerSocket, const char* const pcsServerHostName, VectorAddressInUseInformation* const pvAddressesInUse, const DWORD dwServerAddr, const DWORD dwMask, const DWORD dwMinAddr, const DWORD dwMaxAddr)
{
	ASSERT((INVALID_SOCKET != sServerSocket) && (0 != pcsServerHostName) && (0 != pvAddressesInUse) && (0 != dwServerAddr) && (0 != dwMask) && (0 != dwMinAddr) && (0 != dwMaxAddr));
	bool bSuccess = false;
	BYTE* const pbReadBuffer = (BYTE*)LocalAlloc(LMEM_FIXED, MAX_UDP_MESSAGE_SIZE);
	if (0 != pbReadBuffer)
	{
		bSuccess = true;
		int iLastError = 0;
		ASSERT(WSAENOTSOCK != iLastError);
		while (WSAENOTSOCK != iLastError)
		{
			SOCKADDR_IN saClientAddress;
			int iClientAddressSize = sizeof(saClientAddress);
			const int iBytesReceived = recvfrom(sServerSocket, (char*)pbReadBuffer, MAX_UDP_MESSAGE_SIZE, 0, (SOCKADDR*)(&saClientAddress), &iClientAddressSize);
			if (SOCKET_ERROR != iBytesReceived)
			{
				// ASSERT(DHCP_CLIENT_PORT == ntohs(saClientAddress.sin_port));  // Not always the case
				ProcessDHCPClientRequest(sServerSocket, pcsServerHostName, pbReadBuffer, iBytesReceived, pvAddressesInUse, dwServerAddr, dwMask, dwMinAddr, dwMaxAddr);
			}
			else
			{
				iLastError = WSAGetLastError();
				if (WSAENOTSOCK == iLastError)
				{
					OUTPUT((TEXT("Stopping server request handler.")));
				}
				else if (WSAEINTR == iLastError)
				{
					OUTPUT((TEXT("Socket operation was cancelled.")));
				}
				else
				{
					OUTPUT_ERROR((TEXT("Call to recvfrom returned error %d."), iLastError));
				}
			}
		}
		VERIFY(0 == LocalFree(pbReadBuffer));
	}
	else
	{
		OUTPUT_ERROR((TEXT("Unable to allocate memory for client datagram read buffer.")));
	}
	return bSuccess;
}

SOCKET sServerSocket = INVALID_SOCKET;  // Global to allow ConsoleCtrlHandlerRoutine access to it

BOOL WINAPI ConsoleCtrlHandlerRoutine(DWORD dwCtrlType)
{
	BOOL bReturn = FALSE;
	if ((CTRL_C_EVENT == dwCtrlType) || (CTRL_BREAK_EVENT == dwCtrlType))
	{
		if (INVALID_SOCKET != sServerSocket)
		{
			VERIFY(0 == closesocket(sServerSocket));
			sServerSocket = INVALID_SOCKET;
		}
		bReturn = TRUE;
	}
	return bReturn;
}

int main(int /*argc*/, char** /*argv*/)
{
	OUTPUT((TEXT("")));
	OUTPUT((TEXT("DHCPLite")));
	OUTPUT((TEXT("2016-04-02")));
	OUTPUT((TEXT("Copyright (c) 2001-2016 by David Anson (http://dlaa.me/)")));
	OUTPUT((TEXT("")));
	if (SetConsoleCtrlHandler(ConsoleCtrlHandlerRoutine, TRUE))
	{
		DWORD dwServerAddr;
		DWORD dwMask;
		DWORD dwMinAddr;
		DWORD dwMaxAddr;
		if (GetIPAddressInformation(&dwServerAddr, &dwMask, &dwMinAddr, &dwMaxAddr))
		{
			ASSERT((DWValuetoIP(dwMinAddr) <= DWValuetoIP(dwServerAddr)) && (DWValuetoIP(dwServerAddr) <= DWValuetoIP(dwMaxAddr)));
			VectorAddressInUseInformation vAddressesInUse;
			AddressInUseInformation aiuiServerAddress;
			aiuiServerAddress.dwAddrValue = DWIPtoValue(dwServerAddr);
			aiuiServerAddress.pbClientIdentifier = 0;  // Server entry is only entry without a client ID
			aiuiServerAddress.dwClientIdentifierSize = 0;
			if (PushBack(&vAddressesInUse, &aiuiServerAddress))
			{
				WSADATA wsaData;
				if (0 == WSAStartup(MAKEWORD(1, 1), &wsaData))
				{
					OUTPUT((TEXT("")));
					OUTPUT((TEXT("Server is running...  (Press Ctrl+C to shutdown.)")));
					OUTPUT((TEXT("")));
					char pcsServerHostName[MAX_HOSTNAME_LENGTH];
					if (InitializeDHCPServer(&sServerSocket, dwServerAddr, pcsServerHostName, ARRAY_LENGTH(pcsServerHostName)))
					{
						VERIFY(ReadDHCPClientRequests(sServerSocket, pcsServerHostName, &vAddressesInUse, dwServerAddr, dwMask, dwMinAddr, dwMaxAddr));
						if (INVALID_SOCKET != sServerSocket)
						{
							VERIFY(0 == closesocket(sServerSocket));
							sServerSocket = INVALID_SOCKET;
						}
					}
					else
					{
						// OUTPUT_ERROR called by InitializeDHCPServer
					}
					VERIFY(0 == WSACleanup());
				}
				else
				{
					OUTPUT_ERROR((TEXT("Unable to initialize WinSock.")));
				}
			}
			else
			{
				OUTPUT_ERROR((TEXT("Insufficient memory to add server address.")));
			}
			for (size_t i = 0; i < vAddressesInUse.size(); i++)
			{
				aiuiServerAddress = vAddressesInUse.at(i);
				if (0 != aiuiServerAddress.pbClientIdentifier)
				{
					VERIFY(0 == LocalFree(aiuiServerAddress.pbClientIdentifier));
				}
			}
		}
		else
		{
			// OUTPUT_ERROR called by GetIPAddressInformation
		}
	}
	else
	{
		OUTPUT_ERROR((TEXT("Unable to set Ctrl-C handler.")));
	}
	return 0;
}
