#include "DHCPLite.h"
#include <iostream>
#include <tchar.h>
#include <assert.h>
#include <iphlpapi.h>
#include <iprtrmib.h>

using namespace DHCPLite;

int DHCPServer::FindIndexOf(const VectorAddressInUseInformation *const pvAddressesInUse, FindIndexOfFilter pFilter) {
 	assert((0 != pvAddressesInUse) && (0 != pFilter));

	for (size_t i = 0; i < pvAddressesInUse->size(); i++) {
		if (pFilter(pvAddressesInUse->at(i))) {
			return (int)i;
		}
	}
	return -1;
}

bool DHCPServer::FindOptionData(const BYTE bOption, const BYTE *const pbOptions, const int iOptionsSize, const BYTE **const ppbOptionData, unsigned int *const piOptionDataSize) {
	assert(((0 == iOptionsSize) || (0 != pbOptions)) && (0 != ppbOptionData) && (0 != piOptionDataSize)
		&& (MsgOption_PAD != bOption) && (MsgOption_END != bOption));

	bool bHitEND = false; // RFC 2132
	const BYTE *pbCurrentOption = pbOptions;
	while (((pbCurrentOption - pbOptions) < iOptionsSize) && !bHitEND) {
		const BYTE bCurrentOption = *pbCurrentOption;

		switch (bCurrentOption) {
		case MsgOption_PAD:
			pbCurrentOption++;
			break;
		case MsgOption_END:
			bHitEND = true;
			break;
		default:
		{
			pbCurrentOption++;
			if ((pbCurrentOption - pbOptions) >= iOptionsSize) {
				assert(!(TEXT("Invalid option data (not enough room for required length byte).")));
				break;
			}
			const BYTE bCurrentOptionLen = *pbCurrentOption;
			pbCurrentOption++;
			if (bOption == bCurrentOption) {
				*ppbOptionData = pbCurrentOption;
				*piOptionDataSize = bCurrentOptionLen;
				return true;
			}
			pbCurrentOption += bCurrentOptionLen;
			break;
		}
		}
	}
	return false;
}

bool DHCPServer::InitializeDHCPServer() {
	// Determine server hostname
	if (NO_ERROR != gethostname(pcsServerHostName, sizeof(pcsServerHostName))) {
		pcsServerHostName[0] = '\0';
	}

	// Open socket and set broadcast option on it
	sServerSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (INVALID_SOCKET == sServerSocket) {
		throw SocketException("Unable to open server socket (port 67).");
	}

	SOCKADDR_IN saServerAddress{};
	saServerAddress.sin_family = AF_INET;
	saServerAddress.sin_addr.s_addr = config.addrInfo.address;  // Already in network byte order
	saServerAddress.sin_port = htons((u_short)DHCP_SERVER_PORT);
	const int iServerAddressSize = sizeof(saServerAddress);
	if (SOCKET_ERROR == bind(sServerSocket, (SOCKADDR *)(&saServerAddress), iServerAddressSize)) {
		throw SocketException("Unable to bind to server socket (port 67).");
	}

	int iBroadcastOption = TRUE;
	if (NO_ERROR != setsockopt(sServerSocket, SOL_SOCKET, SO_BROADCAST, (char *)(&iBroadcastOption), sizeof(iBroadcastOption))) {
		throw SocketException("Unable to set socket options.");
	}

	return true;
}

bool DHCPServer::GetDHCPMessageType(const BYTE *const pbOptions, const int iOptionsSize, MessageTypes *const pdhcpmtMessageType) {
 	assert(((0 == iOptionsSize) || (0 != pbOptions)) && (0 != pdhcpmtMessageType));

	const BYTE *pbDHCPMessageTypeData;
	unsigned int iDHCPMessageTypeDataSize;
	if (FindOptionData(MsgOption_DHCPMESSAGETYPE, pbOptions, iOptionsSize, &pbDHCPMessageTypeData, &iDHCPMessageTypeDataSize)
		&& (1 == iDHCPMessageTypeDataSize) && (1 <= *pbDHCPMessageTypeData) && (*pbDHCPMessageTypeData <= 8)) {
		*pdhcpmtMessageType = (MessageTypes)(*pbDHCPMessageTypeData);
		return true;
	}
	return false;
}

void DHCPServer::ProcessDHCPClientRequest(const BYTE *const pbData, const int iDataSize) {
	const BYTE pbDHCPMagicCookie[] = { 99, 130, 83, 99 }; // DHCP magic cookie values

	const DHCPMessage *const pdhcpmRequest = (DHCPMessage *)pbData;
	if ((((sizeof(*pdhcpmRequest) + sizeof(pbDHCPMagicCookie)) <= iDataSize) &&  // Take into account mandatory DHCP magic cookie values in options array (RFC 2131 section 3)
		(MsgOp_BOOTREQUEST == pdhcpmRequest->op) &&
		// (pdhcpmRequest->htype) && // Could also validate htype
		(0 == memcmp(pbDHCPMagicCookie, pdhcpmRequest->options, sizeof(pbDHCPMagicCookie))))
		) {
		const BYTE *const pbOptions = pdhcpmRequest->options + sizeof(pbDHCPMagicCookie);
		const int iOptionsSize = iDataSize - (int)sizeof(*pdhcpmRequest) - (int)sizeof(pbDHCPMagicCookie);
		MessageTypes dhcpmtMessageType;
		if (GetDHCPMessageType(pbOptions, iOptionsSize, &dhcpmtMessageType)) {
			// Determine client host name
			char pcsClientHostName[MAX_HOSTNAME_LENGTH]{};
			pcsClientHostName[0] = '\0';
			const BYTE *pbRequestHostNameData;
			unsigned int iRequestHostNameDataSize;
			if (FindOptionData(MsgOption_HOSTNAME, pbOptions, iOptionsSize, &pbRequestHostNameData, &iRequestHostNameDataSize)) {
				const size_t stHostNameCopySize = min(iRequestHostNameDataSize + 1, sizeof(pcsClientHostName));
				_tcsncpy_s(pcsClientHostName, stHostNameCopySize, (char *)pbRequestHostNameData, _TRUNCATE);
			}
			if (('\0' == pcsServerHostName[0]) || (0 != _stricmp(pcsClientHostName, pcsServerHostName))) {
				// Determine client identifier in proper RFC 2131 order (client identifier option then chaddr)
				const BYTE *pbRequestClientIdentifierData;
				unsigned int iRequestClientIdentifierDataSize;
				if (!FindOptionData(MsgOption_CLIENTIDENTIFIER, pbOptions, iOptionsSize, &pbRequestClientIdentifierData, &iRequestClientIdentifierDataSize)) {
					pbRequestClientIdentifierData = pdhcpmRequest->chaddr;
					iRequestClientIdentifierDataSize = sizeof(pdhcpmRequest->chaddr);
				}
				// Determine if we've seen this client before
				bool bSeenClientBefore = false;
				DWORD dwClientPreviousOfferAddr = (DWORD)INADDR_BROADCAST;  // Invalid IP address for later comparison
				auto cid = std::make_tuple(pbRequestClientIdentifierData, (DWORD)iRequestClientIdentifierDataSize);
				const int iIndex = FindIndexOf(&vAddressesInUse, [=](const AddressInUseInformation &raiui) {
					return (0 != raiui.dwClientIdentifierSize) && (iRequestClientIdentifierDataSize == raiui.dwClientIdentifierSize)
						&& (0 == memcmp(pbRequestClientIdentifierData, raiui.pbClientIdentifier, iRequestClientIdentifierDataSize));
				});
				if (-1 != iIndex) {
					const AddressInUseInformation aiui = vAddressesInUse.at((size_t)iIndex);
					dwClientPreviousOfferAddr = ValuetoIP(aiui.dwAddrValue);
					bSeenClientBefore = true;
				}
				// Server message handling
				// RFC 2131 section 4.3
				BYTE bDHCPMessageBuffer[sizeof(DHCPMessage) + sizeof(DHCPServerOptions)];
				ZeroMemory(bDHCPMessageBuffer, sizeof(bDHCPMessageBuffer));
				DHCPMessage *const pdhcpmReply = (DHCPMessage *)&bDHCPMessageBuffer;
				pdhcpmReply->op = MsgOp_BOOTREPLY;
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
				strncpy_s((char *)(pdhcpmReply->sname), sizeof(pdhcpmReply->sname), serverName.c_str(), _TRUNCATE);
				// pdhcpmReply->file = 0;
				// pdhcpmReply->options below
				DHCPServerOptions *const pdhcpsoServerOptions = (DHCPServerOptions *)(pdhcpmReply->options);
				CopyMemory(pdhcpsoServerOptions->pbMagicCookie, pbDHCPMagicCookie, sizeof(pdhcpsoServerOptions->pbMagicCookie));
				// DHCP Message Type - RFC 2132 section 9.6
				pdhcpsoServerOptions->pbMessageType[0] = MsgOption_DHCPMESSAGETYPE;
				pdhcpsoServerOptions->pbMessageType[1] = 1;
				// pdhcpsoServerOptions->pbMessageType[2] set below
				// IP Address Lease Time - RFC 2132 section 9.2
				pdhcpsoServerOptions->pbLeaseTime[0] = MsgOption_IPADDRESSLEASETIME;
				pdhcpsoServerOptions->pbLeaseTime[1] = 4;
				C_ASSERT(sizeof(u_long) == 4);
				*((u_long *)(&(pdhcpsoServerOptions->pbLeaseTime[2]))) = htonl(1 * 60 * 60);  // One hour
				// Subnet Mask - RFC 2132 section 3.3
				pdhcpsoServerOptions->pbSubnetMask[0] = MsgOption_SUBNETMASK;
				pdhcpsoServerOptions->pbSubnetMask[1] = 4;
				C_ASSERT(sizeof(u_long) == 4);
				*((u_long *)(&(pdhcpsoServerOptions->pbSubnetMask[2]))) = config.addrInfo.mask;  // Already in network order
				// Server Identifier - RFC 2132 section 9.7
				pdhcpsoServerOptions->pbServerID[0] = MsgOption_SERVERIDENTIFIER;
				pdhcpsoServerOptions->pbServerID[1] = 4;
				C_ASSERT(sizeof(u_long) == 4);
				*((u_long *)(&(pdhcpsoServerOptions->pbServerID[2]))) = config.addrInfo.address;  // Already in network order
				pdhcpsoServerOptions->bEND = MsgOption_END;
				bool bSendDHCPMessage = false;
				switch (dhcpmtMessageType) {
				case MsgType_DISCOVER:
				{
					// RFC 2131 section 4.3.1
					// UNSUPPORTED: Requested IP Address option
					static DWORD dwServerLastOfferAddrValue = IPtoValue(config.maxAddr);  // Initialize to max to wrap and offer min first
					const DWORD dwMinAddrValue = IPtoValue(config.minAddr);
					const DWORD dwMaxAddrValue = IPtoValue(config.maxAddr);
					DWORD dwOfferAddrValue;
					bool bOfferAddrValueValid = false;
					if (bSeenClientBefore) {
						dwOfferAddrValue = IPtoValue(dwClientPreviousOfferAddr);
						bOfferAddrValueValid = true;
					}
					else {
						dwOfferAddrValue = dwServerLastOfferAddrValue + 1;
					}
					// Search for an available address if necessary
					const DWORD dwInitialOfferAddrValue = dwOfferAddrValue;
					bool bOfferedInitialValue = false;
					while (!bOfferAddrValueValid && !(bOfferedInitialValue && (dwInitialOfferAddrValue == dwOfferAddrValue)))  // Detect address exhaustion
					{
						if (dwMaxAddrValue < dwOfferAddrValue) {
						 	assert(dwMaxAddrValue + 1 == dwOfferAddrValue);
							dwOfferAddrValue = dwMinAddrValue;
						}
						bOfferAddrValueValid = (-1 == FindIndexOf(&vAddressesInUse, [=](const AddressInUseInformation &raiui) {
							return dwOfferAddrValue == raiui.dwAddrValue;
						}));
						bOfferedInitialValue = true;
						if (!bOfferAddrValueValid) {
							dwOfferAddrValue++;
						}
					}
					if (bOfferAddrValueValid) {
						dwServerLastOfferAddrValue = dwOfferAddrValue;
						const DWORD dwOfferAddr = ValuetoIP(dwOfferAddrValue);
					 	assert((0 != iRequestClientIdentifierDataSize) && (0 != pbRequestClientIdentifierData));
						AddressInUseInformation aiuiClientAddress{};
						aiuiClientAddress.dwAddrValue = dwOfferAddrValue;
						aiuiClientAddress.pbClientIdentifier = (BYTE *)LocalAlloc(LMEM_FIXED, iRequestClientIdentifierDataSize);
						if (0 != aiuiClientAddress.pbClientIdentifier) {
							CopyMemory(aiuiClientAddress.pbClientIdentifier, pbRequestClientIdentifierData, iRequestClientIdentifierDataSize);
							aiuiClientAddress.dwClientIdentifierSize = iRequestClientIdentifierDataSize;

							vAddressesInUse.push_back(aiuiClientAddress);
							pdhcpmReply->yiaddr = dwOfferAddr;
							pdhcpsoServerOptions->pbMessageType[2] = MsgType_OFFER;
							bSendDHCPMessage = true;

							MessageCallback_Discover(pcsClientHostName, dwOfferAddr);

							if (bSeenClientBefore) {
							 	LocalFree(aiuiClientAddress.pbClientIdentifier);
							}
						}
						else {
							LocalFree(aiuiClientAddress.pbClientIdentifier);
							throw RequestException("Insufficient memory to add client address.");
						}
					}
					else {
						throw RequestException("No more IP addresses available for client.");
					}
				}
				break;
				case MsgType_REQUEST:
				{
					// RFC 2131 section 4.3.2
					// Determine requested IP address
					DWORD dwRequestedIPAddress = INADDR_BROADCAST;  // Invalid IP address for later comparison
					const BYTE *pbRequestRequestedIPAddressData = 0;
					unsigned int iRequestRequestedIPAddressDataSize = 0;
					if (FindOptionData(MsgOption_REQUESTEDIPADDRESS, pbOptions, iOptionsSize, &pbRequestRequestedIPAddressData, &iRequestRequestedIPAddressDataSize) && (sizeof(dwRequestedIPAddress) == iRequestRequestedIPAddressDataSize)) {
						dwRequestedIPAddress = *((DWORD *)pbRequestRequestedIPAddressData);
					}
					// Determine server identifier
					const BYTE *pbRequestServerIdentifierData = 0;
					unsigned int iRequestServerIdentifierDataSize = 0;
					if (FindOptionData(MsgOption_SERVERIDENTIFIER, pbOptions, iOptionsSize, &pbRequestServerIdentifierData, &iRequestServerIdentifierDataSize) &&
						(sizeof(config.addrInfo.address) == iRequestServerIdentifierDataSize) && (config.addrInfo.address == *((DWORD *)pbRequestServerIdentifierData))) {
						// Response to OFFER
						// DHCPREQUEST generated during SELECTING state
					 	assert(0 == pdhcpmRequest->ciaddr);
						if (bSeenClientBefore) {
							// Already have an IP address for this client - ACK it
							pdhcpsoServerOptions->pbMessageType[2] = MsgType_ACK;
							// Will set other options below
						}
						else {
							// Haven't seen this client before - NAK it
							pdhcpsoServerOptions->pbMessageType[2] = MsgType_NAK;
							// Will clear invalid options and prepare to send message below
						}
					}
					else {
						// Request to verify or extend
						if (((INADDR_BROADCAST != dwRequestedIPAddress) /*&& (0 == pdhcpmRequest->ciaddr)*/) ||  // DHCPREQUEST generated during INIT-REBOOT state - Some clients set ciaddr in this case, so deviate from the spec by allowing it
							((INADDR_BROADCAST == dwRequestedIPAddress) && (0 != pdhcpmRequest->ciaddr)))  // Unicast -> DHCPREQUEST generated during RENEWING state / Broadcast -> DHCPREQUEST generated during REBINDING state
						{
							if (bSeenClientBefore && ((dwClientPreviousOfferAddr == dwRequestedIPAddress) || (dwClientPreviousOfferAddr == pdhcpmRequest->ciaddr))) {
								// Already have an IP address for this client - ACK it
								pdhcpsoServerOptions->pbMessageType[2] = MsgType_ACK;
								// Will set other options below
							}
							else {
								// Haven't seen this client before or requested IP address is invalid
								pdhcpsoServerOptions->pbMessageType[2] = MsgType_NAK;
								// Will clear invalid options and prepare to send message below
							}
						}
						else {
							assert(!(TEXT("Invalid DHCP message (invalid data).")));
						}
					}
					switch (pdhcpsoServerOptions->pbMessageType[2]) {
					case MsgType_ACK:
					 	assert(INADDR_BROADCAST != dwClientPreviousOfferAddr);
						pdhcpmReply->ciaddr = dwClientPreviousOfferAddr;
						pdhcpmReply->yiaddr = dwClientPreviousOfferAddr;
						bSendDHCPMessage = true;

						MessageCallback_ACK(pcsClientHostName, dwClientPreviousOfferAddr);
						break;
					case MsgType_NAK:
						C_ASSERT(0 == MsgOption_PAD);
						ZeroMemory(pdhcpsoServerOptions->pbLeaseTime, sizeof(pdhcpsoServerOptions->pbLeaseTime));
						ZeroMemory(pdhcpsoServerOptions->pbSubnetMask, sizeof(pdhcpsoServerOptions->pbSubnetMask));
						bSendDHCPMessage = true;

						MessageCallback_NAK(pcsClientHostName, dwClientPreviousOfferAddr);
						break;
					default:
						// Nothing to do
						break;
					}
				}
				break;
				case MsgType_DECLINE:
					// Fall-through
				case MsgType_RELEASE:
					// UNSUPPORTED: Mark address as unused
					break;
				case MsgType_INFORM:
					// Unsupported DHCP message type - fail silently
					break;
				case MsgType_OFFER:
				case MsgType_ACK:
				case MsgType_NAK:
					assert(!(TEXT("Unexpected DHCP message type.")));
					break;
				default:
				 	assert(!"Invalid DHCPMessageType");
					break;
				}
				if (bSendDHCPMessage) {
				 	assert(0 != pdhcpsoServerOptions->pbMessageType[2]);  // Must have set an option if we're going to be sending this message
					// Determine how to send the reply
					// RFC 2131 section 4.1
					u_long ulAddr = INADDR_LOOPBACK;  // Invalid value
					if (0 == pdhcpmRequest->giaddr) {
						switch (pdhcpsoServerOptions->pbMessageType[2]) {
						case MsgType_OFFER:
							// Fall-through
						case MsgType_ACK:
						{
							if (0 == pdhcpmRequest->ciaddr) {
								if (0 != (BROADCAST_FLAG & pdhcpmRequest->flags)) {
									ulAddr = INADDR_BROADCAST;
								}
								else {
									ulAddr = pdhcpmRequest->yiaddr;  // Already in network order
									if (0 == ulAddr) {
										// UNSUPPORTED: Unicast to hardware address
										// Instead, broadcast the response and rely on other DHCP clients to ignore it
										ulAddr = INADDR_BROADCAST;
									}
								}
							}
							else {
								ulAddr = pdhcpmRequest->ciaddr;  // Already in network order
							}
						}
						break;
						case MsgType_NAK:
						{
							ulAddr = INADDR_BROADCAST;
						}
						break;
						default:
							assert(!"Invalid DHCPMessageType");
							break;
						}
					}
					else {
						ulAddr = pdhcpmRequest->giaddr;  // Already in network order
						pdhcpmReply->flags |= BROADCAST_FLAG;  // Indicate to the relay agent that it must broadcast
					}
					assert((INADDR_LOOPBACK != ulAddr) && (0 != ulAddr));
					SOCKADDR_IN saClientAddress{};
					saClientAddress.sin_family = AF_INET;
					saClientAddress.sin_addr.s_addr = ulAddr;
					saClientAddress.sin_port = htons((u_short)DHCP_CLIENT_PORT);
					assert(SOCKET_ERROR != sendto(sServerSocket, (char *)pdhcpmReply, sizeof(bDHCPMessageBuffer), 0, (SOCKADDR *)&saClientAddress, sizeof(saClientAddress)));
				}
			}
			else {
				// Ignore attempts by the DHCP server to obtain a DHCP address (possible if its current address was obtained by auto-IP) because this would invalidate dwServerAddr
			}
		}
		else {
			assert(!"Invalid DHCP message (invalid or missing DHCP message type).");
		}
	}
	else {
		assert(!"Invalid DHCP message (failed initial checks).");
	}
}

bool DHCPServer::ReadDHCPClientRequests() {
	BYTE *const pbReadBuffer = (BYTE *)LocalAlloc(LMEM_FIXED, MAX_UDP_MESSAGE_SIZE);
	if (0 == pbReadBuffer) {
		throw RequestException("Unable to allocate memory for client datagram read buffer.");
	}

	int iLastError = 0;
	while (WSAENOTSOCK != iLastError) {
		SOCKADDR_IN saClientAddress{};
		int iClientAddressSize = sizeof(saClientAddress);
		const int iBytesReceived = recvfrom(sServerSocket, (char *)pbReadBuffer, MAX_UDP_MESSAGE_SIZE, 0, (SOCKADDR *)(&saClientAddress), &iClientAddressSize);
		if (SOCKET_ERROR != iBytesReceived) {
			// assert(DHCP_CLIENT_PORT == ntohs(saClientAddress.sin_port));  // Not always the case
			ProcessDHCPClientRequest(pbReadBuffer, iBytesReceived);
		}
		else {
			iLastError = WSAGetLastError();
			if (iLastError != WSAENOTSOCK && iLastError != WSAEINTR) {
				LocalFree(pbReadBuffer);
				throw SocketException("Call to recvfrom returned error.");
			}
		}
	}
	LocalFree(pbReadBuffer);
	return true;
}


DWORD DHCPServer::IPtoValue(DWORD ip) {
	// Convert between big and small endian order
	DWORD value = 0;
	BYTE *valueBytes = (BYTE *)&value;
	BYTE *ipBytes = (BYTE *)&ip;

	for (size_t i = 0; i < 4; i++)
		valueBytes[i] = ipBytes[3 - i];

	return value;
}

DWORD DHCPServer::ValuetoIP(DWORD value) {
	return IPtoValue(value);
}

std::string DHCPServer::IPAddrToString(DWORD address) {
	BYTE *addrBytes = (BYTE *)&address;

	std::string str = "";
	for (size_t i = 0; i < 3; i++) {
		str.append(std::to_string(addrBytes[i]) + ".");
	}
	str.append(std::to_string(addrBytes[3]));

	return str;
}

std::vector<DHCPServer::IPAddrInfo> DHCPServer::GetIPAddrInfoList() {
	std::vector<IPAddrInfo> infoList;

	MIB_IPADDRTABLE miatIpAddrTable;
	ULONG ulIpAddrTableSize = sizeof(miatIpAddrTable);
	DWORD dwGetIpAddrTableResult = GetIpAddrTable(&miatIpAddrTable, &ulIpAddrTableSize, FALSE);
	// Technically, if NO_ERROR was returned, we don't need to allocate a buffer - but it's easier to do so anyway - and because we need more data than fits in the default buffer, this would only be wasteful in the error case
	if ((NO_ERROR != dwGetIpAddrTableResult) && (ERROR_INSUFFICIENT_BUFFER != dwGetIpAddrTableResult)) {
		throw IPAddrException("Unable to query IP address table.");
	}

	const ULONG ulIpAddrTableSizeAllocated = ulIpAddrTableSize;
	BYTE *const pbIpAddrTableBuffer = (BYTE *)LocalAlloc(LMEM_FIXED, ulIpAddrTableSizeAllocated);
	if (nullptr == pbIpAddrTableBuffer) {
		LocalFree(pbIpAddrTableBuffer);
		throw IPAddrException("Insufficient memory for IP address table.");
	}

	dwGetIpAddrTableResult = GetIpAddrTable((MIB_IPADDRTABLE *)pbIpAddrTableBuffer, &ulIpAddrTableSize, FALSE);
	if ((NO_ERROR != dwGetIpAddrTableResult) || (ulIpAddrTableSizeAllocated > ulIpAddrTableSize)) {
		LocalFree(pbIpAddrTableBuffer);
		throw IPAddrException("Unable to query IP address table.");
	}

	const MIB_IPADDRTABLE *const pmiatIpAddrTable = (MIB_IPADDRTABLE *)pbIpAddrTableBuffer;

	for (size_t i = 0; i < pmiatIpAddrTable->dwNumEntries; i++) {
		infoList.push_back(IPAddrInfo{ pmiatIpAddrTable->table[i].dwAddr, pmiatIpAddrTable->table[i].dwMask });
	}

	LocalFree(pbIpAddrTableBuffer);
	return infoList;
}

DHCPServer::DHCPConfig DHCPServer::GetDHCPConfig() {
	auto addrInfoList = DHCPServer::GetIPAddrInfoList();
	if (2 != addrInfoList.size()) {
		throw IPAddrException("Too many or too few IP addresses are present on this machine. [Routing can not be bypassed.]");
	}

	const bool loopbackAtIndex0 = DHCPServer::ValuetoIP(0x7f000001) == addrInfoList[0].address;
	const bool loopbackAtIndex1 = DHCPServer::ValuetoIP(0x7f000001) == addrInfoList[1].address;
	if (loopbackAtIndex0 == loopbackAtIndex1) {
		throw IPAddrException("Unsupported IP address configuration. [Expected to find loopback address and one other.]");
	}

	const int tableIndex = loopbackAtIndex1 ? 0 : 1;
	const DWORD dwAddr = addrInfoList[tableIndex].address;
	if (0 == dwAddr) {
		throw IPAddrException("IP Address is 0.0.0.0 - no network is available on this machine. [APIPA (Auto-IP) may not have assigned an IP address yet.]");
	}

	const DWORD dwMask = addrInfoList[tableIndex].mask;
	const DWORD dwAddrValue = DHCPServer::IPtoValue(dwAddr);
	const DWORD dwMaskValue = DHCPServer::IPtoValue(dwMask);
	const DWORD dwMinAddrValue = ((dwAddrValue & dwMaskValue) | 2);  // Skip x.x.x.1 (default router address)
	const DWORD dwMaxAddrValue = ((dwAddrValue & dwMaskValue) | (~(dwMaskValue | 1)));
	const DWORD dwMinAddr = DHCPServer::ValuetoIP(dwMinAddrValue);
	const DWORD dwMaxAddr = DHCPServer::ValuetoIP(dwMaxAddrValue);

	if (dwMinAddrValue > dwMaxAddrValue) {
		throw IPAddrException("No network is available on this machine. [The subnet mask is incorrect.]");
	}

	return DHCPServer::DHCPConfig{ dwAddr, dwMask, dwMinAddr, dwMaxAddr };
}

void DHCPServer::SetDiscoverCallback(MessageCallback callback) {
	MessageCallback_Discover = callback;
}

void DHCPServer::SetACKCallback(MessageCallback callback) {
	MessageCallback_ACK = callback;
}

void DHCPServer::SetNAKCallback(MessageCallback callback) {
	MessageCallback_NAK = callback;
}

DHCPLite::DHCPServer::DHCPServer(DHCPConfig config) {
	Init(config);
}

bool DHCPLite::DHCPServer::Init() {
	Init(GetDHCPConfig());

	return false;
}

bool DHCPServer::Init(DHCPConfig config) {
	DHCPServer::config = config;

	AddressInUseInformation aiuiServerAddress{};
	aiuiServerAddress.dwAddrValue = IPtoValue(config.addrInfo.address);
	aiuiServerAddress.pbClientIdentifier = 0; // Server entry is only entry without a client ID
	aiuiServerAddress.dwClientIdentifierSize = 0;
	vAddressesInUse.push_back(aiuiServerAddress);

	WSADATA wsaData;
	if (NO_ERROR != WSAStartup(MAKEWORD(1, 1), &wsaData)) {
		throw SocketException("Unable to initialize WinSock.");
	}

	return InitializeDHCPServer();
}

void DHCPServer::Start() {
	assert(ReadDHCPClientRequests());
}

void DHCPServer::Close() {
	if (INVALID_SOCKET != sServerSocket) {
		assert(NO_ERROR == closesocket(sServerSocket));
		sServerSocket = INVALID_SOCKET;
	}
}

bool DHCPServer::Cleanup() {
	if (!WSACleanup()) return false;

	for (size_t i = 0; i < vAddressesInUse.size(); i++) {
		AddressInUseInformation aiuiServerAddress{};
		aiuiServerAddress = vAddressesInUse.at(i);
		if (aiuiServerAddress.pbClientIdentifier != 0) {
			LocalFree(aiuiServerAddress.pbClientIdentifier);
		}
	}

	return true;
}

bool DHCPLite::DHCPServer::SetServerName(std::string name) {
	if (name.size() > 64)
		return false;

	serverName = name;
	return true;
}
