#include "DHCPLite.h"
#include <iostream>
#include <tchar.h>
#include <assert.h>
#include <iphlpapi.h>
#include <iprtrmib.h>

using namespace DHCPLite;

int DHCPServer::FindIndexOf(const VectorAddressInUseInformation *const pvAddressesInUse, FindIndexOfFilter pFilter, const void *const pvFilterData) {
 	assert((0 != pvAddressesInUse) && (0 != pFilter) && (0 != pvFilterData));

	for (size_t i = 0; i < pvAddressesInUse->size(); i++) {
		if (pFilter(pvAddressesInUse->at(i), pvFilterData)) {
			return (int)i;
		}
	}
	return -1;
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
		throw GetIPAddrException("Unable to query IP address table.");
		return infoList;
	}

	const ULONG ulIpAddrTableSizeAllocated = ulIpAddrTableSize;
	BYTE *const pbIpAddrTableBuffer = (BYTE *)LocalAlloc(LMEM_FIXED, ulIpAddrTableSizeAllocated);
	if (nullptr == pbIpAddrTableBuffer) {
		throw GetIPAddrException("Insufficient memory for IP address table.");
		LocalFree(pbIpAddrTableBuffer);
		return infoList;
	}

	dwGetIpAddrTableResult = GetIpAddrTable((MIB_IPADDRTABLE *)pbIpAddrTableBuffer, &ulIpAddrTableSize, FALSE);
	if ((NO_ERROR != dwGetIpAddrTableResult) || (ulIpAddrTableSizeAllocated > ulIpAddrTableSize)) {
		throw GetIPAddrException("Unable to query IP address table.");
		LocalFree(pbIpAddrTableBuffer);
		return infoList;
	}

	const MIB_IPADDRTABLE *const pmiatIpAddrTable = (MIB_IPADDRTABLE *)pbIpAddrTableBuffer;

	for (size_t i = 0; i < pmiatIpAddrTable->dwNumEntries; i++) {
		infoList.push_back(IPAddrInfo{ pmiatIpAddrTable->table[i].dwAddr, pmiatIpAddrTable->table[i].dwMask });
	}

	LocalFree(pbIpAddrTableBuffer);
	return infoList;
}

bool DHCPServer::InitializeDHCPServer(SOCKET *const psServerSocket, const DWORD dwServerAddr, char *const pcsServerHostName, const size_t stServerHostNameLength) {
 	assert((0 != psServerSocket) && (0 != dwServerAddr) && (0 != pcsServerHostName) && (1 <= stServerHostNameLength));

	// Determine server hostname
	if (NO_ERROR != gethostname(pcsServerHostName, (int)stServerHostNameLength)) {
		pcsServerHostName[0] = '\0';
	}

	// Open socket and set broadcast option on it
	*psServerSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (INVALID_SOCKET == *psServerSocket) {
		throw SocketException("Unable to open server socket (port 67).");
		return false;
	}

	SOCKADDR_IN saServerAddress{};
	saServerAddress.sin_family = AF_INET;
	saServerAddress.sin_addr.s_addr = dwServerAddr;  // Already in network byte order
	saServerAddress.sin_port = htons((u_short)DHCP_SERVER_PORT);
	const int iServerAddressSize = sizeof(saServerAddress);
	if (SOCKET_ERROR == bind(*psServerSocket, (SOCKADDR *)(&saServerAddress), iServerAddressSize)) {
		throw SocketException("Unable to bind to server socket (port 67).");
		return false;
	}

	int iBroadcastOption = TRUE;
	if (NO_ERROR == setsockopt(*psServerSocket, SOL_SOCKET, SO_BROADCAST, (char *)(&iBroadcastOption), sizeof(iBroadcastOption))) {
		return true;
	}
	else {
		throw SocketException("Unable to set socket options.");
	}

	return false;
}

bool DHCPServer::FindOptionData(const BYTE bOption, const BYTE *const pbOptions, const int iOptionsSize, const BYTE **const ppbOptionData, unsigned int *const piOptionDataSize) {
 	assert(((0 == iOptionsSize) || (0 != pbOptions)) && (0 != ppbOptionData) && (0 != piOptionDataSize)
		&& (option_PAD != bOption) && (option_END != bOption));
	
	bool bHitEND = false; // RFC 2132
	const BYTE *pbCurrentOption = pbOptions;
	while (((pbCurrentOption - pbOptions) < iOptionsSize) && !bHitEND) {
		const BYTE bCurrentOption = *pbCurrentOption;

		switch (bCurrentOption) {
		case option_PAD:
			pbCurrentOption++;
			break;
		case option_END:
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

bool DHCPServer::GetDHCPMessageType(const BYTE *const pbOptions, const int iOptionsSize, DHCPMessageTypes *const pdhcpmtMessageType) {
 	assert(((0 == iOptionsSize) || (0 != pbOptions)) && (0 != pdhcpmtMessageType));

	const BYTE *pbDHCPMessageTypeData;
	unsigned int iDHCPMessageTypeDataSize;
	if (FindOptionData(option_DHCPMESSAGETYPE, pbOptions, iOptionsSize, &pbDHCPMessageTypeData, &iDHCPMessageTypeDataSize)
		&& (1 == iDHCPMessageTypeDataSize) && (1 <= *pbDHCPMessageTypeData) && (*pbDHCPMessageTypeData <= 8)) {
		*pdhcpmtMessageType = (DHCPMessageTypes)(*pbDHCPMessageTypeData);
		return true;
	}
	return false;
}

void DHCPServer::ProcessDHCPClientRequest(const SOCKET sServerSocket, const char *const pcsServerHostName, const BYTE *const pbData, const int iDataSize, VectorAddressInUseInformation *const pvAddressesInUse, const DWORD dwServerAddr, const DWORD dwMask, const DWORD dwMinAddr, const DWORD dwMaxAddr) {
 	assert((INVALID_SOCKET != sServerSocket) && (0 != pcsServerHostName) && ((0 == iDataSize) || (0 != pbData)) && (0 != pvAddressesInUse) && (0 != dwServerAddr) && (0 != dwMask) && (0 != dwMinAddr) && (0 != dwMaxAddr));

	const BYTE pbDHCPMagicCookie[] = { 99, 130, 83, 99 }; // DHCP magic cookie values
	const char pcsServerName[] = "DHCPLite DHCP Server";

	const DHCPMessage *const pdhcpmRequest = (DHCPMessage *)pbData;
	if ((((sizeof(*pdhcpmRequest) + sizeof(pbDHCPMagicCookie)) <= iDataSize) &&  // Take into account mandatory DHCP magic cookie values in options array (RFC 2131 section 3)
		(op_BOOTREQUEST == pdhcpmRequest->op) &&
		// (pdhcpmRequest->htype) && // Could also validate htype
		(0 == memcmp(pbDHCPMagicCookie, pdhcpmRequest->options, sizeof(pbDHCPMagicCookie))))
		) {
		const BYTE *const pbOptions = pdhcpmRequest->options + sizeof(pbDHCPMagicCookie);
		const int iOptionsSize = iDataSize - (int)sizeof(*pdhcpmRequest) - (int)sizeof(pbDHCPMagicCookie);
		DHCPMessageTypes dhcpmtMessageType;
		if (GetDHCPMessageType(pbOptions, iOptionsSize, &dhcpmtMessageType)) {
			// Determine client host name
			char pcsClientHostName[MAX_HOSTNAME_LENGTH]{};
			pcsClientHostName[0] = '\0';
			const BYTE *pbRequestHostNameData;
			unsigned int iRequestHostNameDataSize;
			if (FindOptionData(option_HOSTNAME, pbOptions, iOptionsSize, &pbRequestHostNameData, &iRequestHostNameDataSize)) {
				const size_t stHostNameCopySize = min(iRequestHostNameDataSize + 1, sizeof(pcsClientHostName));
				_tcsncpy_s(pcsClientHostName, stHostNameCopySize, (char *)pbRequestHostNameData, _TRUNCATE);
			}
			if (('\0' == pcsServerHostName[0]) || (0 != _stricmp(pcsClientHostName, pcsServerHostName))) {
				// Determine client identifier in proper RFC 2131 order (client identifier option then chaddr)
				const BYTE *pbRequestClientIdentifierData;
				unsigned int iRequestClientIdentifierDataSize;
				if (!FindOptionData(option_CLIENTIDENTIFIER, pbOptions, iOptionsSize, &pbRequestClientIdentifierData, &iRequestClientIdentifierDataSize)) {
					pbRequestClientIdentifierData = pdhcpmRequest->chaddr;
					iRequestClientIdentifierDataSize = sizeof(pdhcpmRequest->chaddr);
				}
				// Determine if we've seen this client before
				bool bSeenClientBefore = false;
				DWORD dwClientPreviousOfferAddr = (DWORD)INADDR_BROADCAST;  // Invalid IP address for later comparison
				const ClientIdentifierData cid = { pbRequestClientIdentifierData, (DWORD)iRequestClientIdentifierDataSize };
				const int iIndex = FindIndexOf(pvAddressesInUse, [](const AddressInUseInformation &raiui, const void *const pvFilterData) {
					const ClientIdentifierData *const pcid = (ClientIdentifierData *)pvFilterData;
					assert(0 != pcid);

					return (0 != raiui.dwClientIdentifierSize) && (pcid->dwClientIdentifierSize == raiui.dwClientIdentifierSize)
						&& (0 == memcmp(pcid->pbClientIdentifier, raiui.pbClientIdentifier, pcid->dwClientIdentifierSize));
				}, &cid);
				if (-1 != iIndex) {
					const AddressInUseInformation aiui = pvAddressesInUse->at((size_t)iIndex);
					dwClientPreviousOfferAddr = ValuetoIP(aiui.dwAddrValue);
					bSeenClientBefore = true;
				}
				// Server message handling
				// RFC 2131 section 4.3
				BYTE bDHCPMessageBuffer[sizeof(DHCPMessage) + sizeof(DHCPServerOptions)];
				ZeroMemory(bDHCPMessageBuffer, sizeof(bDHCPMessageBuffer));
				DHCPMessage *const pdhcpmReply = (DHCPMessage *)&bDHCPMessageBuffer;
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
				strncpy_s((char *)(pdhcpmReply->sname), sizeof(pdhcpmReply->sname), pcsServerName, _TRUNCATE);
				// pdhcpmReply->file = 0;
				// pdhcpmReply->options below
				DHCPServerOptions *const pdhcpsoServerOptions = (DHCPServerOptions *)(pdhcpmReply->options);
				CopyMemory(pdhcpsoServerOptions->pbMagicCookie, pbDHCPMagicCookie, sizeof(pdhcpsoServerOptions->pbMagicCookie));
				// DHCP Message Type - RFC 2132 section 9.6
				pdhcpsoServerOptions->pbMessageType[0] = option_DHCPMESSAGETYPE;
				pdhcpsoServerOptions->pbMessageType[1] = 1;
				// pdhcpsoServerOptions->pbMessageType[2] set below
				// IP Address Lease Time - RFC 2132 section 9.2
				pdhcpsoServerOptions->pbLeaseTime[0] = option_IPADDRESSLEASETIME;
				pdhcpsoServerOptions->pbLeaseTime[1] = 4;
				C_ASSERT(sizeof(u_long) == 4);
				*((u_long *)(&(pdhcpsoServerOptions->pbLeaseTime[2]))) = htonl(1 * 60 * 60);  // One hour
				// Subnet Mask - RFC 2132 section 3.3
				pdhcpsoServerOptions->pbSubnetMask[0] = option_SUBNETMASK;
				pdhcpsoServerOptions->pbSubnetMask[1] = 4;
				C_ASSERT(sizeof(u_long) == 4);
				*((u_long *)(&(pdhcpsoServerOptions->pbSubnetMask[2]))) = dwMask;  // Already in network order
				// Server Identifier - RFC 2132 section 9.7
				pdhcpsoServerOptions->pbServerID[0] = option_SERVERIDENTIFIER;
				pdhcpsoServerOptions->pbServerID[1] = 4;
				C_ASSERT(sizeof(u_long) == 4);
				*((u_long *)(&(pdhcpsoServerOptions->pbServerID[2]))) = dwServerAddr;  // Already in network order
				pdhcpsoServerOptions->bEND = option_END;
				bool bSendDHCPMessage = false;
				switch (dhcpmtMessageType) {
				case DHCPMessageType_DISCOVER:
				{
					// RFC 2131 section 4.3.1
					// UNSUPPORTED: Requested IP Address option
					static DWORD dwServerLastOfferAddrValue = IPtoValue(dwMaxAddr);  // Initialize to max to wrap and offer min first
					const DWORD dwMinAddrValue = IPtoValue(dwMinAddr);
					const DWORD dwMaxAddrValue = IPtoValue(dwMaxAddr);
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
						bOfferAddrValueValid = (-1 == FindIndexOf(pvAddressesInUse, [](const AddressInUseInformation &raiui, const void *const pvFilterData) {
							const DWORD *const pdwAddrValue = (DWORD *)pvFilterData;
							return (*pdwAddrValue == raiui.dwAddrValue);
						}, &dwOfferAddrValue));
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

							pvAddressesInUse->push_back(aiuiClientAddress);
							pdhcpmReply->yiaddr = dwOfferAddr;
							pdhcpsoServerOptions->pbMessageType[2] = DHCPMessageType_OFFER;
							bSendDHCPMessage = true;

							MessageCallback_Discover(pcsClientHostName, dwOfferAddr);

							if (bSeenClientBefore) {
							 	assert(0 == LocalFree(aiuiClientAddress.pbClientIdentifier));
							}
						}
						else {
							throw RequestException("Insufficient memory to add client address.");
						}
					}
					else {
						throw RequestException("No more IP addresses available for client.");
					}
				}
				break;
				case DHCPMessageType_REQUEST:
				{
					// RFC 2131 section 4.3.2
					// Determine requested IP address
					DWORD dwRequestedIPAddress = INADDR_BROADCAST;  // Invalid IP address for later comparison
					const BYTE *pbRequestRequestedIPAddressData = 0;
					unsigned int iRequestRequestedIPAddressDataSize = 0;
					if (FindOptionData(option_REQUESTEDIPADDRESS, pbOptions, iOptionsSize, &pbRequestRequestedIPAddressData, &iRequestRequestedIPAddressDataSize) && (sizeof(dwRequestedIPAddress) == iRequestRequestedIPAddressDataSize)) {
						dwRequestedIPAddress = *((DWORD *)pbRequestRequestedIPAddressData);
					}
					// Determine server identifier
					const BYTE *pbRequestServerIdentifierData = 0;
					unsigned int iRequestServerIdentifierDataSize = 0;
					if (FindOptionData(option_SERVERIDENTIFIER, pbOptions, iOptionsSize, &pbRequestServerIdentifierData, &iRequestServerIdentifierDataSize) &&
						(sizeof(dwServerAddr) == iRequestServerIdentifierDataSize) && (dwServerAddr == *((DWORD *)pbRequestServerIdentifierData))) {
						// Response to OFFER
						// DHCPREQUEST generated during SELECTING state
					 	assert(0 == pdhcpmRequest->ciaddr);
						if (bSeenClientBefore) {
							// Already have an IP address for this client - ACK it
							pdhcpsoServerOptions->pbMessageType[2] = DHCPMessageType_ACK;
							// Will set other options below
						}
						else {
							// Haven't seen this client before - NAK it
							pdhcpsoServerOptions->pbMessageType[2] = DHCPMessageType_NAK;
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
								pdhcpsoServerOptions->pbMessageType[2] = DHCPMessageType_ACK;
								// Will set other options below
							}
							else {
								// Haven't seen this client before or requested IP address is invalid
								pdhcpsoServerOptions->pbMessageType[2] = DHCPMessageType_NAK;
								// Will clear invalid options and prepare to send message below
							}
						}
						else {
							assert(!(TEXT("Invalid DHCP message (invalid data).")));
						}
					}
					switch (pdhcpsoServerOptions->pbMessageType[2]) {
					case DHCPMessageType_ACK:
					 	assert(INADDR_BROADCAST != dwClientPreviousOfferAddr);
						pdhcpmReply->ciaddr = dwClientPreviousOfferAddr;
						pdhcpmReply->yiaddr = dwClientPreviousOfferAddr;
						bSendDHCPMessage = true;

						MessageCallback_ACK(pcsClientHostName, dwClientPreviousOfferAddr);
						break;
					case DHCPMessageType_NAK:
						C_ASSERT(0 == option_PAD);
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
						case DHCPMessageType_OFFER:
							// Fall-through
						case DHCPMessageType_ACK:
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
						case DHCPMessageType_NAK:
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
			assert(!(TEXT("Invalid DHCP message (invalid or missing DHCP message type).")));
		}
	}
	else {
		assert(!(TEXT("Invalid DHCP message (failed initial checks).")));
	}
}

bool DHCPServer::ReadDHCPClientRequests(const SOCKET sServerSocket, const char *const pcsServerHostName, VectorAddressInUseInformation *const pvAddressesInUse, const DWORD dwServerAddr, const DWORD dwMask, const DWORD dwMinAddr, const DWORD dwMaxAddr) {
	assert((INVALID_SOCKET != sServerSocket) && (0 != pcsServerHostName) && (0 != pvAddressesInUse) && (0 != dwServerAddr) && (0 != dwMask) && (0 != dwMinAddr) && (0 != dwMaxAddr));

	BYTE *const pbReadBuffer = (BYTE *)LocalAlloc(LMEM_FIXED, MAX_UDP_MESSAGE_SIZE);
	if (0 == pbReadBuffer) {
		throw RequestException("Unable to allocate memory for client datagram read buffer.");
		return false;
	}

	int iLastError = 0;
	assert(WSAENOTSOCK != iLastError);

	while (WSAENOTSOCK != iLastError) {
		SOCKADDR_IN saClientAddress{};
		int iClientAddressSize = sizeof(saClientAddress);
		const int iBytesReceived = recvfrom(sServerSocket, (char *)pbReadBuffer, MAX_UDP_MESSAGE_SIZE, 0, (SOCKADDR *)(&saClientAddress), &iClientAddressSize);
		if (SOCKET_ERROR != iBytesReceived) {
			// assert(DHCP_CLIENT_PORT == ntohs(saClientAddress.sin_port));  // Not always the case
			ProcessDHCPClientRequest(sServerSocket, pcsServerHostName, pbReadBuffer, iBytesReceived, pvAddressesInUse, dwServerAddr, dwMask, dwMinAddr, dwMaxAddr);
		}
		else {
			iLastError = WSAGetLastError();
			if (iLastError != WSAENOTSOCK && iLastError != WSAEINTR)
				throw SocketException("Call to recvfrom returned error.");
		}
	}
	LocalFree(pbReadBuffer);
	return true;
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

bool DHCPServer::Init(const DWORD dwServerAddr) {
	aiuiServerAddress.dwAddrValue = IPtoValue(dwServerAddr);
	aiuiServerAddress.pbClientIdentifier = 0; // Server entry is only entry without a client ID
	aiuiServerAddress.dwClientIdentifierSize = 0;
	vAddressesInUse.push_back(aiuiServerAddress);

	WSADATA wsaData;
	if (NO_ERROR == WSAStartup(MAKEWORD(1, 1), &wsaData)) {
		return InitializeDHCPServer(&sServerSocket, dwServerAddr, pcsServerHostName, sizeof(pcsServerHostName));
	}
	else {
		throw SocketException("Unable to initialize WinSock.");
	}

	return false;
}

void DHCPServer::Start(DHCPConfig config) {
	assert(ReadDHCPClientRequests(sServerSocket, pcsServerHostName, &vAddressesInUse,
		config.addrInfo.address, config.addrInfo.mask, config.minAddr, config.maxAddr));
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
		aiuiServerAddress = vAddressesInUse.at(i);
		if (0 != aiuiServerAddress.pbClientIdentifier) {
			LocalFree(aiuiServerAddress.pbClientIdentifier);
		}
	}

	return true;
}
