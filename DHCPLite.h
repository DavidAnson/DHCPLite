#pragma once
#include <tchar.h>
#include <vector>
#include <assert.h>
#include <windows.h>

#define ASSERT(e) assert(e)

// Provide a verify macro for all environments
#if !defined(VERIFY)
#if defined(DEBUG) || defined(_DEBUG)
#define VERIFY(e) ASSERT(e)
#else  // defined(DEBUG) || defined(_DEBUG)
#define VERIFY(e) ((void)(e))
#endif  // defined(DEBUG) || defined(_DEBUG)
#endif  // !defined(VERIFY)

// Macro to simplify determining the number of elements in an array (do *not*
// use this macro for pointers)
#define ARRAY_LENGTH(x) (sizeof(x)/sizeof((x)[0]))

const TCHAR ptsCRLF[] = "\r\n";
const TCHAR ptsERRORPrefix[] = "ERROR %d: ";
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
enum op_values {
	op_BOOTREQUEST = 1,
	op_BOOTREPLY = 2,
};
// RFC 2132 section 9.6
enum option_values {
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
enum DHCPMessageTypes {
	DHCPMessageType_DISCOVER = 1,
	DHCPMessageType_OFFER = 2,
	DHCPMessageType_REQUEST = 3,
	DHCPMessageType_DECLINE = 4,
	DHCPMessageType_ACK = 5,
	DHCPMessageType_NAK = 6,
	DHCPMessageType_RELEASE = 7,
	DHCPMessageType_INFORM = 8,
};

struct AddressInUseInformation {
	DWORD dwAddrValue;
	BYTE *pbClientIdentifier;
	DWORD dwClientIdentifierSize;
	// SYSTEMTIME stExpireTime;  // If lease timeouts are needed
};
typedef std::vector<AddressInUseInformation> VectorAddressInUseInformation;

bool GetIPAddressInformation(DWORD *const pdwAddr, DWORD *const pdwMask, DWORD *const pdwMinAddr, DWORD *const pdwMaxAddr);

bool InitializeDHCPServer(SOCKET *const psServerSocket, const DWORD dwServerAddr, char *const pcsServerHostName, const size_t stServerHostNameLength);

bool ReadDHCPClientRequests(const SOCKET sServerSocket, const char *const pcsServerHostName, VectorAddressInUseInformation *const pvAddressesInUse, const DWORD dwServerAddr, const DWORD dwMask, const DWORD dwMinAddr, const DWORD dwMaxAddr);

bool PushBack(VectorAddressInUseInformation *const pvAddressesInUse, const AddressInUseInformation *const paiui);
