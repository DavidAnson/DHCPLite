#pragma once
#include <vector>
#include <functional>
#include <assert.h>
#include <windows.h>

class DHCPException : public std::exception {
public:
	DHCPException(const char *Message) : exception(Message, 1) {}
};

class GetIPAddrException : public DHCPException {
public:
	GetIPAddrException(const char *Message) : DHCPException(Message) {}
};

class SocketException : public DHCPException {
public:
	SocketException(const char *Message) : DHCPException(Message) {}
};

class RequestException : public DHCPException {
public:
	RequestException(const char *Message) : DHCPException(Message) {}
};

#define DWIP0(dw) (((dw)>> 0) & 0xff)
#define DWIP1(dw) (((dw)>> 8) & 0xff)
#define DWIP2(dw) (((dw)>>16) & 0xff)
#define DWIP3(dw) (((dw)>>24) & 0xff)
#define DWIPtoValue(dw) ((DWIP0(dw)<<24) | (DWIP1(dw)<<16) | (DWIP2(dw)<<8) | DWIP3(dw))
#define DWValuetoIP(dw) ((DWIP0(dw)<<24) | (DWIP1(dw)<<16) | (DWIP2(dw)<<8) | DWIP3(dw))

const char pcsServerName[] = "DHCPLite DHCP Server";

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
struct ClientIdentifierData {
	const BYTE *pbClientIdentifier;
	DWORD dwClientIdentifierSize;
};

// RFC 2131 section 2
#pragma warning(push)
#pragma warning(disable : 4200)
#pragma pack(push, 1)
struct DHCPMessage {
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
struct DHCPServerOptions {
	BYTE pbMagicCookie[4];
	BYTE pbMessageType[3];
	BYTE pbLeaseTime[6];
	BYTE pbSubnetMask[6];
	BYTE pbServerID[6];
	BYTE bEND;
};
#pragma pack(pop)
#pragma warning(pop)

struct AddressInUseInformation {
	DWORD dwAddrValue;
	BYTE *pbClientIdentifier;
	DWORD dwClientIdentifierSize;
	// SYSTEMTIME stExpireTime;  // If lease timeouts are needed
};
typedef std::vector<AddressInUseInformation> VectorAddressInUseInformation;

struct IPAddrInfo {
	DWORD address;
	DWORD mask;
};

struct DHCPConfig {
	IPAddrInfo addrInfo;
	DWORD minAddr;
	DWORD maxAddr;
};

std::vector<IPAddrInfo> GetIPAddrInfoList();

bool InitializeDHCPServer(SOCKET *const psServerSocket, const DWORD dwServerAddr, char *const pcsServerHostName, const size_t stServerHostNameLength);

bool ReadDHCPClientRequests(const SOCKET sServerSocket, const char *const pcsServerHostName, VectorAddressInUseInformation *const pvAddressesInUse, const DWORD dwServerAddr, const DWORD dwMask, const DWORD dwMinAddr, const DWORD dwMaxAddr);

typedef std::function<void (char *clientHostName, DWORD offerAddr)> MessageCallback;

// Set Discover Message Callback
// Callback Parameter: pcsClientHostName, dwOfferAddr
void SetDiscoverCallback(MessageCallback callback);

// Set Acknowledge Message Callback
// Callback Parameter: pcsClientHostName, dwClientPreviousOfferAddr
void SetACKCallback(MessageCallback callback);

// Set Negative Acknowledgment Message Callback
// Callback Parameter: pcsClientHostName, dwClientPreviousOfferAddr
void SetNAKCallback(MessageCallback callback);

bool Init(const DWORD dwServerAddr);

void Start(DHCPConfig config);

void Close();

bool Cleanup();
