#pragma once
#include <vector>
#include <string>
#include <functional>
#include <windows.h>

namespace DHCPLite {
	// Maximum size of a UDP datagram (see RFC 768)
	constexpr auto MAX_UDP_MESSAGE_SIZE = 65536 - 8;
	// DHCP constants (see RFC 2131 section 4.1)
	constexpr auto DHCP_SERVER_PORT = 67;
	constexpr auto DHCP_CLIENT_PORT = 68;
	// Broadcast bit for flags field (RFC 2131 section 2)
	constexpr auto BROADCAST_FLAG = 0x80;
	// For display of host name information
	constexpr auto MAX_HOSTNAME_LENGTH = 256;


	class DHCPServer {
	private:
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

		typedef std::function<bool(const AddressInUseInformation &raiui, const void *const pvFilterData)> FindIndexOfFilter;

	private:
		SOCKET sServerSocket = INVALID_SOCKET; // Global to allow ConsoleCtrlHandlerRoutine access to it
		VectorAddressInUseInformation vAddressesInUse;
		AddressInUseInformation aiuiServerAddress{};
		char pcsServerHostName[MAX_HOSTNAME_LENGTH];

		FindIndexOfFilter AddressInUseInformationAddrValueFilter, AddressInUseInformationClientIdentifierFilter;

		int FindIndexOf(const VectorAddressInUseInformation *const pvAddressesInUse, FindIndexOfFilter pFilter, const void *const pvFilterData);

		bool FindOptionData(const BYTE bOption, const BYTE *const pbOptions, const int iOptionsSize, const BYTE **const ppbOptionData, unsigned int *const piOptionDataSize);

		bool GetDHCPMessageType(const BYTE *const pbOptions, const int iOptionsSize, DHCPMessageTypes *const pdhcpmtMessageType);

		void ProcessDHCPClientRequest(const SOCKET sServerSocket, const char *const pcsServerHostName, const BYTE *const pbData, const int iDataSize, VectorAddressInUseInformation *const pvAddressesInUse, const DWORD dwServerAddr, const DWORD dwMask, const DWORD dwMinAddr, const DWORD dwMaxAddr);

		bool ReadDHCPClientRequests(const SOCKET sServerSocket, const char *const pcsServerHostName, VectorAddressInUseInformation *const pvAddressesInUse, const DWORD dwServerAddr, const DWORD dwMask, const DWORD dwMinAddr, const DWORD dwMaxAddr);

		bool InitializeDHCPServer(SOCKET *const psServerSocket, const DWORD dwServerAddr, char *const pcsServerHostName, const size_t stServerHostNameLength);

	public:
		struct IPAddrInfo {
			DWORD address;
			DWORD mask;
		};

		struct DHCPConfig {
			IPAddrInfo addrInfo;
			DWORD minAddr;
			DWORD maxAddr;
		};

		typedef std::function<void(char *clientHostName, DWORD offerAddr)> MessageCallback;

		static DWORD IPtoValue(DWORD ip);
		static DWORD ValuetoIP(DWORD value);

		static std::string IPAddrToString(DWORD address);

		static std::vector<IPAddrInfo> GetIPAddrInfoList();

	private:
		MessageCallback MessageCallback_Discover;
		MessageCallback MessageCallback_ACK;
		MessageCallback MessageCallback_NAK;

	public:
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
	};

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
}
