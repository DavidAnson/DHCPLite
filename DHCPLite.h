#pragma once

#include <map>
#include <array>
#include <vector>
#include <string>
#include <functional>
#include <windows.h>

namespace DHCPLite {
	// Maximum size of a UDP datagram (see RFC 768)
	constexpr auto MAX_UDP_MESSAGE_SIZE = 65536 - 8;
	// DHCP constants (see RFC 2131 section 4.1)
	constexpr auto DHCP_SERVER_PORT = 67;
	// DHCP constants (see RFC 2131 section 4.1)
	constexpr auto DHCP_CLIENT_PORT = 68;
	// Broadcast bit for flags field (RFC 2131 section 2)
	constexpr auto BROADCAST_FLAG = 0x80;
	// For display of host name information
	constexpr auto MAX_HOSTNAME_LENGTH = 256;

	class DHCPMessage {
	public:
		enum MessageTypes {
			MsgType_DISCOVER = 1,
			MsgType_OFFER = 2,
			MsgType_REQUEST = 3,
			MsgType_DECLINE = 4,
			MsgType_ACK = 5,
			MsgType_NAK = 6,
			MsgType_RELEASE = 7,
			MsgType_INFORM = 8,
		};
		enum MessageOpValues { // RFC 2131 section 2
			MsgOp_BOOT_REQUEST = 1,
			MsgOp_BOOT_REPLY = 2,
		};
		enum MessageOptionValues { // RFC 2132 section 9.6
			MsgOption_PAD = 0,
			MsgOption_SUBNET_MASK = 1,
			MsgOption_HOSTNAME = 12,
			MsgOption_REQUESTED_ADDRESS = 50,
			MsgOption_ADDRESS_LEASETIME = 51,
			MsgOption_MESSAGE_TYPE = 53,
			MsgOption_SERVERID_ENTIFIER = 54,
			MsgOption_CLIENTID_ENTIFIER = 61,
			MsgOption_END = 255,
		};

	private:
		std::map<BYTE, std::vector<BYTE>> optionList;

		// Get the options and save it into optionList
		size_t SetOptionList(std::vector<BYTE> options);

	public:
		struct MessageBody {		// RFC 2131 section 2
			BYTE op;				// 0: Message opcode/type
			BYTE htype;			  	// 1: Hardware addr type (net/if_types.h)
			BYTE hlen;			  	// 2: Hardware addr length
			BYTE hops;			  	// 3: Number of relay agent hops from client
			DWORD xid;			  	// 4: Transaction ID
			WORD secs;			  	// 8: Seconds since client started looking
			WORD flags;			  	// 10: Flag bits
			DWORD ciaddr;		  	// 12: Client IP address (if already in use)
			DWORD yiaddr;		  	// 16: Client IP address
			DWORD siaddr;		  	// 20: IP address of next server to talk to
			DWORD giaddr;		  	// 24: DHCP relay agent IP address
			BYTE chaddr[16];	  	// 28: Client hardware address
			BYTE sname[64];		  	// 44: Server name
			BYTE file[128];		  	// 108: Boot filename
			DWORD magicCookie;		// 236: Optional parameters (First is MagicCookie)
		} messageBody;

		DHCPMessage();
		DHCPMessage(std::vector<BYTE> data);

		std::vector<BYTE> GetData();
		void SetData(std::vector<BYTE> data);

		std::vector<BYTE> GetOption(MessageOptionValues option);
		void SetOption(MessageOptionValues option, std::vector<BYTE> data);
	};

	class DHCPServer {
	private:
		enum MessageOpValues { // RFC 2131 section 2
			MsgOp_BOOT_REQUEST = 1,
			MsgOp_BOOT_REPLY = 2,
		};
		enum MessageOptionValues { // RFC 2132 section 9.6
			MsgOption_PAD = 0,
			MsgOption_SUBNET_MASK = 1,
			MsgOption_HOSTNAME = 12,
			MsgOption_REQUESTED_ADDRESS = 50,
			MsgOption_ADDRESS_LEASETIME = 51,
			MsgOption_MESSAGE_TYPE = 53,
			MsgOption_SERVERID_ENTIFIER = 54,
			MsgOption_CLIENTID_ENTIFIER = 61,
			MsgOption_END = 255,
		};
		enum MessageTypes {
			MsgType_DISCOVER = 1,
			MsgType_OFFER = 2,
			MsgType_REQUEST = 3,
			MsgType_DECLINE = 4,
			MsgType_ACK = 5,
			MsgType_NAK = 6,
			MsgType_RELEASE = 7,
			MsgType_INFORM = 8,
		};

#pragma warning(push)
#pragma warning(disable : 4200)
#pragma pack(push, 1)
		struct DHCPMessage {		// RFC 2131 section 2
			BYTE op;				// 0: Message opcode/type
			BYTE htype;			  	// 1: Hardware addr type (net/if_types.h)
			BYTE hlen;			  	// 2: Hardware addr length
			BYTE hops;			  	// 3: Number of relay agent hops from client
			DWORD xid;			  	// 4: Transaction ID
			WORD secs;			  	// 8: Seconds since client started looking
			WORD flags;			  	// 10: Flag bits
			DWORD ciaddr;		  	// 12: Client IP address (if already in use)
			DWORD yiaddr;		  	// 16: Client IP address
			DWORD siaddr;		  	// 18: IP address of next server to talk to
			DWORD giaddr;		  	// 20: DHCP relay agent IP address
			BYTE chaddr[16];	  	// 24: Client hardware address
			BYTE sname[64];		  	// 40: Server name
			BYTE file[128];		  	// 104: Boot filename
			BYTE options[];			// 212: Optional parameters
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

	private:
		struct AddressInUseInformation {
			DWORD dwAddrValue;
			BYTE *pbClientIdentifier;
			DWORD dwClientIdentifierSize;
			// SYSTEMTIME stExpireTime; // If lease timeouts are needed
		};
		typedef std::vector<AddressInUseInformation> VectorAddressInUseInformation;

		typedef std::function<bool(const AddressInUseInformation &raiui)> FindIndexOfFilter;

	private:
		SOCKET sServerSocket = INVALID_SOCKET; // Global to allow ConsoleCtrlHandlerRoutine access to it
		VectorAddressInUseInformation vAddressesInUse;
		char pcsServerHostName[MAX_HOSTNAME_LENGTH]{};
		std::string serverName = "DHCPLite DHCP Server";

		int FindIndexOf(const VectorAddressInUseInformation *const pvAddressesInUse, FindIndexOfFilter pFilter);

		bool FindOptionData(const BYTE bOption, const BYTE *const pbOptions, const int iOptionsSize,
			const BYTE **const ppbOptionData, unsigned int *const piOptionDataSize);

		bool InitializeDHCPServer();

		bool GetDHCPMessageType(const BYTE *const pbOptions, const int iOptionsSize,
			MessageTypes *const pdhcpmtMessageType);

		void ProcessDHCPClientRequest(const BYTE *const pbData, const int iDataSize);

		bool ReadDHCPClientRequests();

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
		static DHCPConfig GetDHCPConfig();

	private:
		DHCPConfig config{};

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

		DHCPServer() {}
		DHCPServer(DHCPConfig config);

		bool Init();
		bool Init(DHCPConfig config);

		void Start();

		void Close();

		bool Cleanup();

		bool SetServerName(std::string name);
	};

	class DHCPException : public std::exception {
	public:
		DHCPException(const char *Message) : exception(Message, 1) {}
	};

	class IPAddrException : public DHCPException {
	public:
		IPAddrException(const char *Message) : DHCPException(Message) {}
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
