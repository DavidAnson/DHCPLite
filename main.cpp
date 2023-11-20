#include "DHCPLite.h"
#include <iostream>
#include <windows.h>

SOCKET sServerSocket = INVALID_SOCKET;  // Global to allow ConsoleCtrlHandlerRoutine access to it

BOOL WINAPI ConsoleCtrlHandlerRoutine(DWORD dwCtrlType) {
	if ((CTRL_C_EVENT == dwCtrlType) || (CTRL_BREAK_EVENT == dwCtrlType)) {
		if (INVALID_SOCKET != sServerSocket) {
			assert(0 == closesocket(sServerSocket));
			sServerSocket = INVALID_SOCKET;
		}
		return TRUE;
	}
	return FALSE;
}

bool GetIPAddrInfo(DWORD *const pdwAddr, DWORD *const pdwMask, DWORD *const pdwMinAddr, DWORD *const pdwMaxAddr) {
	auto addrInfoList = GetIPAddrInfoList();
	if (2 != addrInfoList.size()) {
		std::cout << "Too many or too few IP addresses are present on this machine. [Routing can not be bypassed.]\n";
		return false;
	}

	const bool loopbackAtIndex0 = DWValuetoIP(0x7f000001) == addrInfoList[0].address;
	const bool loopbackAtIndex1 = DWValuetoIP(0x7f000001) == addrInfoList[1].address;
	if (loopbackAtIndex0 == loopbackAtIndex1) {
		std::cout << "Unsupported IP address configuration. [Expected to find loopback address and one other.]\n";
		return false;
	}

	const int tableIndex = loopbackAtIndex1 ? 0 : 1;
	std::cout << "IP Address being used:\n";
	const DWORD dwAddr = addrInfoList[tableIndex].address;
	if (0 == dwAddr) {
		std::cout << "IP Address is 0.0.0.0 - no network is available on this machine. [APIPA (Auto-IP) may not have assigned an IP address yet.]\n";
		return false;
	}

	const DWORD dwMask = addrInfoList[tableIndex].mask;
	const DWORD dwAddrValue = DWIPtoValue(dwAddr);
	const DWORD dwMaskValue = DWIPtoValue(dwMask);
	const DWORD dwMinAddrValue = ((dwAddrValue & dwMaskValue) | 2);  // Skip x.x.x.1 (default router address)
	const DWORD dwMaxAddrValue = ((dwAddrValue & dwMaskValue) | (~(dwMaskValue | 1)));
	const DWORD dwMinAddr = DWValuetoIP(dwMinAddrValue);
	const DWORD dwMaxAddr = DWValuetoIP(dwMaxAddrValue);

	printf("%d.%d.%d.%d - Subnet:%d.%d.%d.%d - Range:[%d.%d.%d.%d-%d.%d.%d.%d]\n",
		DWIP0(dwAddr), DWIP1(dwAddr), DWIP2(dwAddr), DWIP3(dwAddr),
		DWIP0(dwMask), DWIP1(dwMask), DWIP2(dwMask), DWIP3(dwMask),
		DWIP0(dwMinAddr), DWIP1(dwMinAddr), DWIP2(dwMinAddr), DWIP3(dwMinAddr),
		DWIP0(dwMaxAddr), DWIP1(dwMaxAddr), DWIP2(dwMaxAddr), DWIP3(dwMaxAddr));

	if (dwMinAddrValue > dwMaxAddrValue) {
		std::cout << "No network is available on this machine. [The subnet mask is incorrect.]\n";
		return false;
	}

	*pdwAddr = dwAddr;
	*pdwMask = dwMask;
	*pdwMinAddr = dwMinAddr;
	*pdwMaxAddr = dwMaxAddr;

	return true;
}

void main(int /*argc*/, char ** /*argv*/) {
	std::cout << "DHCPLite\n2016-04-02\n";
	std::cout << "Copyright (c) 2001-2016 by David Anson (http://dlaa.me/)\n\n";

	if (!SetConsoleCtrlHandler(ConsoleCtrlHandlerRoutine, TRUE)) {
		std::cout << "[Error] Unable to set Ctrl-C handler.\n";
		system("pause");
		return;
	}

	DWORD dwServerAddr;
	DWORD dwMask;
	DWORD dwMinAddr;
	DWORD dwMaxAddr;
	try {
		if (!GetIPAddrInfo(&dwServerAddr, &dwMask, &dwMinAddr, &dwMaxAddr)) {
			system("pause");
			return;
		}
	}
	catch (GetIPAddrException e) {
		std::cout << e.what() << "\n";
		system("pause");
		return;
	}
	assert((DWValuetoIP(dwMinAddr) <= DWValuetoIP(dwServerAddr)) && (DWValuetoIP(dwServerAddr) <= DWValuetoIP(dwMaxAddr)));

	VectorAddressInUseInformation vAddressesInUse;
	AddressInUseInformation aiuiServerAddress;
	aiuiServerAddress.dwAddrValue = DWIPtoValue(dwServerAddr);
	aiuiServerAddress.pbClientIdentifier = 0;  // Server entry is only entry without a client ID
	aiuiServerAddress.dwClientIdentifierSize = 0;
	vAddressesInUse.push_back(aiuiServerAddress);
	
	WSADATA wsaData;
	if (NO_ERROR == WSAStartup(MAKEWORD(1, 1), &wsaData)) {
		std::cout << "Server is running...  (Press Ctrl+C to shutdown.)\n";

		char pcsServerHostName[MAX_HOSTNAME_LENGTH];
		if (InitializeDHCPServer(&sServerSocket, dwServerAddr, pcsServerHostName, sizeof(pcsServerHostName))) {
			assert(ReadDHCPClientRequests(sServerSocket, pcsServerHostName, &vAddressesInUse, dwServerAddr, dwMask, dwMinAddr, dwMaxAddr));
			if (INVALID_SOCKET != sServerSocket) {
				assert(NO_ERROR == closesocket(sServerSocket));
				sServerSocket = INVALID_SOCKET;
			}
		}
		assert(NO_ERROR == WSACleanup());
	}
	else {
		std::cout << "[Error] Unable to initialize WinSock.\n";
	}

	for (size_t i = 0; i < vAddressesInUse.size(); i++) {
		aiuiServerAddress = vAddressesInUse.at(i);
		if (0 != aiuiServerAddress.pbClientIdentifier) {
			LocalFree(aiuiServerAddress.pbClientIdentifier);
		}
	}

	system("pause");
}
