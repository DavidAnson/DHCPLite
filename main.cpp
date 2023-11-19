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
		GetIPAddressInformation(&dwServerAddr, &dwMask, &dwMinAddr, &dwMaxAddr);
	}
	catch (GetIPInfoException e) {
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
	if (PushBack(&vAddressesInUse, &aiuiServerAddress)) {
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
	}
	else {
		std::cout << "[Error] Insufficient memory to add server address.\n";
	}

	for (size_t i = 0; i < vAddressesInUse.size(); i++) {
		aiuiServerAddress = vAddressesInUse.at(i);
		if (0 != aiuiServerAddress.pbClientIdentifier) {
			LocalFree(aiuiServerAddress.pbClientIdentifier);
		}
	}

	system("pause");
}
