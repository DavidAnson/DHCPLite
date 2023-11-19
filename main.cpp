#include "DHCPLite.h"
#include <windows.h>
#include <stdio.h>

SOCKET sServerSocket = INVALID_SOCKET;  // Global to allow ConsoleCtrlHandlerRoutine access to it

BOOL WINAPI ConsoleCtrlHandlerRoutine(DWORD dwCtrlType) {
	if ((CTRL_C_EVENT == dwCtrlType) || (CTRL_BREAK_EVENT == dwCtrlType)) {
		if (INVALID_SOCKET != sServerSocket) {
			VERIFY(0 == closesocket(sServerSocket));
			sServerSocket = INVALID_SOCKET;
		}
		return TRUE;
	}
	return FALSE;
}

void main(int /*argc*/, char ** /*argv*/) {
	OUTPUT((TEXT("DHCPLite")));
	OUTPUT((TEXT("2016-04-02")));
	OUTPUT((TEXT("Copyright (c) 2001-2016 by David Anson (http://dlaa.me/)")));
	OUTPUT((TEXT("")));

	if (!SetConsoleCtrlHandler(ConsoleCtrlHandlerRoutine, TRUE)) {
		OUTPUT_ERROR((TEXT("Unable to set Ctrl-C handler.")));
		system("pause");
		return;
	}

	DWORD dwServerAddr;
	DWORD dwMask;
	DWORD dwMinAddr;
	DWORD dwMaxAddr;
	if (!GetIPAddressInformation(&dwServerAddr, &dwMask, &dwMinAddr, &dwMaxAddr)) {
		system("pause");
		return;
	}
	ASSERT((DWValuetoIP(dwMinAddr) <= DWValuetoIP(dwServerAddr)) && (DWValuetoIP(dwServerAddr) <= DWValuetoIP(dwMaxAddr)));

	VectorAddressInUseInformation vAddressesInUse;
	AddressInUseInformation aiuiServerAddress;
	aiuiServerAddress.dwAddrValue = DWIPtoValue(dwServerAddr);
	aiuiServerAddress.pbClientIdentifier = 0;  // Server entry is only entry without a client ID
	aiuiServerAddress.dwClientIdentifierSize = 0;
	if (PushBack(&vAddressesInUse, &aiuiServerAddress)) {
		WSADATA wsaData;
		if (NO_ERROR == WSAStartup(MAKEWORD(1, 1), &wsaData)) {
			OUTPUT((TEXT("")));
			OUTPUT((TEXT("Server is running...  (Press Ctrl+C to shutdown.)")));
			OUTPUT((TEXT("")));
			char pcsServerHostName[MAX_HOSTNAME_LENGTH];
			if (InitializeDHCPServer(&sServerSocket, dwServerAddr, pcsServerHostName, sizeof(pcsServerHostName))) {
				VERIFY(ReadDHCPClientRequests(sServerSocket, pcsServerHostName, &vAddressesInUse, dwServerAddr, dwMask, dwMinAddr, dwMaxAddr));
				if (INVALID_SOCKET != sServerSocket) {
					VERIFY(NO_ERROR == closesocket(sServerSocket));
					sServerSocket = INVALID_SOCKET;
				}
			}
			VERIFY(NO_ERROR == WSACleanup());
		}
		else {
			OUTPUT_ERROR((TEXT("Unable to initialize WinSock.")));
		}
	}
	else {
		OUTPUT_ERROR((TEXT("Insufficient memory to add server address.")));
	}

	for (size_t i = 0; i < vAddressesInUse.size(); i++) {
		aiuiServerAddress = vAddressesInUse.at(i);
		if (0 != aiuiServerAddress.pbClientIdentifier) {
			VERIFY(0 == LocalFree(aiuiServerAddress.pbClientIdentifier));
		}
	}

	system("pause");
}
