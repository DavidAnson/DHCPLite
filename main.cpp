#include "DHCPLite.h"
#include <iostream>
#include <windows.h>

using namespace DHCPLite;

std::unique_ptr<DHCPServer> server;

BOOL WINAPI ConsoleCtrlHandlerRoutine(DWORD dwCtrlType) {
	if ((CTRL_C_EVENT == dwCtrlType) || (CTRL_BREAK_EVENT == dwCtrlType)) {
		server->Close();
		std::cout << "Stopping server request handler.\n";

		return TRUE;
	}
	return FALSE;
}

int main(int /*argc*/, char ** /*argv*/) {
	std::cout << "DHCPLite\n2016-04-02\n";
	std::cout << "Copyright (c) 2001-2016 by David Anson (http://dlaa.me/)\n\n";

	server = std::make_unique<DHCPServer>();

	if (!SetConsoleCtrlHandler(ConsoleCtrlHandlerRoutine, TRUE)) {
		std::cout << "[Error] Unable to set Ctrl-C handler.\n";
		system("pause");
		return 1;
	}

	server->SetDiscoverCallback([](char *clientHostName, DWORD offerAddr) {
		std::cout << "Offering client \"" << clientHostName << "\" "
			<< "IP address " << DHCPServer::IPAddrToString(offerAddr) << "\n";
	});

	server->SetACKCallback([](char *clientHostName, DWORD offerAddr) {
		std::cout << "Acknowledging client \"" << clientHostName << "\" "
			<< "has IP address " << DHCPServer::IPAddrToString(offerAddr) << "\n";
	});

	server->SetNAKCallback([](char *clientHostName, DWORD offerAddr) {
		std::cout << "Denying client \"" << clientHostName << "\" unoffered IP address.\n";
	});

	try {
		auto config = DHCPServer::GetDHCPConfig();

		std::cout << "IP Address being used:\n"
			<< DHCPServer::IPAddrToString(config.addrInfo.address)
			<< " - Subnet:" << DHCPServer::IPAddrToString(config.addrInfo.mask)
			<< " - Range:[" << DHCPServer::IPAddrToString(config.minAddr)
			<< "-" << DHCPServer::IPAddrToString(config.maxAddr) << "]\n";

		server->Init(config);
		std::cout << "Server is running...  (Press Ctrl+C to shutdown.)\n";
		server->Start();
	}
	catch (DHCPException e) {
		std::cout << "[Error] " << e.what() << "\n";
	}

	server->Cleanup();

	system("pause");
	return 0;
}
