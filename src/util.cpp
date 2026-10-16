
// Utility exe for the cpp-kasa library.
// Can discover and interact with Kasa devices on the network.
// Usage:
//   util discover
//   util discover-modern
//   util get <ip|deviceName>
//   util set <ip|deviceName> <on|off>
//   util smart-get <ip|deviceName> <username> <password>
//   util smart-set <ip|deviceName> <username> <password> <on|off>

#include "cpp-kasa/cpp-kasa.h"
#include "lgi/common/Json.h"

#include <iostream>
#include <future>
#include <string>
#include <vector>

namespace
{
	LString PrettyJson(const LString &json)
	{
        LJson j;
        j.SetJson(json);
        return j.GetJson();
	}

	void PrintUsage(const char *name)
	{
		std::cerr << "Usage:\n"
			<< "  " << name << " discover\n"
			<< "  " << name << " discover-modern\n"
			<< "  " << name << " get <ip|deviceName>\n"
			<< "  " << name << " set <ip|deviceName> <on|off>\n"
			<< "  " << name << " smart-get <ip|deviceName> <username> <password>\n"
			<< "  " << name << " smart-set <ip|deviceName> <username> <password> <on|off>\n";
	}

	template<typename Submit>
	bool WaitForStatus(Submit submit, LString &response)
	{
		auto complete = std::make_shared<std::promise<bool>>();
		auto result = complete->get_future();
		if (!submit([&response, complete](bool success, const LString &message)
		{
			response.Set(message.Get(), message.Length());
			complete->set_value(success);
		}))
		{
			std::cerr << "Unable to queue operation\n";
			return false;
		}
		bool success = result.get();
		if (!success)
			std::cerr << response.Get() << '\n';
		return success;
	}
}

int main(int argc, char **argv)
{
	if (argc < 2)
	{
		PrintUsage(argv[0]);
		return 2;
	}

	LKasaProtocol protocol;
	const char *command = argv[1];
	auto printDevice = [](const LKasaDevice &device)
	{
		std::cout << device.Ip.Get() << '\n' << PrettyJson(device.Response).Get() << "\n\n" << std::flush;
	};
	if (strcmp(command, "discover") == 0 && argc == 2)
	{
		LString response;
		return WaitForStatus([&](const LKasaProtocol::TStatusCb &complete)
		{
			return protocol.Discover(printDevice, nullptr, complete);
		}, response) ? 0 : 1;
	}
	if (strcmp(command, "discover-modern") == 0 && argc == 2)
	{
		LString response;
		return WaitForStatus([&](const LKasaProtocol::TStatusCb &complete)
		{
			return protocol.DiscoverModern(printDevice, nullptr, complete);
		}, response) ? 0 : 1;
	}
	if ((strcmp(command, "smart-get") == 0 && argc == 5) ||
		(strcmp(command, "smart-set") == 0 && argc == 6))
	{
		bool isSet = strcmp(command, "smart-set") == 0;
		bool on = false;
		if (isSet)
		{
			if (strcmp(argv[5], "on") == 0)
				on = true;
			else if (strcmp(argv[5], "off") != 0)
			{
				PrintUsage(argv[0]);
				return 2;
			}
		}
		LString response;
		if (!WaitForStatus([&](const LKasaProtocol::TStatusCb &complete)
		{
			return protocol.ConnectSmart(argv[2], argv[3], argv[4], complete);
		}, response))
			return 1;
		bool success = WaitForStatus([&](const LKasaProtocol::TStatusCb &complete)
		{
			return isSet ? protocol.SetDeviceOn(on, complete) : protocol.GetDeviceInfo(complete);
		}, response);
		if (!success)
		{
			return 1;
		}
		std::cout << PrettyJson(response).Get() << '\n';
		return 0;
	}

	if ((strcmp(command, "get") == 0 && argc == 3) ||
		(strcmp(command, "set") == 0 && argc == 4))
	{
		bool isSet = strcmp(command, "set") == 0;
		bool on = false;
		if (isSet)
		{
			if (strcmp(argv[3], "on") == 0)
				on = true;
			else if (strcmp(argv[3], "off") != 0)
			{
				PrintUsage(argv[0]);
				return 2;
			}
		}

		LString response;
		if (!WaitForStatus([&](const LKasaProtocol::TStatusCb &complete)
		{
			return protocol.Connect(argv[2], complete);
		}, response))
			return 1;
		bool success = WaitForStatus([&](const LKasaProtocol::TStatusCb &complete)
		{
			return isSet ? protocol.SetRelayState(on, complete) : protocol.GetSysInfo(complete);
		}, response);
		if (!success)
		{
			return 1;
		}

		std::cout << PrettyJson(response).Get() << '\n';
		return 0;
	}

	PrintUsage(argv[0]);
	return 2;
}

