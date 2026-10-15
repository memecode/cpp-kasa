
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

	void PrintError(const LKasaProtocol &protocol)
	{
		LError error = protocol.GetLastError();
		std::cerr << error.ToString().Get() << '\n';
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
	if (strcmp(command, "discover") == 0 && argc == 2)
	{
		LArray<LKasaDevice> devices;
		if (!protocol.Discover(devices))
		{
			PrintError(protocol);
			return 1;
		}

		for (auto &device: devices)
			std::cout << device.Ip.Get() << '\n' << PrettyJson(device.Response).Get() << "\n\n";
		return 0;
	}
	if (strcmp(command, "discover-modern") == 0 && argc == 2)
	{
		LArray<LKasaDevice> devices;
		if (!protocol.DiscoverModern(devices))
		{
			PrintError(protocol);
			return 1;
		}

		for (auto &device: devices)
			std::cout << device.Ip.Get() << '\n' << PrettyJson(device.Response).Get() << "\n\n";
		return 0;
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
		if (!protocol.ConnectSmart(argv[2], argv[3], argv[4]))
		{
			PrintError(protocol);
			return 1;
		}
		LString response;
		bool success = isSet
			? protocol.SetDeviceOn(on, response)
			: protocol.GetDeviceInfo(response);
		if (!success)
		{
			PrintError(protocol);
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

		if (!protocol.Connect(argv[2]))
		{
			PrintError(protocol);
			return 1;
		}

		LString response;
		bool success = isSet
			? protocol.SetRelayState(on, response)
			: protocol.GetSysInfo(response);
		if (!success)
		{
			PrintError(protocol);
			return 1;
		}

		std::cout << PrettyJson(response).Get() << '\n';
		return 0;
	}

	PrintUsage(argv[0]);
	return 2;
}

