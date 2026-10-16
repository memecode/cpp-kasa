
// Utility exe for the cpp-kasa library.
// Can discover and interact with Kasa devices on the network.
// Usage:
//   util discover
//   util get <ip|deviceName> [<username> <password>]
//   util set <ip|deviceName> <on|off> [<username> <password>]

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
			<< "  " << name << " get <ip|deviceName> [<username> <password>]\n"
			<< "  " << name << " set <ip|deviceName> <on|off> [<username> <password>]\n";
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
	if ((strcmp(command, "get") == 0 && (argc == 3 || argc == 5)) ||
		(strcmp(command, "set") == 0 && (argc == 4 || argc == 6)))
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
		LKasaDevice device;
		if (!WaitForStatus([&](const LKasaProtocol::TStatusCb &complete)
		{
			return protocol.Discover([&](const LKasaDevice &found)
			{
				device.Ip.Set(found.Ip.Get(), found.Ip.Length());
				device.Response.Set(found.Response.Get(), found.Response.Length());
			}, argv[2], complete);
		}, response))
			return 1;

		LJson metadata;
		metadata.SetJson(device.Response.Get());
		LString deviceType = metadata.Get("result.device_type");
		bool smart = deviceType.Get() && strncmp(deviceType.Get(), "SMART.", 6) == 0;
		int credentialIndex = isSet ? 4 : 3;
		bool hasCredentials = argc == credentialIndex + 2;
		if (smart && !hasCredentials)
		{
			std::cerr << "This device requires a username and password as the final two arguments.\n";
			return 2;
		}
		if (!WaitForStatus([&](const LKasaProtocol::TStatusCb &complete)
		{
			return smart
				? protocol.ConnectSmart(device, argv[credentialIndex], argv[credentialIndex + 1], complete)
				: protocol.Connect(device.Ip.Get(), complete);
		}, response))
			return 1;
		bool success = WaitForStatus([&](const LKasaProtocol::TStatusCb &complete)
		{
			if (smart)
				return isSet ? protocol.SetDeviceOn(on, complete) : protocol.GetDeviceInfo(complete);
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

