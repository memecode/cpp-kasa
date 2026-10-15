#include "cpp-kasa/cpp-kasa.h"
#include "lgi/common/Json.h"

#include <string>

namespace
{
	constexpr uint32_t MaxFrameSize = (uint32_t)LKasaProtocol::MaxMessageSize;
}

LKasaProtocol::LKasaProtocol()
{
}

LKasaProtocol::~LKasaProtocol()
{
	Disconnect();
}

bool LKasaProtocol::Connect(const char *host, int port, int timeoutMs)
{
	Disconnect();
	LastError.Empty();

	if (!host || !*host || port <= 0 || port > 65535)
	{
		LastError.Set(LErrorInvalidParam, "Invalid host or port");
		return false;
	}

	Socket.SetTimeout(timeoutMs);
	if (!Socket.Open(host, port))
	{
		LastError = Socket.GetError();
		if (!LastError)
			LastError.Set(LErrorFuncFailed, Socket.GetErrorString());
		return false;
	}
	return true;
}

void LKasaProtocol::Disconnect()
{
	if (Socket.IsOpen())
		Socket.Close();
}

bool LKasaProtocol::IsConnected() const
{
	return const_cast<LSocket &>(Socket).IsOpen();
}

LError LKasaProtocol::GetLastError() const
{
	return LastError;
}

bool LKasaProtocol::Discover(LArray<LKasaDevice> &devices, const char *targetIp, int timeoutMs)
{
	devices.Length(0);
	LastError.Empty();
	if (timeoutMs <= 0)
	{
		LastError.Set(LErrorInvalidParam, "Discovery timeout must be positive");
		return false;
	}

	LSocket discoverySocket;
	discoverySocket.SetBroadcast(true);
	discoverySocket.SetUdp(true);

	LString probe = "{\"system\":{\"get_sysinfo\":{}}}";
	LString encryptedProbe = XorEncrypt(probe.Get(), probe.Length());
	int sent = 0;
	if (targetIp)
	{
		uint32_t target = LHostnameToIp(targetIp);
		if (!target)
		{
			LastError.Set(LErrorInvalidParam, "Invalid discovery target");
			return false;
		}
		sent = discoverySocket.WriteUdp(encryptedProbe.Get(), (int)encryptedProbe.Length(), 0, target, DefaultPort) > 0;
	}
	else
	{
		LArray<LSocket::Interface> interfaces;
		if (!LSocket::EnumInterfaces(interfaces))
		{
			LastError.Set(LErrorFuncFailed, "Unable to enumerate network interfaces");
			return false;
		}

		LArray<uint32_t> broadcastIps;
		for (auto &interface: interfaces)
		{
			if (!interface.Ip4 || !interface.Netmask4 || interface.IsLoopBack())
				continue;

			uint32_t broadcastIp = interface.Ip4 | ~interface.Netmask4;
			// LSocket treats 255.255.255.255 as its INADDR_ANY sentinel.
			if (broadcastIp == 0xffffffff || broadcastIp == interface.Ip4)
				continue;

			bool duplicate = false;
			for (auto existing: broadcastIps)
				if (existing == broadcastIp)
					duplicate = true;
			if (duplicate)
				continue;

			broadcastIps.New() = broadcastIp;
			if (discoverySocket.WriteUdp(encryptedProbe.Get(), (int)encryptedProbe.Length(), 0,
				broadcastIp, DefaultPort) > 0)
				sent++;
		}
	}

	if (!sent)
	{
		LastError = discoverySocket.GetError();
		if (!LastError)
			LastError.Set(LErrorFuncFailed, "Unable to send discovery probe");
		return false;
	}

	const uint64_t deadline = LCurrentTime() + timeoutMs;
	std::string datagram(65507, '\0');
	while (true)
	{
		uint64_t now = LCurrentTime();
		if (now >= deadline)
			break;

		int waitMs = (int)(deadline - now);
		if (!discoverySocket.IsReadable(waitMs))
			break;

		uint32_t sourceIp = 0;
		uint16_t sourcePort = 0;
		int received = discoverySocket.ReadUdp(datagram.data(), (int)datagram.size(), 0,
			&sourceIp, &sourcePort);
		if (received <= 0 || !sourceIp)
			continue;

		LString plaintext = XorDecrypt(datagram.data(), (size_t)received);
		LJson response;
		if (!response.SetJson(plaintext.Get()))
			continue;

		LString ip = LIpToStr(sourceIp);
		bool duplicate = false;
		for (auto &device: devices)
			if (device.Ip == ip)
				duplicate = true;
		if (duplicate)
			continue;

		auto &device = devices.New();
		device.Ip = ip;
		device.Response = plaintext;
	}

	if (!devices.Length())
	{
		LastError.Set(LErrorTimedOut, "No legacy devices replied before the timeout");
		return false;
	}
	return true;
}

bool LKasaProtocol::WriteAll(const void *data, size_t size)
{
	const auto *bytes = static_cast<const uint8_t *>(data);
	size_t offset = 0;
	while (offset < size)
	{
		auto written = Socket.Write(bytes + offset, (ssize_t)(size - offset));
		if (written <= 0)
		{
			LastError = Socket.GetError();
			if (!LastError)
				LastError.Set(LErrorIoFailed, Socket.GetErrorString());
			return false;
		}
		offset += (size_t)written;
	}
	return true;
}

bool LKasaProtocol::ReadAll(void *data, size_t size)
{
	auto *bytes = static_cast<uint8_t *>(data);
	size_t offset = 0;
	while (offset < size)
	{
		auto received = Socket.Read(bytes + offset, (ssize_t)(size - offset));
		if (received <= 0)
		{
			LastError = Socket.GetError();
			if (!LastError)
				LastError.Set(LErrorIoFailed, Socket.GetErrorString());
			return false;
		}
		offset += (size_t)received;
	}
	return true;
}

namespace
{
	LString TransformXor(const void *data, size_t size, bool decrypt)
	{
		if (!data && size)
			return LString();

		std::string output(size, '\0');
		const auto *bytes = static_cast<const uint8_t *>(data);
		uint8_t state = 0xAB;
		for (size_t i = 0; i < size; i++)
		{
			uint8_t input = bytes[i];
			uint8_t value = input ^ state;
			output[i] = (char)value;
			state = decrypt ? input : value;
		}
		return LString(output.data(), (ssize_t)output.size());
	}
}

LString LKasaProtocol::XorEncrypt(const void *data, size_t size)
{
	return TransformXor(data, size, false);
}

LString LKasaProtocol::XorDecrypt(const void *data, size_t size)
{
	return TransformXor(data, size, true);
}

bool LKasaProtocol::Request(const char *requestJson, LString &responseJson)
{
	responseJson.Empty();
	LastError.Empty();

	if (!Socket.IsOpen())
	{
		LastError.Set(LErrorInvalidParam, "Not connected");
		return false;
	}
	if (!requestJson)
	{
		LastError.Set(LErrorInvalidParam, "Request JSON is null");
		return false;
	}

	LJson request;
	if (!request.SetJson(requestJson))
	{
		LastError.Set(LErrorInvalidParam, "Invalid request JSON");
		return false;
	}

	const size_t requestSize = strlen(requestJson);
	if (!requestSize || requestSize > MaxFrameSize)
	{
		LastError.Set(LErrorInvalidParam, "Request size is outside the supported range");
		return false;
	}

	LString encrypted = XorEncrypt(requestJson, requestSize);
	uint32_t frameSize = (uint32_t)encrypted.Length();
	uint8_t header[4] =
	{
		(uint8_t)(frameSize >> 24),
		(uint8_t)(frameSize >> 16),
		(uint8_t)(frameSize >> 8),
		(uint8_t)frameSize
	};
	if (!WriteAll(header, sizeof(header)) ||
		!WriteAll(encrypted.Get(), (size_t)encrypted.Length()))
	{
		Disconnect();
		return false;
	}

	if (!ReadAll(header, sizeof(header)))
	{
		Disconnect();
		return false;
	}
	frameSize = ((uint32_t)header[0] << 24) |
				((uint32_t)header[1] << 16) |
				((uint32_t)header[2] << 8) |
				(uint32_t)header[3];
	if (!frameSize || frameSize > MaxFrameSize)
	{
		LastError.Set(LErrorFuncFailed, "Response frame size is outside the supported range");
		Disconnect();
		return false;
	}

	std::string encryptedResponse(frameSize, '\0');
	if (!ReadAll(encryptedResponse.data(), encryptedResponse.size()))
	{
		Disconnect();
		return false;
	}

	LString plaintext = XorDecrypt(encryptedResponse.data(), encryptedResponse.size());
	responseJson.Set(plaintext.Get(), plaintext.Length());
	LJson response;
	if (!response.SetJson(responseJson.Get()))
	{
		LastError.Set(LErrorFuncFailed, "Device returned invalid JSON");
		responseJson.Empty();
		Disconnect();
		return false;
	}
	return true;
}

bool LKasaProtocol::GetSysInfo(LString &responseJson)
{
	return Request("{\"system\":{\"get_sysinfo\":{}}}", responseJson);
}

bool LKasaProtocol::SetRelayState(bool on, LString &responseJson)
{
	return on
		? Request("{\"system\":{\"set_relay_state\":{\"state\":1}}}", responseJson)
		: Request("{\"system\":{\"set_relay_state\":{\"state\":0}}}", responseJson);
}
