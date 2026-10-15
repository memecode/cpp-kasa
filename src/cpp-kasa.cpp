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
