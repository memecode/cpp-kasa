#include "cpp-kasa/cpp-kasa.h"
#include "lgi/common/Json.h"

#include <exception>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

namespace
{
	constexpr uint32_t MaxFrameSize = (uint32_t)LKasaProtocol::MaxMessageSize;
	constexpr uint16_t ModernDiscoveryPorts[] = { 20002, 20004 };

	LError CopyError(LError &source)
	{
		LError copy(source.GetCode(), source.GetMsg().Get());
		copy.SrcFile = source.SrcFile;
		copy.SrcLine = source.SrcLine;
		for (auto &note: source.DevNotes)
			copy.DevNotes.New().Set(note.Get(), note.Length());
		return copy;
	}

	uint32_t Crc32(const char *data, size_t size)
	{
		uint32_t crc = 0xffffffff;
		for (size_t i = 0; i < size; i++)
		{
			crc ^= (uint8_t)data[i];
			for (int bit = 0; bit < 8; bit++)
				crc = (crc >> 1) ^ (0xedb88320 & (uint32_t)-(int32_t)(crc & 1));
		}
		return crc ^ 0xffffffff;
	}

	bool GenerateModernProbe(std::string &packet)
	{
		using PkeyCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
		using Pkey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
		using Bio = std::unique_ptr<BIO, decltype(&BIO_free)>;

		PkeyCtx context(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
		if (!context || EVP_PKEY_keygen_init(context.get()) <= 0 ||
			EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), 2048) <= 0)
			return false;

		EVP_PKEY *generatedKey = nullptr;
		if (EVP_PKEY_keygen(context.get(), &generatedKey) <= 0)
			return false;
		Pkey key(generatedKey, EVP_PKEY_free);

		Bio pem(BIO_new(BIO_s_mem()), BIO_free);
		if (!pem || PEM_write_bio_PUBKEY(pem.get(), key.get()) != 1)
			return false;

		char *pemData = nullptr;
		long pemSize = BIO_get_mem_data(pem.get(), &pemData);
		if (pemSize <= 0 || !pemData)
			return false;

		std::string escapedPem;
		for (long i = 0; i < pemSize; i++)
		{
			if (pemData[i] == '\n')
				escapedPem += "\\n";
			else if (pemData[i] != '\r')
				escapedPem.push_back(pemData[i]);
		}

		std::string body = "{\"params\":{\"rsa_key\":\"" + escapedPem + "\"}}";
		if (body.size() > 0xffff)
			return false;

		packet.assign(16, '\0');
		packet[0] = 2;
		packet[1] = 0;
		packet[2] = 0;
		packet[3] = 1;
		packet[4] = (char)(body.size() >> 8);
		packet[5] = (char)body.size();
		packet[6] = 0x11;
		if (RAND_bytes((unsigned char *)&packet[8], 4) != 1)
			return false;
		packet[12] = 0x5a;
		packet[13] = 0x6b;
		packet[14] = 0x7c;
		packet[15] = (char)0x8d;
		packet += body;

		uint32_t crc = Crc32(packet.data(), packet.size());
		packet[12] = (char)(crc >> 24);
		packet[13] = (char)(crc >> 16);
		packet[14] = (char)(crc >> 8);
		packet[15] = (char)crc;
		return true;
	}
}

int LKasaProtocol::GetTimeout() const
{
	return Timeout.load();
}

bool LKasaProtocol::SetTimeout(int timeoutMs)
{
	if (timeoutMs <= 0)
		return false;
	Timeout.store(timeoutMs);
	return true;
}

void LKasaProtocol::SetCredentials(const char *username, const char *password)
{
	std::lock_guard<std::mutex> lock(StatusMutex);
	Username.Set(username && password ? username : nullptr);
	Password.Set(username && password ? password : nullptr);
}

bool LKasaProtocol::Enqueue(std::function<bool(LString &, int)> operation, TStatusCb onComplete)
{
	std::lock_guard<std::mutex> lock(QueueMutex);
	if (Stopping)
		return false;
	int timeoutMs = GetTimeout();
	Pending.emplace_back([this, operation = std::move(operation), onComplete, timeoutMs]()
	{
		if (CancelState->IsCancelled())
			return;
		LString response;
		bool success = false;
		LastError.Empty();
		try
		{
			ApplyTimeout(timeoutMs);
			success = operation(response, timeoutMs);
		}
		catch (const std::exception &error)
		{
			LastError.Set(LErrorFuncFailed, error.what());
		}
		catch (...)
		{
			LastError.Set(LErrorFuncFailed, "Asynchronous operation threw an exception");
		}
		if (!success)
			response = LastError.ToString();
		{
			std::lock_guard<std::mutex> statusLock(StatusMutex);
			PublishedError = CopyError(LastError);
			Connected = Socket.IsOpen() || HasSmartSession();
		}
		if (onComplete && !CancelState->IsCancelled())
			onComplete(success, response);
	});
	QueueReady.notify_one();
	return true;
}

void LKasaProtocol::WorkerLoop()
{
	while (true)
	{
		std::function<void()> operation;
		{
			std::unique_lock<std::mutex> lock(QueueMutex);
			QueueReady.wait(lock, [this]() { return Stopping || !Pending.empty(); });
			if (Stopping || Pending.empty())
				return;
			operation = std::move(Pending.front());
			Pending.pop_front();
		}
		try
		{
			operation();
		}
		catch (...)
		{
			std::lock_guard<std::mutex> lock(StatusMutex);
			PublishedError.Set(LErrorFuncFailed, "Completion callback threw an exception");
		}
	}
}

bool LKasaProtocol::Connect(const char *host, TStatusCb onComplete, int port)
{
	if (!onComplete)
		return false;
	std::string hostCopy = host ? host : "";
	return Enqueue([=](LString &, int timeoutMs)
	{
		return ConnectSync(hostCopy.c_str(), port, timeoutMs);
	}, onComplete);
}

bool LKasaProtocol::ConnectSync(const char *host, int port, int timeoutMs)
{
	DisconnectSync();
	LastError.Empty();

	if (!host || !*host || port <= 0 || port > 65535 || timeoutMs <= 0)
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
	Enqueue([this](LString &, int)
	{
		DisconnectSync();
		return true;
	}, {});
}

void LKasaProtocol::DisconnectSync()
{
	Socket.Close();
	ClearSmartSession();
}

bool LKasaProtocol::IsConnected() const
{
	std::lock_guard<std::mutex> lock(StatusMutex);
	return Connected;
}

LError LKasaProtocol::GetError() const
{
	std::lock_guard<std::mutex> lock(StatusMutex);
	return CopyError(PublishedError);
}

bool LKasaProtocol::Discover(const TDeviceCb &onDevice, const char *targetIp,
	TStatusCb onComplete)
{
	if (!onDevice)
		return false;
	std::string target = targetIp ? targetIp : "";
	bool directed = targetIp != nullptr;
	return Enqueue([=](LString &, int timeoutMs)
	{
		return DiscoverSync(onDevice, directed ? target.c_str() : nullptr, timeoutMs);
	}, onComplete);
}

bool LKasaProtocol::DiscoverSync(const TDeviceCb &onDevice, const char *targetIp, int timeoutMs)
{
	LastError.Empty();
	if (!onDevice || timeoutMs <= 0)
	{
		LastError.Set(LErrorInvalidParam, "Discovery requires a callback and a positive timeout");
		return false;
	}

	std::mutex callbackMutex;
	LArray<LString> modernIps;
	bool foundDevice = false;
	auto deliver = [&](const LKasaDevice &device, bool modern)
	{
		std::lock_guard<std::mutex> lock(callbackMutex);
		if (CancelState->IsCancelled())
			return;
		for (auto &ip: modernIps)
			if (ip == device.Ip)
				return;
		if (modern)
			modernIps.New() = device.Ip;
		foundDevice = true;
		LKasaDevice discovered = device;
		discovered.isSmart = modern;
		onDevice(discovered);
	};
	LKasaProtocol legacyProtocol;
	LKasaProtocol modernProtocol;
	legacyProtocol.CancelState = CancelState;
	modernProtocol.CancelState = CancelState;
	legacyProtocol.OwnsCancellation = false;
	modernProtocol.OwnsCancellation = false;
	legacyProtocol.Socket.SetCancel(CancelState.get());
	modernProtocol.Socket.SetCancel(CancelState.get());
	bool foundLegacy = false;
	bool foundModern = false;
	LError legacyError;
	LError modernError;
	std::exception_ptr legacyException;
	std::exception_ptr modernException;
	std::thread legacyThread([&]()
	{
		try
		{
			foundLegacy = legacyProtocol.DiscoverLegacySync([&](const LKasaDevice &device)
			{
				deliver(device, false);
			}, targetIp, timeoutMs);
			legacyError = legacyProtocol.LastError;
		}
		catch (...)
		{
			legacyException = std::current_exception();
		}
	});
	std::thread modernThread([&]()
	{
		try
		{
			foundModern = modernProtocol.DiscoverModernSync([&](const LKasaDevice &device)
			{
				deliver(device, true);
			}, targetIp, timeoutMs);
			modernError = modernProtocol.LastError;
		}
		catch (...)
		{
			modernException = std::current_exception();
		}
	});
	legacyThread.join();
	modernThread.join();
	if (legacyException)
		std::rethrow_exception(legacyException);
	if (modernException)
		std::rethrow_exception(modernException);

	if (foundDevice)
	{
		LastError.Empty();
		return true;
	}

	if (!foundModern && modernError.GetCode() != LErrorTimedOut)
		LastError = modernError;
	else if (!foundLegacy)
		LastError = legacyError;
	else
		LastError.Set(LErrorTimedOut, "No devices replied to legacy or modern discovery");
	return false;
}

bool LKasaProtocol::DiscoverLegacySync(const TDeviceCb &onDevice, const char *targetIp, int timeoutMs)
{
	LastError.Empty();
	if (!onDevice || timeoutMs <= 0)
	{
		LastError.Set(LErrorInvalidParam, "Discovery requires a callback and a positive timeout");
		return false;
	}
	LArray<LString> discoveredIps;

	LSocket discoverySocket;
	discoverySocket.SetCancel(CancelState.get());
	discoverySocket.SetBroadcast(true);
	discoverySocket.SetUdp(true);

	LString probe = "{\"system\":{\"get_sysinfo\":{}}}";
	LString encryptedProbe = XorEncrypt(probe.Get(), probe.Length());
	LArray<uint32_t> targets;
	if (targetIp)
	{
		uint32_t target = LHostnameToIp(targetIp);
		if (!target)
		{
			LastError.Set(LErrorInvalidParam, "Invalid discovery target");
			return false;
		}
		targets.New() = target;
	}
	else
	{
		LArray<LSocket::Interface> interfaces;
		if (!LSocket::EnumInterfaces(interfaces))
		{
			LastError.Set(LErrorFuncFailed, "Unable to enumerate network interfaces");
			return false;
		}

		for (auto &interface: interfaces)
		{
			if (!interface.Ip4 || !interface.Netmask4 || interface.IsLoopBack())
				continue;

			uint32_t broadcastIp = interface.Ip4 | ~interface.Netmask4;
			// LSocket treats 255.255.255.255 as its INADDR_ANY sentinel.
			if (broadcastIp == 0xffffffff || broadcastIp == interface.Ip4)
				continue;

			bool duplicate = false;
			for (auto existing: targets)
				if (existing == broadcastIp)
					duplicate = true;
			if (duplicate)
				continue;

			targets.New() = broadcastIp;
		}
	}

	if (!targets.Length())
	{
		LastError.Set(LErrorFuncFailed, "No usable discovery targets found");
		return false;
	}

	int sent = 0;
	const uint64_t start = LCurrentTime();
	const uint64_t deadline = start + (uint64_t)timeoutMs;
	uint64_t nextRound = start;
	int roundsSent = 0;
	std::string datagram(65507, '\0');
	while (!CancelState->IsCancelled())
	{
		uint64_t now = LCurrentTime();
		while (roundsSent < 3 && now >= nextRound)
		{
			for (auto target: targets)
				if (discoverySocket.WriteUdp(encryptedProbe.Get(), (int)encryptedProbe.Length(), 0,
					target, DefaultPort) > 0)
					sent++;
			roundsSent++;
			nextRound = start + ((uint64_t)timeoutMs * roundsSent) / 3;
			now = LCurrentTime();
		}
		if (now >= deadline)
			break;

		uint64_t wakeAt = roundsSent < 3 ? MIN(nextRound, deadline) : deadline;
		int waitMs = (int)(wakeAt > now ? wakeAt - now : 0);
		if (!discoverySocket.IsReadable(MIN(waitMs, 50)))
			continue;

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
		for (auto &existing: discoveredIps)
			if (existing == ip)
				duplicate = true;
		if (duplicate)
			continue;

		discoveredIps.New() = ip;
		LKasaDevice device;
		device.Ip = ip;
		device.Response = plaintext;
		if (!CancelState->IsCancelled())
			onDevice(device);
	}

	if (!sent)
	{
		LastError = discoverySocket.GetError();
		if (!LastError)
			LastError.Set(LErrorFuncFailed, "Unable to send discovery probe");
		return false;
	}
	if (!discoveredIps.Length())
	{
		LastError.Set(LErrorTimedOut, "No legacy devices replied before the timeout");
		return false;
	}
	return true;
}

bool LKasaProtocol::DiscoverModernSync(const TDeviceCb &onDevice, const char *targetIp, int timeoutMs)
{
	LastError.Empty();
	if (!onDevice || timeoutMs <= 0)
	{
		LastError.Set(LErrorInvalidParam, "Discovery requires a callback and a positive timeout");
		return false;
	}
	LArray<LString> discoveredIps;

	std::string probe;
	if (!GenerateModernProbe(probe))
	{
		LastError.Set(LErrorFuncFailed, "Unable to generate modern discovery probe");
		return false;
	}

	LArray<uint32_t> targets;
	if (targetIp)
	{
		uint32_t target = LHostnameToIp(targetIp);
		if (!target)
		{
			LastError.Set(LErrorInvalidParam, "Invalid discovery target");
			return false;
		}
		targets.New() = target;
	}
	else
	{
		LArray<LSocket::Interface> interfaces;
		if (!LSocket::EnumInterfaces(interfaces))
		{
			LastError.Set(LErrorFuncFailed, "Unable to enumerate network interfaces");
			return false;
		}

		for (auto &interface: interfaces)
		{
			if (!interface.Ip4 || !interface.Netmask4 || interface.IsLoopBack())
				continue;
			uint32_t broadcastIp = interface.Ip4 | ~interface.Netmask4;
			if (broadcastIp == 0xffffffff || broadcastIp == interface.Ip4)
				continue;

			bool duplicate = false;
			for (auto existing: targets)
				if (existing == broadcastIp)
					duplicate = true;
			if (!duplicate)
				targets.New() = broadcastIp;
		}
	}
	if (!targets.Length())
	{
		LastError.Set(LErrorFuncFailed, "No usable discovery targets found");
		return false;
	}

	LSocket discoverySocket;
	discoverySocket.SetCancel(CancelState.get());
	discoverySocket.SetBroadcast(true);
	discoverySocket.SetUdp(true);
	int sent = 0;
	const uint64_t start = LCurrentTime();
	const uint64_t deadline = start + (uint64_t)timeoutMs;
	uint64_t nextRound = start;
	int roundsSent = 0;
	std::string datagram(65507, '\0');

	while (!CancelState->IsCancelled())
	{
		uint64_t now = LCurrentTime();
		while (roundsSent < 3 && now >= nextRound)
		{
			for (auto target: targets)
				for (uint16_t port: ModernDiscoveryPorts)
					if (discoverySocket.WriteUdp(probe.data(), (int)probe.size(), 0, target, port) > 0)
						sent++;
			roundsSent++;
			nextRound = start + ((uint64_t)timeoutMs * roundsSent) / 3;
			now = LCurrentTime();
		}
		if (now >= deadline)
			break;

		uint64_t wakeAt = roundsSent < 3 ? MIN(nextRound, deadline) : deadline;
		int waitMs = (int)(wakeAt > now ? wakeAt - now : 0);
		if (!discoverySocket.IsReadable(MIN(waitMs, 50)))
			continue;

		uint32_t sourceIp = 0;
		uint16_t sourcePort = 0;
		int received = discoverySocket.ReadUdp(datagram.data(), (int)datagram.size(), 0,
			&sourceIp, &sourcePort);
		if (received <= 16 || !sourceIp)
			continue;

		LString responseJson;
		responseJson.Set(datagram.data() + 16, received - 16);
		LJson response;
		if (!response.SetJson(responseJson.Get()))
			continue;

		LString ip = LIpToStr(sourceIp);
		bool duplicate = false;
		for (auto &existing: discoveredIps)
			if (existing == ip)
				duplicate = true;
		if (duplicate)
			continue;

		discoveredIps.New() = ip;
		LKasaDevice device;
		device.Ip = ip;
		device.Response = responseJson;
		if (!CancelState->IsCancelled())
			onDevice(device);
	}

	if (!sent)
	{
		LastError = discoverySocket.GetError();
		if (!LastError)
			LastError.Set(LErrorFuncFailed, "Unable to send modern discovery probes");
		return false;
	}
	if (!discoveredIps.Length())
	{
		LastError.Set(LErrorTimedOut, "No modern devices replied before the timeout");
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

bool LKasaProtocol::Request(const char *requestJson, TStatusCb onComplete)
{
	if (!onComplete)
		return false;
	std::string request = requestJson ? requestJson : "";
	bool valid = requestJson != nullptr;
	return Enqueue([=](LString &response, int)
	{
		return RequestSync(valid ? request.c_str() : nullptr, response);
	}, onComplete);
}

bool LKasaProtocol::RequestSync(const char *requestJson, LString &responseJson)
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
		DisconnectSync();
		return false;
	}

	if (!ReadAll(header, sizeof(header)))
	{
		DisconnectSync();
		return false;
	}
	frameSize = ((uint32_t)header[0] << 24) |
				((uint32_t)header[1] << 16) |
				((uint32_t)header[2] << 8) |
				(uint32_t)header[3];
	if (!frameSize || frameSize > MaxFrameSize)
	{
		LastError.Set(LErrorFuncFailed, "Response frame size is outside the supported range");
		DisconnectSync();
		return false;
	}

	std::string encryptedResponse(frameSize, '\0');
	if (!ReadAll(encryptedResponse.data(), encryptedResponse.size()))
	{
		DisconnectSync();
		return false;
	}

	LString plaintext = XorDecrypt(encryptedResponse.data(), encryptedResponse.size());
	responseJson.Set(plaintext.Get(), plaintext.Length());
	LJson response;
	if (!response.SetJson(responseJson.Get()))
	{
		LastError.Set(LErrorFuncFailed, "Device returned invalid JSON");
		responseJson.Empty();
		DisconnectSync();
		return false;
	}
	return true;
}

bool LKasaProtocol::GetSysInfo(TStatusCb onComplete)
{
	return Request("{\"system\":{\"get_sysinfo\":{}}}", onComplete);
}

bool LKasaProtocol::SetRelayState(bool on, TStatusCb onComplete)
{
	return on
		? Request("{\"system\":{\"set_relay_state\":{\"state\":1}}}", onComplete)
		: Request("{\"system\":{\"set_relay_state\":{\"state\":0}}}", onComplete);
}
