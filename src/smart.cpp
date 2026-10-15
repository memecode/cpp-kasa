#include "cpp-kasa/cpp-kasa.h"
#include "lgi/common/Http.h"
#include "lgi/common/Json.h"

#include <chrono>
#include <cctype>
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

struct LKasaSmartSession
{
	enum class Transport
	{
		Aes,
		KlapV1,
		KlapV2
	};

	Transport Type = Transport::Aes;
	std::string Host;
	std::string Cookie;
	std::string Token;
	std::string TerminalUuid;
	std::string Key;
	std::string Iv;
	std::string IvPrefix;
	std::string SignaturePrefix;
	int Port = 80;
	int LoginVersion = 1;
	int64_t Sequence = 0;
	int TimeoutMs = 5000;
};

namespace
{
	using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
	using PkeyContextPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
	using CipherContextPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

	std::string ToStdString(const LString &value)
	{
		return value.Get() ? std::string(value.Get(), (size_t)value.Length()) : std::string();
	}

	bool DigestBytes(const EVP_MD *algorithm, const std::string &input, std::string &digest)
	{
		unsigned char buffer[EVP_MAX_MD_SIZE];
		unsigned int size = 0;
		if (EVP_Digest(input.data(), input.size(), buffer, &size, algorithm, nullptr) != 1)
			return false;
		digest.assign((const char *)buffer, size);
		return true;
	}

	std::string HexLower(const std::string &data)
	{
		static const char digits[] = "0123456789abcdef";
		std::string result(data.size() * 2, '\0');
		for (size_t i = 0; i < data.size(); i++)
		{
			uint8_t value = (uint8_t)data[i];
			result[i * 2] = digits[value >> 4];
			result[i * 2 + 1] = digits[value & 0x0f];
		}
		return result;
	}

	std::string Base64Encode(const std::string &data)
	{
		if (data.size() > INT_MAX)
			return std::string();
		std::vector<unsigned char> output(4 * ((data.size() + 2) / 3) + 1);
		int size = EVP_EncodeBlock(output.data(), (const unsigned char *)data.data(), (int)data.size());
		return size >= 0 ? std::string((const char *)output.data(), (size_t)size) : std::string();
	}

	bool Base64Decode(const std::string &data, std::string &decoded)
	{
		if (data.empty() || data.size() > INT_MAX || data.size() % 4)
			return false;
		std::vector<unsigned char> output((data.size() / 4) * 3);
		int size = EVP_DecodeBlock(output.data(), (const unsigned char *)data.data(), (int)data.size());
		if (size < 0)
			return false;
		if (data.back() == '=') size--;
		if (data.size() > 1 && data[data.size() - 2] == '=') size--;
		decoded.assign((const char *)output.data(), (size_t)size);
		return true;
	}

	bool AesCrypt(bool encrypt, const std::string &key, const std::string &iv,
		const std::string &input, std::string &output)
	{
		if (key.size() != 16 || iv.size() != 16 || input.size() > INT_MAX)
			return false;
		CipherContextPtr context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
		if (!context)
			return false;

		int ok = encrypt
			? EVP_EncryptInit_ex(context.get(), EVP_aes_128_cbc(), nullptr,
				(const unsigned char *)key.data(), (const unsigned char *)iv.data())
			: EVP_DecryptInit_ex(context.get(), EVP_aes_128_cbc(), nullptr,
				(const unsigned char *)key.data(), (const unsigned char *)iv.data());
		if (ok != 1)
			return false;

		output.resize(input.size() + EVP_MAX_BLOCK_LENGTH);
		int firstSize = 0;
		int finalSize = 0;
		ok = encrypt
			? EVP_EncryptUpdate(context.get(), (unsigned char *)output.data(), &firstSize,
				(const unsigned char *)input.data(), (int)input.size())
			: EVP_DecryptUpdate(context.get(), (unsigned char *)output.data(), &firstSize,
				(const unsigned char *)input.data(), (int)input.size());
		if (ok != 1)
			return false;
		ok = encrypt
			? EVP_EncryptFinal_ex(context.get(), (unsigned char *)output.data() + firstSize, &finalSize)
			: EVP_DecryptFinal_ex(context.get(), (unsigned char *)output.data() + firstSize, &finalSize);
		if (ok != 1)
			return false;
		output.resize((size_t)(firstSize + finalSize));
		return true;
	}

	bool GenerateRsaKey(int bits, PkeyPtr &key)
	{
		PkeyContextPtr context(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
		if (!context || EVP_PKEY_keygen_init(context.get()) <= 0 ||
			EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), bits) <= 0)
			return false;
		EVP_PKEY *generated = nullptr;
		if (EVP_PKEY_keygen(context.get(), &generated) <= 0)
			return false;
		key.reset(generated);
		return true;
	}

	bool PublicKeyBase64(EVP_PKEY *key, std::string &encoded)
	{
		int size = i2d_PUBKEY(key, nullptr);
		if (size <= 0)
			return false;
		std::vector<unsigned char> der((size_t)size);
		unsigned char *cursor = der.data();
		if (i2d_PUBKEY(key, &cursor) != size)
			return false;
		encoded = Base64Encode(std::string((const char *)der.data(), der.size()));
		return !encoded.empty();
	}

	bool RsaDecrypt(EVP_PKEY *key, const std::string &ciphertext, std::string &plaintext)
	{
		PkeyContextPtr context(EVP_PKEY_CTX_new(key, nullptr), EVP_PKEY_CTX_free);
		if (!context || EVP_PKEY_decrypt_init(context.get()) <= 0 ||
			EVP_PKEY_CTX_set_rsa_padding(context.get(), RSA_PKCS1_PADDING) <= 0)
			return false;
		size_t size = 0;
		if (EVP_PKEY_decrypt(context.get(), nullptr, &size,
			(const unsigned char *)ciphertext.data(), ciphertext.size()) <= 0)
			return false;
		plaintext.resize(size);
		if (EVP_PKEY_decrypt(context.get(), (unsigned char *)plaintext.data(), &size,
			(const unsigned char *)ciphertext.data(), ciphertext.size()) <= 0)
			return false;
		plaintext.resize(size);
		return true;
	}

	std::string SessionCookie(const std::string &headers)
	{
		size_t start = 0;
		while (start < headers.size())
		{
			size_t end = headers.find('\n', start);
			if (end == std::string::npos)
				end = headers.size();
			std::string line = headers.substr(start, end - start);
			start = end + 1;
			if (!line.empty() && line.back() == '\r')
				line.pop_back();
			auto colon = line.find(':');
			if (colon == std::string::npos)
				continue;
			std::string name = line.substr(0, colon);
			for (char &c: name) c = (char)std::tolower((unsigned char)c);
			if (name != "set-cookie")
				continue;

			std::string value = line.substr(colon + 1);
			while (!value.empty() && std::isspace((unsigned char)value.front())) value.erase(value.begin());
			auto semicolon = value.find(';');
			if (semicolon != std::string::npos)
				value.resize(semicolon);
			auto equals = value.find('=');
			if (equals == std::string::npos)
				continue;
			std::string cookieName = value.substr(0, equals);
			if (cookieName == "TP_SESSIONID" || cookieName == "SESSIONID")
				return "TP_SESSIONID=" + value.substr(equals + 1);
		}
		return std::string();
	}

	bool HttpPost(const std::string &host, int port, const std::string &path,
		const std::string &body, const std::string &cookie, int timeoutMs,
		int &status, std::string &responseBody, std::string &responseHeaders, LError &error,
		const char *contentType = "application/json", bool requestByApp = true)
	{
		LHttp http;
		LAutoPtr<LSocketI> socket(new LSocket);
		if (!socket)
		{
			error.Set(LErrorNoMem, "Unable to allocate HTTP socket");
			return false;
		}
		socket->SetTimeout(timeoutMs);
		if (!http.Open(socket, host.c_str(), port))
		{
			error = http.GetError();
			if (!error)
				error.Set(LErrorFuncFailed, "Unable to open HTTP connection");
			return false;
		}

		LStringPipe request;
		LStringPipe response;
		LStringPipe headers;
		if (!body.empty() && request.Write(body.data(), (ssize_t)body.size()) != (ssize_t)body.size())
		{
			error.Set(LErrorNoMem, "Unable to buffer HTTP request body");
			return false;
		}

		std::string requestHeaders = "Content-Type: " + std::string(contentType) +
			"\r\nAccept: application/json\r\n";
		if (requestByApp)
			requestHeaders += "requestByApp: true\r\n";
		requestHeaders += "Content-Length: " + std::to_string(body.size()) + "\r\n";
		if (!cookie.empty())
			requestHeaders += "Cookie: " + cookie + "\r\n";
		std::string uri = "http://" + host + ":" + std::to_string(port) + path;
		status = 0;
		bool ok = http.Post(uri.data(), body.empty() ? nullptr : &request, &status,
			&response, &headers, requestHeaders.c_str());
		if (!ok)
		{
			error = http.GetError();
			if (!error)
				error.Set(LErrorIoFailed, "HTTP POST failed");
			return false;
		}
		responseBody = ToStdString(response.NewLStr());
		responseHeaders = ToStdString(headers.NewLStr());
		return true;
	}

	bool CheckSmartJson(const std::string &text, LError &error)
	{
		LJson response;
		if (!response.SetJson(text.c_str()))
		{
			error.Set(LErrorFuncFailed, "Device returned invalid SMART JSON");
			return false;
		}
		LString errorCode = response.Get("error_code");
		int code = errorCode ? atoi(errorCode.Get()) : 0;
		if (code != 0)
		{
			LString message = response.Get("msg");
			if (!message)
				message = response.Get("error_msg");
			error.Set(code, message ? message.Get() : "SMART command failed");
			return false;
		}
		return true;
	}

	int64_t CurrentTimeMillis()
	{
		return std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::system_clock::now().time_since_epoch()).count();
	}

	std::string BuildSmartRequest(const std::string &method, const std::string &terminalUuid,
		const char *paramsJson)
	{
		std::string request = "{\"method\":\"" + method + "\"";
		if (paramsJson)
			request += ",\"params\":" + std::string(paramsJson);
		request += ",\"request_time_milis\":" + std::to_string(CurrentTimeMillis());
		request += ",\"terminal_uuid\":\"" + terminalUuid + "\"}";
		return request;
	}

	std::string UrlEncode(const std::string &value)
	{
		static const char hex[] = "0123456789ABCDEF";
		std::string encoded;
		for (unsigned char c: value)
		{
			if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
				encoded.push_back((char)c);
			else
			{
				encoded.push_back('%');
				encoded.push_back(hex[c >> 4]);
				encoded.push_back(hex[c & 0x0f]);
			}
		}
		return encoded;
	}

	bool AesPassthrough(LKasaSmartSession &session, const std::string &inner,
		std::string &result, LError &error)
	{
		std::string ciphertext;
		if (!AesCrypt(true, session.Key, session.Iv, inner, ciphertext))
		{
			error.Set(LErrorFuncFailed, "AES request encryption failed");
			return false;
		}
		std::string outer = "{\"method\":\"securePassthrough\",\"params\":{\"request\":\"" +
			Base64Encode(ciphertext) + "\"}}";
		std::string path = "/app";
		if (!session.Token.empty())
			path += "?token=" + UrlEncode(session.Token);

		int status = 0;
		std::string responseBody, responseHeaders;
		if (!HttpPost(session.Host, session.Port, path, outer, session.Cookie,
			session.TimeoutMs, status, responseBody, responseHeaders, error))
			return false;
		std::string cookie = SessionCookie(responseHeaders);
		if (!cookie.empty())
			session.Cookie = cookie;
		if (status != 200)
		{
			error.Set(LErrorFuncFailed, LString::Fmt("SMART HTTP request failed with status %i", status));
			return false;
		}

		LJson outerResponse;
		if (!outerResponse.SetJson(responseBody.c_str()))
		{
			error.Set(LErrorFuncFailed, "Device returned invalid secure-passthrough JSON");
			return false;
		}
		LString outerCode = outerResponse.Get("error_code");
		int code = outerCode ? atoi(outerCode.Get()) : 0;
		if (code != 0)
		{
			error.Set(code, "SMART secure-passthrough request failed");
			return false;
		}
		std::string response = ToStdString(outerResponse.Get("result.response"));
		auto first = response.find_first_not_of(" \t\r\n");
		if (first != std::string::npos && response[first] == '{')
			result = response;
		else
		{
			std::string encrypted, plaintext;
			if (!Base64Decode(response, encrypted) || !AesCrypt(false, session.Key, session.Iv, encrypted, plaintext))
			{
				error.Set(LErrorFuncFailed, "Unable to decrypt SMART response");
				return false;
			}
			result = plaintext;
		}
		return CheckSmartJson(result, error);
	}

	bool ConnectAes(LKasaSmartSession &session, const char *username,
		const char *password, LError &error)
	{
		PkeyPtr privateKey(nullptr, EVP_PKEY_free);
		std::string publicKey;
		if (!GenerateRsaKey(1024, privateKey) || !PublicKeyBase64(privateKey.get(), publicKey))
		{
			error.Set(LErrorFuncFailed, "Unable to generate AES handshake key");
			return false;
		}
		std::string pem = "-----BEGIN PUBLIC KEY-----\\n" + publicKey + "\\n-----END PUBLIC KEY-----\\n";
		std::string handshake = "{\"method\":\"handshake\",\"params\":{\"key\":\"" + pem + "\"}}";
		int status = 0;
		std::string body, headers;
		if (!HttpPost(session.Host, session.Port, "/app", handshake, "", session.TimeoutMs,
			status, body, headers, error))
			return false;
		if (status != 200)
		{
			error.Set(LErrorFuncFailed, LString::Fmt("AES handshake failed with HTTP status %i", status));
			return false;
		}
		LJson reply;
		if (!reply.SetJson(body.c_str()) || !CheckSmartJson(body, error))
			return false;
		std::string encryptedKey;
		if (!Base64Decode(ToStdString(reply.Get("result.key")), encryptedKey) ||
			!RsaDecrypt(privateKey.get(), encryptedKey, session.Key) || session.Key.size() != 32)
		{
			error.Set(LErrorFuncFailed, "Unable to decrypt AES session key");
			return false;
		}
		session.Iv.assign(session.Key.data() + 16, 16);
		session.Key.resize(16);
		session.Cookie = SessionCookie(headers);

		std::string digest;
		if (!DigestBytes(EVP_sha1(), username, digest))
		{
			error.Set(LErrorFuncFailed, "Unable to hash SMART username");
			return false;
		}
		std::string encodedUsername = Base64Encode(HexLower(digest));
		std::string passwordValue;
		std::string passwordField = "password";
		if (session.LoginVersion >= 2)
		{
			if (!DigestBytes(EVP_sha1(), password, digest))
			{
				error.Set(LErrorFuncFailed, "Unable to hash SMART password");
				return false;
			}
			passwordValue = Base64Encode(HexLower(digest));
			passwordField = "password2";
		}
		else
			passwordValue = Base64Encode(password);

		std::string login = "{\"method\":\"login_device\",\"params\":{\"username\":\"" +
			encodedUsername + "\",\"" + passwordField + "\":\"" + passwordValue +
			"\"},\"request_time_milis\":" + std::to_string(CurrentTimeMillis()) + "}";
		std::string loginReply;
		if (!AesPassthrough(session, login, loginReply, error))
			return false;
		LJson loginJson;
		if (!loginJson.SetJson(loginReply.c_str()))
		{
			error.Set(LErrorFuncFailed, "Device returned invalid login JSON");
			return false;
		}
		session.Token = ToStdString(loginJson.Get("result.token"));
		if (session.Token.empty())
		{
			error.Set(LErrorFuncFailed, "SMART login response did not contain a token");
			return false;
		}
		return true;
	}

	bool ConnectKlap(LKasaSmartSession &session, const char *username,
		const char *password, LError &error)
	{
		std::string clientSeed(16, '\0');
		if (RAND_bytes((unsigned char *)clientSeed.data(), (int)clientSeed.size()) != 1)
		{
			error.Set(LErrorFuncFailed, "Unable to generate KLAP client seed");
			return false;
		}

		std::string userHash, passwordHash, authHash;
		if (session.Type == LKasaSmartSession::Transport::KlapV1)
		{
			if (!DigestBytes(EVP_md5(), username, userHash) ||
				!DigestBytes(EVP_md5(), password, passwordHash) ||
				!DigestBytes(EVP_md5(), userHash + passwordHash, authHash))
			{
				error.Set(LErrorFuncFailed, "Unable to compute KLAP v1 authentication hash");
				return false;
			}
		}
		else
		{
			if (!DigestBytes(EVP_sha1(), username, userHash) ||
				!DigestBytes(EVP_sha1(), password, passwordHash) ||
				!DigestBytes(EVP_sha256(), userHash + passwordHash, authHash))
			{
				error.Set(LErrorFuncFailed, "Unable to compute KLAP v2 authentication hash");
				return false;
			}
		}

		int status = 0;
		std::string serverReply, headers;
		if (!HttpPost(session.Host, session.Port, "/app/handshake1", clientSeed, "",
			session.TimeoutMs, status, serverReply, headers, error, "application/octet-stream", false))
			return false;
		if (status != 200 || serverReply.size() != 48)
		{
			error.Set(LErrorFuncFailed, "Invalid KLAP handshake1 response");
			return false;
		}
		std::string serverSeed = serverReply.substr(0, 16);
		std::string serverProof = serverReply.substr(16, 32);
		session.Cookie = SessionCookie(headers);
		if (session.Cookie.empty())
		{
			error.Set(LErrorFuncFailed, "KLAP handshake did not return a session cookie");
			return false;
		}

		std::string proofInput = clientSeed;
		if (session.Type == LKasaSmartSession::Transport::KlapV2)
			proofInput += serverSeed;
		proofInput += authHash;
		std::string expectedProof;
		if (!DigestBytes(EVP_sha256(), proofInput, expectedProof) ||
			CRYPTO_memcmp(expectedProof.data(), serverProof.data(), 32) != 0)
		{
			error.Set(LErrorFuncFailed, "KLAP server proof validation failed");
			return false;
		}

		proofInput = serverSeed;
		if (session.Type == LKasaSmartSession::Transport::KlapV2)
			proofInput += clientSeed;
		proofInput += authHash;
		std::string clientProof;
		if (!DigestBytes(EVP_sha256(), proofInput, clientProof))
		{
			error.Set(LErrorFuncFailed, "Unable to compute KLAP client proof");
			return false;
		}
		std::string handshake2Reply, handshake2Headers;
		if (!HttpPost(session.Host, session.Port, "/app/handshake2", clientProof, session.Cookie,
			session.TimeoutMs, status, handshake2Reply, handshake2Headers, error,
			"application/octet-stream", false))
			return false;
		if (status != 200)
		{
			error.Set(LErrorFuncFailed, LString::Fmt("KLAP handshake2 failed with HTTP status %i", status));
			return false;
		}
		std::string updatedCookie = SessionCookie(handshake2Headers);
		if (!updatedCookie.empty())
			session.Cookie = updatedCookie;

		std::string seed = clientSeed + serverSeed + authHash;
		std::string keyDigest, ivDigest, signatureDigest;
		if (!DigestBytes(EVP_sha256(), "lsk" + seed, keyDigest) ||
			!DigestBytes(EVP_sha256(), "iv" + seed, ivDigest) ||
			!DigestBytes(EVP_sha256(), "ldk" + seed, signatureDigest))
		{
			error.Set(LErrorFuncFailed, "Unable to derive KLAP session keys");
			return false;
		}
		session.Key.assign(keyDigest.data(), 16);
		session.IvPrefix.assign(ivDigest.data(), 12);
		session.SignaturePrefix.assign(signatureDigest.data(), 28);
		uint32_t sequenceBits = ((uint32_t)(uint8_t)ivDigest[28] << 24) |
			((uint32_t)(uint8_t)ivDigest[29] << 16) |
			((uint32_t)(uint8_t)ivDigest[30] << 8) | (uint8_t)ivDigest[31];
		session.Sequence = sequenceBits & 0x80000000
			? (int64_t)sequenceBits - 0x100000000LL
			: (int64_t)sequenceBits;
		return true;
	}
}

LKasaProtocol::LKasaProtocol()
{
}

LKasaProtocol::~LKasaProtocol()
{
	Disconnect();
}

void LKasaProtocol::ClearSmartSession()
{
	Smart.reset();
}

bool LKasaProtocol::HasSmartSession() const
{
	return Smart != nullptr;
}

bool LKasaProtocol::ConnectSmart(const LKasaDevice &device, const char *username,
	const char *password, int timeoutMs)
{
	Disconnect();
	LastError.Empty();
	if (!username || !password || timeoutMs <= 0 || !device.Ip || !device.Response)
	{
		LastError.Set(LErrorInvalidParam, "Device metadata, credentials, and a positive timeout are required");
		return false;
	}

	LJson discovery;
	if (!discovery.SetJson(device.Response.Get()))
	{
		LastError.Set(LErrorInvalidParam, "Invalid device discovery JSON");
		return false;
	}
	std::string deviceType = ToStdString(discovery.Get("result.device_type"));
	if (deviceType.find("SMART.") != 0 || deviceType.find("CAMERA") != std::string::npos ||
		deviceType.find("ROBOVAC") != std::string::npos)
	{
		LastError.Set(LErrorNotSupported, "Only standard SMART switches are currently supported");
		return false;
	}

	std::string encryption = ToStdString(discovery.Get("result.mgt_encrypt_schm.encrypt_type"));
	if (encryption.empty())
		encryption = ToStdString(discovery.Get("result.encrypt_info.sym_schm"));
	if (encryption != "AES" && encryption != "KLAP")
	{
		LastError.Set(LErrorNotSupported, "Unsupported SMART encryption type");
		return false;
	}
	LString portValue = discovery.Get("result.mgt_encrypt_schm.http_port");
	int port = portValue ? atoi(portValue.Get()) : 80;
	if (port <= 0 || port > 65535)
		port = 80;
	if (port == 4433)
	{
		LastError.Set(LErrorNotSupported, "HTTPS KLAP is not supported yet");
		return false;
	}

	auto session = std::make_unique<LKasaSmartSession>();
	session->Host = ToStdString(device.Ip);
	session->Port = port;
	session->TimeoutMs = timeoutMs;
	LString version = discovery.Get("result.mgt_encrypt_schm.lv");
	int loginVersion = version ? atoi(version.Get()) : 1;
	session->LoginVersion = loginVersion > 0 ? loginVersion : 1;
	if (encryption == "KLAP")
		session->Type = session->LoginVersion >= 2
			? LKasaSmartSession::Transport::KlapV2 : LKasaSmartSession::Transport::KlapV1;
	else
		session->Type = LKasaSmartSession::Transport::Aes;

	std::string uuidBytes(16, '\0'), uuidDigest;
	if (RAND_bytes((unsigned char *)uuidBytes.data(), (int)uuidBytes.size()) != 1 ||
		!DigestBytes(EVP_md5(), uuidBytes, uuidDigest))
	{
		LastError.Set(LErrorFuncFailed, "Unable to generate SMART terminal UUID");
		return false;
	}
	session->TerminalUuid = Base64Encode(uuidDigest);

	LError error;
	bool connected = session->Type == LKasaSmartSession::Transport::Aes
		? ConnectAes(*session, username, password, error)
		: ConnectKlap(*session, username, password, error);
	if (!connected)
	{
		LastError = error;
		return false;
	}
	Smart = std::move(session);
	return true;
}

bool LKasaProtocol::ConnectSmart(const char *host, const char *username,
	const char *password, int timeoutMs)
{
	if (!host || !*host)
	{
		LastError.Set(LErrorInvalidParam, "A SMART device host is required");
		return false;
	}
	LArray<LKasaDevice> devices;
	if (!DiscoverModern(devices, host, timeoutMs) || !devices.Length())
		return false;
	return ConnectSmart(devices[0], username, password, timeoutMs);
}

bool LKasaProtocol::SmartRequest(const char *method, const char *paramsJson, LString &responseJson)
{
	responseJson.Empty();
	LastError.Empty();
	if (!Smart || !method)
	{
		LastError.Set(LErrorInvalidParam, "SMART session is not connected");
		return false;
	}
	std::string request = BuildSmartRequest(method, Smart->TerminalUuid, paramsJson);
	std::string response;
	LError error;
	if (Smart->Type == LKasaSmartSession::Transport::Aes)
	{
		if (!AesPassthrough(*Smart, request, response, error))
		{
			LastError = error;
			return false;
		}
	}
	else
	{
		if (Smart->Sequence >= INT32_MAX)
		{
			LastError.Set(LErrorFuncFailed, "KLAP sequence exhausted; reconnect before sending more requests");
			return false;
		}
		Smart->Sequence++;
		uint32_t sequence = (uint32_t)(int32_t)Smart->Sequence;
		std::string sequenceBytes(4, '\0');
		sequenceBytes[0] = (char)(sequence >> 24);
		sequenceBytes[1] = (char)(sequence >> 16);
		sequenceBytes[2] = (char)(sequence >> 8);
		sequenceBytes[3] = (char)sequence;
		std::string iv = Smart->IvPrefix + sequenceBytes;
		std::string ciphertext, signature;
		if (!AesCrypt(true, Smart->Key, iv, request, ciphertext) ||
			!DigestBytes(EVP_sha256(), Smart->SignaturePrefix + sequenceBytes + ciphertext, signature))
		{
			LastError.Set(LErrorFuncFailed, "Unable to encrypt KLAP request");
			return false;
		}
		std::string body = signature + ciphertext;
		std::string path = "/app/request?seq=" + std::to_string(Smart->Sequence);
		int status = 0;
		std::string responseHeaders;
		if (!HttpPost(Smart->Host, Smart->Port, path, body, Smart->Cookie, Smart->TimeoutMs,
			status, response, responseHeaders, error, "application/octet-stream", false))
		{
			LastError = error;
			return false;
		}
		if (status != 200 || response.size() < 32)
		{
			LastError.Set(LErrorFuncFailed, LString::Fmt("KLAP request failed with HTTP status %i", status));
			return false;
		}
		std::string plaintext;
		if (!AesCrypt(false, Smart->Key, iv, response.substr(32), plaintext))
		{
			LastError.Set(LErrorFuncFailed, "Unable to decrypt KLAP response");
			return false;
		}
		response = plaintext;
		if (!CheckSmartJson(response, error))
		{
			LastError = error;
			return false;
		}
	}
	responseJson.Set(response.data(), (ssize_t)response.size());
	return true;
}

bool LKasaProtocol::GetDeviceInfo(LString &responseJson)
{
	return SmartRequest("get_device_info", nullptr, responseJson);
}

bool LKasaProtocol::SetDeviceOn(bool on, LString &responseJson)
{
	return on
		? SmartRequest("set_device_info", "{\"device_on\":true}", responseJson)
		: SmartRequest("set_device_info", "{\"device_on\":false}", responseJson);
}