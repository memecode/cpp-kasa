#include "cpp-kasa/cpp-kasa.h"
#include "lgi/common/Http.h"
#include "lgi/common/Json.h"

#include <chrono>
#include <cctype>
#include <cstdlib>
#include <charconv>
#include <memory>
#include <string>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

struct LKasaSmartSession
{
	enum class Transport
	{
		Aes,
		KlapV1,
		KlapV2,
		Tpap
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
	std::string BaseNonce;
	int Port = 80;
	int LoginVersion = 1;
	int64_t Sequence = 0;
	int TimeoutMs = 5000;
	LCancel *Cancel = nullptr;
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
		const std::string &body, const std::string &cookie, LCancel *cancel, int timeoutMs,
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
		socket->SetCancel(cancel);
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

	bool TpapNumber(LJson &json, const char *path, uint32_t &number)
	{
		auto text = ToStdString(json.Get(path));
		auto parsed = std::from_chars(text.data(), text.data() + text.size(), number);
		return !text.empty() && parsed.ec == std::errc() && parsed.ptr == text.data() + text.size();
	}

	bool TpapHkdf(const std::string &input, const std::string &salt,
		const std::string &info, size_t size, std::string &output)
	{
		PkeyContextPtr context(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free);
		output.resize(size);
		return context && EVP_PKEY_derive_init(context.get()) > 0 &&
			EVP_PKEY_CTX_set_hkdf_md(context.get(), EVP_sha256()) > 0 &&
			EVP_PKEY_CTX_set1_hkdf_salt(context.get(), (const unsigned char *)salt.data(), (int)salt.size()) > 0 &&
			EVP_PKEY_CTX_set1_hkdf_key(context.get(), (const unsigned char *)input.data(), (int)input.size()) > 0 &&
			EVP_PKEY_CTX_add1_hkdf_info(context.get(), (const unsigned char *)info.data(), (int)info.size()) > 0 &&
			EVP_PKEY_derive(context.get(), (unsigned char *)output.data(), &size) > 0 && size == output.size();
	}

	std::string TpapHmac(const std::string &key, const std::string &input)
	{
		unsigned char digest[EVP_MAX_MD_SIZE];
		unsigned int size = 0;
		if (!HMAC(EVP_sha256(), key.data(), (int)key.size(),
			(const unsigned char *)input.data(), input.size(), digest, &size))
			return {};
		return std::string((const char *)digest, size);
	}

	bool CheckTpapJson(const std::string &text, LError &error)
	{
		LJson response;
		if (response.SetJson(text.c_str()))
		{
			auto value = ToStdString(response.Get("error_code"));
			int code = 0;
			auto parsed = std::from_chars(value.data(), value.data() + value.size(), code);
			if (!value.empty() && parsed.ec == std::errc() && parsed.ptr == value.data() + value.size())
				return CheckSmartJson(text, error);
		}
		error.Set(LErrorFuncFailed, "Invalid TPAP JSON response or error code");
		return false;
	}

	bool TpapLogin(LKasaSmartSession &session, const std::string &params, LJson &reply, LError &error)
	{
		if (session.Cancel && session.Cancel->IsCancelled())
			return false;
		int status = 0;
		std::string response, headers;
		if (!HttpPost(session.Host, session.Port, "/", "{\"method\":\"login\",\"params\":" + params + "}",
			"", session.Cancel, session.TimeoutMs, status, response, headers, error, "application/json", false))
			return false;
		if (status != 200 || response.size() > LKasaProtocol::MaxMessageSize ||
			!reply.SetJson(response.c_str()) || !reply.Get("error_code"))
		{
			error.Set(LErrorFuncFailed, "Invalid TPAP login response");
			return false;
		}
		return CheckTpapJson(response, error);
	}

	bool TpapCredentials(LJson &registration, const std::string &username,
		const std::string &password, const std::string &mac, std::string &credentials)
	{
		auto type = ToStdString(registration.Get("result.extra_crypt.type"));
		if (type.empty())
		{
			credentials = username.empty() ? password : username + "/" + password;
			return true;
		}
		if (type == "password_shadow")
		{
			uint32_t identifier = 0;
			if (!TpapNumber(registration, "result.extra_crypt.params.passwd_id", identifier))
				return false;
			if (identifier == 2)
			{
				std::string digest;
				if (!DigestBytes(EVP_sha1(), password, digest))
					return false;
				credentials = HexLower(digest);
				return true;
			}
			if (identifier == 3)
			{
				std::string normalizedMac;
				for (unsigned char character: mac)
				{
					if (character == ':' || character == '-')
						continue;
					if (!std::isxdigit(character))
						return false;
					normalizedMac += (char)std::toupper(character);
				}
				if (normalizedMac.size() != 12 || username.empty())
					return false;
				std::string formattedMac;
				for (size_t index = 0; index < normalizedMac.size(); index += 2)
				{
					if (index)
						formattedMac += ':';
					formattedMac += normalizedMac.substr(index, 2);
				}
				std::string digest;
				if (!DigestBytes(EVP_md5(), username, digest) ||
					!DigestBytes(EVP_sha1(), HexLower(digest) + "_" + formattedMac, digest))
					return false;
				credentials = HexLower(digest);
				return true;
			}
		}
		if (type == "password_sha_with_salt")
		{
			uint32_t name = 0;
			std::string salt, digest;
			if (!TpapNumber(registration, "result.extra_crypt.params.sha_name", name) ||
				!Base64Decode(ToStdString(registration.Get("result.extra_crypt.params.sha_salt")), salt) ||
				!DigestBytes(EVP_sha256(), (name == 0 ? "admin" : "user") + salt + password, digest))
				return false;
			credentials = HexLower(digest);
			return true;
		}
		return false;
	}

	bool TpapShare(LJson &registration, const std::string &credentials, const std::string &userRandom,
		std::string &share, std::string &confirmation, std::string &expected, std::string &shared)
	{
		uint32_t suite = 0, iterations = 0;
		std::string salt, remoteRandom, remoteShare;
		if (!TpapNumber(registration, "result.cipher_suites", suite) || suite != 1 ||
			!TpapNumber(registration, "result.iterations", iterations) || !iterations || iterations > 1000000 ||
			!registration.Get("result.encryption").Equals("aes_128_ccm", false) ||
			!Base64Decode(ToStdString(registration.Get("result.dev_salt")), salt) || salt.empty() ||
			!Base64Decode(ToStdString(registration.Get("result.dev_random")), remoteRandom) || remoteRandom.empty() ||
			!Base64Decode(ToStdString(registration.Get("result.dev_share")), remoteShare) ||
			(remoteShare.size() != 33 && remoteShare.size() != 65))
			return false;

		using Group = std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)>;
		using Context = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
		using Number = std::unique_ptr<BIGNUM, decltype(&BN_clear_free)>;
		using Point = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
		Group group(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1), EC_GROUP_free);
		Context context(BN_CTX_new(), BN_CTX_free);
		if (!group || !context)
			return false;
		Number order(BN_new(), BN_clear_free), weight(BN_new(), BN_clear_free),
			hidden(BN_new(), BN_clear_free), secret(BN_new(), BN_clear_free);
		std::string derived(80, '\0');
		if (!order || !weight || !hidden || !secret ||
			!PKCS5_PBKDF2_HMAC(credentials.data(), (int)credentials.size(), (const unsigned char *)salt.data(),
				(int)salt.size(), (int)iterations, EVP_sha256(), (int)derived.size(), (unsigned char *)derived.data()) ||
			!EC_GROUP_get_order(group.get(), order.get(), context.get()) ||
			!BN_bin2bn((const unsigned char *)derived.data(), 40, weight.get()) ||
			!BN_bin2bn((const unsigned char *)derived.data() + 40, 40, hidden.get()) ||
			!BN_mod(weight.get(), weight.get(), order.get(), context.get()) ||
			!BN_mod(hidden.get(), hidden.get(), order.get(), context.get()))
			return false;
		OPENSSL_cleanse(derived.data(), derived.size());
		BN_set_flags(weight.get(), BN_FLG_CONSTTIME);
		BN_set_flags(hidden.get(), BN_FLG_CONSTTIME);
		BN_set_flags(secret.get(), BN_FLG_CONSTTIME);
		do
		{
			if (!BN_priv_rand_range(secret.get(), order.get()))
				return false;
		} while (BN_is_zero(secret.get()));

		Point mask(EC_POINT_hex2point(group.get(),
			"02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f", nullptr, context.get()), EC_POINT_free);
		Point peerMask(EC_POINT_hex2point(group.get(),
			"03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49", nullptr, context.get()), EC_POINT_free);
		Point local(EC_POINT_new(group.get()), EC_POINT_free), remote(EC_POINT_new(group.get()), EC_POINT_free),
			unmasked(EC_POINT_new(group.get()), EC_POINT_free), intermediate(EC_POINT_new(group.get()), EC_POINT_free),
			proof(EC_POINT_new(group.get()), EC_POINT_free);
		if (!mask || !peerMask || !local || !remote || !unmasked || !intermediate || !proof ||
			!EC_POINT_oct2point(group.get(), remote.get(), (const unsigned char *)remoteShare.data(),
				remoteShare.size(), context.get()) || EC_POINT_is_at_infinity(group.get(), remote.get()) ||
			EC_POINT_is_on_curve(group.get(), remote.get(), context.get()) != 1 ||
			!EC_POINT_mul(group.get(), local.get(), secret.get(), mask.get(), weight.get(), context.get()) ||
			!EC_POINT_mul(group.get(), unmasked.get(), nullptr, peerMask.get(), weight.get(), context.get()) ||
			!EC_POINT_invert(group.get(), unmasked.get(), context.get()) ||
			!EC_POINT_add(group.get(), unmasked.get(), remote.get(), unmasked.get(), context.get()) ||
			EC_POINT_is_at_infinity(group.get(), unmasked.get()) ||
			!EC_POINT_mul(group.get(), intermediate.get(), nullptr, unmasked.get(), secret.get(), context.get()) ||
			!EC_POINT_mul(group.get(), proof.get(), nullptr, unmasked.get(), hidden.get(), context.get()))
			return false;
		auto encodePoint = [&](const Point &point)
		{
			std::string encoded(65, '\0');
			if (EC_POINT_is_at_infinity(group.get(), point.get()) ||
				EC_POINT_point2oct(group.get(), point.get(), POINT_CONVERSION_UNCOMPRESSED,
					(unsigned char *)encoded.data(), encoded.size(), context.get()) != encoded.size())
				encoded.clear();
			return encoded;
		};
		std::string localBytes = encodePoint(local), remoteBytes = encodePoint(remote),
			sharedPoint = encodePoint(intermediate), proofBytes = encodePoint(proof);
		if (localBytes.empty() || remoteBytes.empty() || sharedPoint.empty() || proofBytes.empty())
			return false;
		std::string weightBytes(MAX(BN_num_bytes(weight.get()), 1), '\0');
		BN_bn2bin(weight.get(), (unsigned char *)weightBytes.data());
		if (weightBytes.size() % 2 && ((unsigned char)weightBytes.front() & 0x80))
			weightBytes.insert(weightBytes.begin(), '\0');
		std::string contextHash;
		if (!DigestBytes(EVP_sha256(), "PAKE V1" + userRandom + remoteRandom, contextHash))
			return false;
		std::string transcript;
		for (const auto &part: {contextHash, std::string(), std::string(), encodePoint(mask), encodePoint(peerMask),
			localBytes, remoteBytes, sharedPoint, proofBytes, weightBytes})
		{
			uint64_t size = part.size();
			for (int byte = 0; byte < 8; byte++)
				transcript.push_back((char)(size >> (byte * 8)));
			transcript += part;
		}
		std::string transcriptHash, confirmations;
		if (!DigestBytes(EVP_sha256(), transcript, transcriptHash) ||
			!TpapHkdf(transcriptHash, std::string(64, '\0'), "ConfirmationKeys", 64, confirmations) ||
			!TpapHkdf(transcriptHash, std::string(32, '\0'), "SharedKey", 32, shared))
			return false;
		share = Base64Encode(localBytes);
		confirmation = TpapHmac(confirmations.substr(0, 32), remoteBytes);
		expected = TpapHmac(confirmations.substr(32), localBytes);
		return confirmation.size() == 32 && expected.size() == 32;
	}

	bool ConnectTpap(LKasaSmartSession &session, const char *username, const char *password, LError &error)
	{
		LJson discovery;
		if (!TpapLogin(session, "{\"sub_method\":\"discover\"}", discovery, error))
			return false;
		uint32_t tls = 0, port = 0;
		auto dac = ToStdString(discovery.Get("result.tpap.dac"));
		bool userPassword = false;
		for (auto &entry: discovery.GetArray("result.tpap.pake"))
			if (entry.Get().value.Equals("2", false))
				userPassword = true;
		if (!TpapNumber(discovery, "result.tpap.tls", tls) || tls != 0 ||
			(dac != "0" && dac != "false") || !userPassword ||
			!TpapNumber(discovery, "result.tpap.port", port) || port == 0 || port > 65535)
		{
			error.Set(LErrorNotSupported, "TPAP requires HTTP, no DAC, and account-password PAKE mode 2");
			return false;
		}
		session.Port = (int)port;
		std::string adminHash;
		auto hashType = ToStdString(discovery.Get("result.tpap.user_hash_type"));
		if (!hashType.empty() && hashType != "0" && hashType != "1")
		{
			error.Set(LErrorNotSupported, "Unsupported TPAP username hash type");
			return false;
		}
		if (!DigestBytes(hashType == "1" ? EVP_sha256() : EVP_md5(), "admin", adminHash))
			return false;
		adminHash = HexLower(adminHash);
		if (hashType == "1")
			for (auto &character: adminHash)
				character = (char)std::toupper((unsigned char)character);
		std::string userRandom(32, '\0');
		if (RAND_bytes((unsigned char *)userRandom.data(), (int)userRandom.size()) != 1)
			return false;
		LJson registration;
		if (!TpapLogin(session, "{\"sub_method\":\"pake_register\",\"username\":\"" + adminHash +
			"\",\"user_random\":\"" + Base64Encode(userRandom) + "\",\"cipher_suites\":[1],"
			"\"encryption\":[\"aes_128_ccm\"],\"passcode_type\":\"userpw\",\"stok\":null}", registration, error))
			return false;
		std::string credentials;
		if (!TpapCredentials(registration, username, password, ToStdString(discovery.Get("result.mac")), credentials))
		{
			error.Set(LErrorNotSupported, "Unsupported TPAP extra_crypt credential transformation");
			return false;
		}
		std::string share, confirmation, expected, shared;
		bool derived = TpapShare(registration, credentials, userRandom, share, confirmation, expected, shared);
		OPENSSL_cleanse(credentials.data(), credentials.size());
		if (!derived)
		{
			error.Set(LErrorNotSupported, "Invalid TPAP register response or unsupported suite (requires suite 1/AES-128-CCM)");
			return false;
		}
		LJson established;
		if (!TpapLogin(session, "{\"sub_method\":\"pake_share\",\"user_share\":\"" + share +
			"\",\"user_confirm\":\"" + Base64Encode(confirmation) + "\"}", established, error))
			return false;
		std::string actual;
		uint32_t sequence = 0;
		if (!Base64Decode(ToStdString(established.Get("result.dev_confirm")), actual) || actual.size() != expected.size() ||
			CRYPTO_memcmp(actual.data(), expected.data(), expected.size()) ||
			!TpapNumber(established, "result.start_seq", sequence))
		{
			error.Set(LErrorFuncFailed, "TPAP server confirmation or sequence is invalid");
			return false;
		}
		session.Token = ToStdString(established.Get("result.sessionId"));
		if (session.Token.empty())
			session.Token = ToStdString(established.Get("result.stok"));
		if (session.Token.empty() ||
			!TpapHkdf(shared, "tp-kdf-salt-aes128-key", "tp-kdf-info-aes128-key", 16, session.Key) ||
			!TpapHkdf(shared, "tp-kdf-salt-aes128-iv", "tp-kdf-info-aes128-iv", 12, session.BaseNonce))
		{
			error.Set(LErrorFuncFailed, "TPAP session key or identifier is invalid");
			return false;
		}
		session.Sequence = sequence;
		return true;
	}

	bool TpapCipher(bool encrypt, const LKasaSmartSession &session, uint32_t sequence,
		const std::string &input, std::string &output)
	{
		if (session.Key.size() != 16 || session.BaseNonce.size() != 12 ||
			input.size() > LKasaProtocol::MaxMessageSize || (!encrypt && input.size() < 16))
			return false;
		std::string nonce = session.BaseNonce;
		for (int byte = 0; byte < 4; byte++)
			nonce[8 + byte] = (char)(sequence >> (24 - byte * 8));
		CipherContextPtr context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
		int size = (int)input.size() - (encrypt ? 0 : 16), written = 0;
		output.resize(size + (encrypt ? 16 : 0));
		if (!context || EVP_CipherInit_ex(context.get(), EVP_aes_128_ccm(), nullptr, nullptr, nullptr, encrypt) != 1 ||
			EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_CCM_SET_IVLEN, 12, nullptr) != 1 ||
			EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_CCM_SET_TAG, 16,
				encrypt ? nullptr : (void *)(input.data() + size)) != 1 ||
			EVP_CipherInit_ex(context.get(), nullptr, nullptr, (const unsigned char *)session.Key.data(),
				(const unsigned char *)nonce.data(), encrypt) != 1 ||
			EVP_CipherUpdate(context.get(), nullptr, &written, nullptr, size) != 1 ||
			EVP_CipherUpdate(context.get(), (unsigned char *)output.data(), &written,
				(const unsigned char *)input.data(), size) != 1)
		{
			output.clear();
			return false;
		}
		return !encrypt || EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_CCM_GET_TAG, 16, output.data() + size) == 1;
	}

	bool TpapRequest(LKasaSmartSession &session, const std::string &request, std::string &response, LError &error)
	{
		if (session.Sequence < 0 || session.Sequence > UINT32_MAX)
		{
			error.Set(LErrorFuncFailed, "TPAP sequence exhausted; reconnect before sending requests");
			return false;
		}
		uint32_t sequence = (uint32_t)session.Sequence++;
		std::string ciphertext;
		if (!TpapCipher(true, session, sequence, request, ciphertext))
		{
			error.Set(LErrorFuncFailed, "Unable to encrypt TPAP request");
			return false;
		}
		std::string frame(4, '\0');
		for (int byte = 0; byte < 4; byte++)
			frame[byte] = (char)(sequence >> (24 - byte * 8));
		frame += ciphertext;
		int status = 0;
		std::string headers, body;
		if (!HttpPost(session.Host, session.Port, "/stok=" + UrlEncode(session.Token) + "/ds", frame,
			"", session.Cancel, session.TimeoutMs, status, body, headers, error, "application/octet-stream", false))
			return false;
		if (status != 200 || body.size() < 20 || body.size() > LKasaProtocol::MaxMessageSize ||
			body.compare(0, 4, frame, 0, 4) != 0 || !TpapCipher(false, session, sequence, body.substr(4), response))
		{
			LJson plain;
			if (plain.SetJson(body.c_str()) && plain.Get("error_code") && !CheckSmartJson(body, error))
				return false;
			error.Set(LErrorFuncFailed, "Invalid TPAP response framing or authentication tag; reconnect required");
			return false;
		}
		return CheckTpapJson(response, error);
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
			session.Cancel, session.TimeoutMs, status, responseBody, responseHeaders, error))
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
		if (!HttpPost(session.Host, session.Port, "/app", handshake, "", session.Cancel, session.TimeoutMs,
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
			session.Cancel, session.TimeoutMs, status, serverReply, headers, error, "application/octet-stream", false))
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
			session.Cancel, session.TimeoutMs, status, handshake2Reply, handshake2Headers, error,
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
	Socket.SetCancel(CancelState.get());
	Worker = std::thread([this]() { WorkerLoop(); });
}

LKasaProtocol::LKasaProtocol(const LKasaProtocol &other)
	: LKasaProtocol()
{
	std::lock_guard<std::mutex> lock(other.StatusMutex);
	Username.Set(other.Username.Get());
	Password.Set(other.Password.Get());
}

LKasaProtocol::~LKasaProtocol()
{
	{
		std::lock_guard<std::mutex> lock(QueueMutex);
		Stopping = true;
		if (OwnsCancellation)
			CancelState->Cancel();
		Pending.clear();
	}
	QueueReady.notify_one();
	Worker.join();
	DisconnectSync();
}

void LKasaProtocol::ClearSmartSession()
{
	Smart.reset();
}

bool LKasaProtocol::HasSmartSession() const
{
	return Smart != nullptr;
}

void LKasaProtocol::ApplyTimeout(int timeoutMs)
{
	Socket.SetTimeout(timeoutMs);
	if (Smart)
		Smart->TimeoutMs = timeoutMs;
}

bool LKasaProtocol::ConnectSmart(const LKasaDevice &device, const TStatusCb &onComplete)
{
	LString user, secret;
	{
		std::lock_guard<std::mutex> lock(StatusMutex);
		user.Set(Username.Get());
		secret.Set(Password.Get());
	}
	return ConnectSmart(device, user.Get(), secret.Get(), onComplete);
}

bool LKasaProtocol::ConnectSmart(const char *host, const TStatusCb &onComplete)
{
	LString user, secret;
	{
		std::lock_guard<std::mutex> lock(StatusMutex);
		user.Set(Username.Get());
		secret.Set(Password.Get());
	}
	return ConnectSmart(host, user.Get(), secret.Get(), onComplete);
}

bool LKasaProtocol::ConnectSmart(const LKasaDevice &device, const char *username,
	const char *password, const TStatusCb &onComplete)
{
	if (!onComplete)
		return false;
	std::string ip = device.Ip.Get() ? device.Ip.Get() : "";
	std::string metadata = device.Response.Get() ? device.Response.Get() : "";
	std::string user = username ? username : "";
	std::string secret = password ? password : "";
	bool credentials = username && password;
	return Enqueue([=](LString &, int timeoutMs)
	{
		LKasaDevice copy;
		copy.Ip = ip.c_str();
		copy.Response = metadata.c_str();
		return ConnectSmartSync(copy, credentials ? user.c_str() : nullptr,
			credentials ? secret.c_str() : nullptr, timeoutMs);
	}, onComplete);
}

bool LKasaProtocol::ConnectSmart(const char *host, const char *username,
	const char *password, const TStatusCb &onComplete)
{
	if (!onComplete)
		return false;
	std::string address = host ? host : "";
	std::string user = username ? username : "";
	std::string secret = password ? password : "";
	bool credentials = username && password;
	return Enqueue([=](LString &, int timeoutMs)
	{
		return ConnectSmartSync(address.c_str(), credentials ? user.c_str() : nullptr,
			credentials ? secret.c_str() : nullptr, timeoutMs);
	}, onComplete);
}

bool LKasaProtocol::ConnectSmartSync(const LKasaDevice &device, const char *username,
	const char *password, int timeoutMs)
{
	DisconnectSync();
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
	if (encryption != "AES" && encryption != "KLAP" && encryption != "TPAP")
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
	if (encryption == "TPAP")
	{
		auto tls = ToStdString(discovery.Get("result.tpap.tls"));
		auto https = ToStdString(discovery.Get("result.mgt_encrypt_schm.is_support_https"));
		if ((!tls.empty() && tls != "0") || https == "true" || https == "1")
		{
			LastError.Set(LErrorNotSupported, "HTTPS TPAP is not supported");
			return false;
		}
	}

	auto session = std::make_unique<LKasaSmartSession>();
	session->Cancel = CancelState.get();
	session->Host = ToStdString(device.Ip);
	session->Port = port;
	session->TimeoutMs = timeoutMs;
	LString version = discovery.Get("result.mgt_encrypt_schm.lv");
	int loginVersion = version ? atoi(version.Get()) : 1;
	session->LoginVersion = loginVersion > 0 ? loginVersion : 1;
	if (encryption == "TPAP")
		session->Type = LKasaSmartSession::Transport::Tpap;
	else if (encryption == "KLAP")
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
	bool connected = session->Type == LKasaSmartSession::Transport::Tpap
		? ConnectTpap(*session, username, password, error)
		: session->Type == LKasaSmartSession::Transport::Aes
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

bool LKasaProtocol::ConnectSmartSync(const char *host, const char *username,
	const char *password, int timeoutMs)
{
	if (!host || !*host)
	{
		LastError.Set(LErrorInvalidParam, "A SMART device host is required");
		return false;
	}
	LArray<LKasaDevice> devices;
	if (!DiscoverModernSync([&](const LKasaDevice &device)
		{
			devices.New() = device;
		}, host, timeoutMs) || !devices.Length())
		return false;
	return ConnectSmartSync(devices[0], username, password, timeoutMs);
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
	if (Smart->Type == LKasaSmartSession::Transport::Tpap)
	{
		if (!TpapRequest(*Smart, request, response, error))
		{
			LastError = error;
			ClearSmartSession();
			return false;
		}
	}
	else if (Smart->Type == LKasaSmartSession::Transport::Aes)
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
		if (!HttpPost(Smart->Host, Smart->Port, path, body, Smart->Cookie, Smart->Cancel, Smart->TimeoutMs,
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

bool LKasaProtocol::GetDeviceInfo(const TStatusCb &onComplete)
{
	if (!onComplete)
		return false;
	return Enqueue([this](LString &response, int)
	{
		return SmartRequest("get_device_info", nullptr, response);
	}, onComplete);
}

bool LKasaProtocol::SetDeviceOn(bool on, const TStatusCb &onComplete)
{
	if (!onComplete)
		return false;
	return Enqueue([this, on](LString &response, int)
	{
		return SmartRequest("set_device_info", on ? "{\"device_on\":true}" : "{\"device_on\":false}", response);
	}, onComplete);
}