#pragma once

#include "lgi/common/Lgi.h"
#include "lgi/common/Net.h"

#include <memory>

struct LKasaDevice
{
    LString Ip;
    LString Response; // Json
};

struct LKasaSmartSession;

class LKasaProtocol
{
    LSocket Socket;
    LError LastError;
    std::unique_ptr<LKasaSmartSession> Smart;

    bool WriteAll(const void *data, size_t size);
    bool ReadAll(void *data, size_t size);
    bool SmartRequest(const char *method, const char *paramsJson, LString &responseJson);
    bool HasSmartSession() const;
    void ClearSmartSession();

public:
    static constexpr int DefaultPort = 9999;
    static constexpr size_t MaxMessageSize = 1024 * 1024;

    LKasaProtocol();
    ~LKasaProtocol();

    bool Connect(const char *host, int port = DefaultPort, int timeoutMs = 5000);
    void Disconnect();
    bool IsConnected() const;
    LError GetLastError() const;

    // Probes both legacy and modern discovery backends; each gets its own timeout.
    bool Discover(LArray<LKasaDevice> &devices, const char *targetIp = nullptr, int timeoutMs = 5000);
    // Protocol-specific discovery for callers that only need legacy XOR devices.
    bool DiscoverLegacy(LArray<LKasaDevice> &devices, const char *targetIp = nullptr, int timeoutMs = 5000);
    bool DiscoverModern(LArray<LKasaDevice> &devices, const char *targetIp = nullptr, int timeoutMs = 5000);

    // Sends an IOT JSON command and returns the decrypted response JSON.
    bool Request(const char *requestJson, LString &responseJson);
    bool GetSysInfo(LString &responseJson);
    bool SetRelayState(bool on, LString &responseJson);

    // Connect to a discovered standard SMART switch using its advertised AES or KLAP transport.
    bool ConnectSmart(const LKasaDevice &device, const char *username, const char *password,
        int timeoutMs = 5000);
    bool ConnectSmart(const char *host, const char *username, const char *password,
        int timeoutMs = 5000);
    bool GetDeviceInfo(LString &responseJson);
    bool SetDeviceOn(bool on, LString &responseJson);

    // Each message starts with state 0xAB; decryption advances on ciphertext.
    static LString XorEncrypt(const void *data, size_t size);
    static LString XorDecrypt(const void *data, size_t size);
};