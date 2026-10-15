#pragma once

#include "lgi/common/Lgi.h"
#include "lgi/common/Net.h"

struct LKasaDevice
{
    LString Ip;
    LString Response; // Json
};

class LKasaProtocol
{
    LSocket Socket;
    LError LastError;

    bool WriteAll(const void *data, size_t size);
    bool ReadAll(void *data, size_t size);

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

    // Each message starts with state 0xAB; decryption advances on ciphertext.
    static LString XorEncrypt(const void *data, size_t size);
    static LString XorDecrypt(const void *data, size_t size);
};