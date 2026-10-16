#pragma once

#include "lgi/common/Lgi.h"
#include "lgi/common/Net.h"

#include <functional>
#include <memory>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>

struct LKasaDevice
{
    LString Ip;
    LString Name;
    LString Response; // Json
};

struct LKasaSmartSession;

class LKasaProtocol
{
public:
    using TDeviceCb = std::function<void(const LKasaDevice &)>;
    using TStatusCb = std::function<void(bool, const LString &)>;

private:
    struct Cancellation : LCancel
    {
        std::atomic<bool> Cancelled{false};
        bool IsCancelled() override { return Cancelled.load(); }
        bool Cancel(bool cancelled = true) override
        {
            Cancelled.store(cancelled);
            return true;
        }
    };

    std::shared_ptr<Cancellation> CancelState = std::make_shared<Cancellation>();
    bool OwnsCancellation = true;
    LSocket Socket;
    LError LastError;
    std::unique_ptr<LKasaSmartSession> Smart;
    std::mutex QueueMutex;
    std::condition_variable QueueReady;
    std::deque<std::function<void()>> Pending;
    bool Stopping = false;
    std::thread Worker;
    mutable std::mutex StatusMutex;
    mutable LError PublishedError;
    bool Connected = false;
    LString Username;
    LString Password;
    std::atomic<int> Timeout{DefaultTimeoutMs};

    bool Enqueue(std::function<bool(LString &, int)> operation, const TStatusCb &onComplete);
    void ApplyTimeout(int timeoutMs);
    void WorkerLoop();
    bool ConnectSync(const char *host, int port, int timeoutMs);
    void DisconnectSync();
    bool DiscoverSync(const TDeviceCb &onDevice, const char *targetIp, int timeoutMs);
    bool DiscoverLegacySync(const TDeviceCb &onDevice, const char *targetIp, int timeoutMs);
    bool DiscoverModernSync(const TDeviceCb &onDevice, const char *targetIp, int timeoutMs);
    bool RequestSync(const char *requestJson, LString &responseJson);
    bool ConnectSmartSync(const LKasaDevice &device, const char *username, const char *password, int timeoutMs);
    bool ConnectSmartSync(const char *host, const char *username, const char *password, int timeoutMs);

    bool WriteAll(const void *data, size_t size);
    bool ReadAll(void *data, size_t size);
    bool SmartRequest(const char *method, const char *paramsJson, LString &responseJson);
    bool HasSmartSession() const;
    void ClearSmartSession();

public:
    static constexpr int DefaultPort = 9999;
    static constexpr size_t MaxMessageSize = 1024 * 1024;
    static constexpr int DefaultTimeoutMs = 5000;

    LKasaProtocol();
    LKasaProtocol(const LKasaProtocol &other);
    ~LKasaProtocol();

    int GetTimeout() const;
    bool SetTimeout(int timeoutMs);
    void SetCredentials(const char *username, const char *password);

    bool Connect(const char *host, const TStatusCb &onComplete, int port = DefaultPort);
    void Disconnect();
    bool IsConnected() const;
    LError GetError() const;

    // targetIp is an IPv4 address or hostname to probe directly.
    // nullptr broadcasts discovery probes on all usable non-loopback IPv4 interfaces.
    bool Discover(const TDeviceCb &onDevice, const char *targetIp = nullptr,
        const TStatusCb &onComplete = {});
    // Sends an IOT JSON command and returns the decrypted response JSON.
    bool Request(const char *requestJson, const TStatusCb &onComplete);
    bool GetSysInfo(const TStatusCb &onComplete);
    bool SetRelayState(bool on, const TStatusCb &onComplete);

    // Connect to a discovered standard SMART switch using its advertised AES, KLAP, or supported TPAP profile.
    bool ConnectSmart(const LKasaDevice &device, const TStatusCb &onComplete);
    bool ConnectSmart(const char *host, const TStatusCb &onComplete);
    bool ConnectSmart(const LKasaDevice &device, const char *username, const char *password,
        const TStatusCb &onComplete);
    bool ConnectSmart(const char *host, const char *username, const char *password,
        const TStatusCb &onComplete);
    bool GetDeviceInfo(const TStatusCb &onComplete);
    bool SetDeviceOn(bool on, const TStatusCb &onComplete);

    // Each message starts with state 0xAB; decryption advances on ciphertext.
    static LString XorEncrypt(const void *data, size_t size);
    static LString XorDecrypt(const void *data, size_t size);
};