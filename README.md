# cpp-kasa

`cpp-kasa` is a small C++ library for discovering Kasa devices and sending basic
commands to legacy and standard SMART switches on a local network. It uses Lgi
for networking and JSON handling.

## Protocol Support

- Combined discovery probes both legacy XOR discovery (UDP port 9999) and modern
	TDP discovery (UDP ports 20002 and 20004) concurrently. Results are deduplicated
	within each backend by source IP and delivered through callbacks immediately.
	A modern reply updates an earlier legacy reply for the same address; a legacy
	reply is suppressed if a modern reply was already delivered. Each backend has
	a five-second timeout by default.
- Legacy device control uses XOR-over-TCP on port 9999, with IOT commands such
	as `get_sysinfo` and `set_relay_state`.
- Standard SMART switch control supports the advertised HTTP AES or KLAP v1/v2
	transport, account credentials, `get_device_info`, and `set_device_info` for
	the `device_on` state.
- TPAP SMART plugs support the HTTP, no-DAC, account-password PAKE-2 profile
	with P-256 suite 1 and AES-128-CCM. It uses the existing `ConnectSmart()`,
	`GetDeviceInfo()`, and `SetDeviceOn()` APIs and the same utility commands.
	No additional dependency is required. This implementation follows upstream
	python-kasa PR #1592 and has loopback interoperability tests, but has not yet
	been verified against a physical TPAP device.

Modern control currently requires plain HTTP. HTTPS, cameras, hubs, robovacs,
child devices, and other specialized command families are not supported.
TPAP TLS/DAC modes, alternate suites/ciphers, default/shared-token credentials,
password-authkey transformations, and MD5-crypt/SHA256-crypt password shadows
are not supported. Unsupported variants fail explicitly rather than falling
back to a weaker transport. TPAP session expiry or authentication failure clears
the connection; reconnect explicitly before another request.
Discovery does not attempt to decrypt optional encrypted metadata. The protocol
reference is in [docs/kasa-protocol.md](docs/kasa-protocol.md).

## Dependencies

- [CMake](https://github.com/kitware/cmake) 3.20 or newer.
- A C++17 compiler.
- [OpenSSL](https://www.openssl.org/) Crypto and SSL development files.
- The [Lgi](https://github.com/memecode/lgi) source tree at `../lgi/trunk`,
  relative to this project directory.

Lgi's platform-specific build dependencies are also required. On Linux, this
project builds Lgi's GTK backend and therefore needs its development packages
available to CMake.

## Build

From the `cpp-kasa` project directory:

```sh
cmake -S . -B build
cmake --build build
```

The build produces the `cpp-kasa` library and the `util` command-line
executable in the build directory.

## Command-Line Utility

```text
util discover
util get <ip|deviceName> [<username> <password>]
util set <ip|deviceName> <on|off> [<username> <password>]
```

`discover` automatically runs both discovery backends.
Device replies are pretty printed as JSON. The `get` and `set` commands discover
the target and automatically select legacy XOR or SMART control. SMART devices
require the device's account username and password as the final two arguments;
legacy devices do not require credentials and ignore them if supplied. Credentials
must be supplied together. Set commands use explicit on/off state. Protocol
selection waits for discovery to finish so modern replies can supersede legacy ones.

For example, after building:

```sh
./build/util discover
./build/util get 192.168.1.50
./build/util set 192.168.1.50 on
./build/util get 192.168.1.51 user@example.com password
./build/util set 192.168.1.51 off user@example.com password
```

## Library API

Include `cpp-kasa/cpp-kasa.h` and use `LKasaProtocol`:

```cpp
#include <cstdio>
LKasaProtocol kasa;

kasa.Discover([](const LKasaDevice &device)
{
	printf("%s: %s\n", device.Ip.Get(), device.Response.Get());
});

kasa.Connect("192.168.1.50", [&](bool connected, const LString &message)
{
	if (!connected)
	{
		printf("%s\n", message.Get());
		return;
	}
	kasa.GetSysInfo([](bool success, const LString &response)
	{
		printf("%s: %s\n", success ? "response" : "error", response.Get());
	});
});

// Use a separate instance for a separate device connection.
LKasaProtocol smart;
smart.ConnectSmart("192.168.1.51", "username", "password",
	[&](bool connected, const LString &message)
	{
		if (connected)
			smart.GetDeviceInfo([](bool success, const LString &response)
			{
				printf("%s: %s\n", success ? "response" : "error", response.Get());
			});
		else
			printf("%s\n", message.Get());
	});
```

`Discover()` uses directed broadcast addresses when no target is supplied, or
unicasts to a supplied IP address or hostname. It automatically probes both
discovery protocols, takes a `TDeviceCb` (`std::function<void(const LKasaDevice &)>`),
and calls it as each device arrives, with its source IP and raw JSON response.
The device reference is valid only during the callback. To retain device data
on another thread, deep-copy its strings with `LString::Set()` or `std::string`;
ordinary `LString` copies share storage with a non-atomic reference count.
All network methods return immediately after queueing work on a per-instance
FIFO worker. Their boolean return value means the operation was accepted, not
that it succeeded. `Connect()`, `Request()`, `GetSysInfo()`, `SetRelayState()`,
`ConnectSmart()`, `GetDeviceInfo()`, and `SetDeviceOn()` require a `TStatusCb`
(`std::function<void(bool, const LString &)>`). It receives success and response
JSON, or failure and an error message. Successful connections have an empty
message. Request inputs, device metadata, and credentials are copied at submission.

Each instance has a thread-safe timeout setting, initially 5000 ms
(`DefaultTimeoutMs`). Use `GetTimeout()` to read it and `SetTimeout(milliseconds)`
to change it. The setter returns `false` for nonpositive values without changing
the setting. All discovery, connection, and request operations use this setting,
including requests on existing connections. Each operation snapshots the timeout
when submitted; later changes do not affect queued or running operations. Timeout
counting starts when work executes, not while waiting in the queue.

Discovery accepts an optional completion callback:
`Discover(onDevice, targetIp, onComplete)`. Completion reports whether any devices
replied. `Disconnect()` also queues behind earlier operations.

Completion callbacks run on the instance's worker. Discovery invokes device
callbacks serially on its discovery threads. Callback references are only valid
during the call.
Callbacks may enqueue more operations, but must not wait for those operations,
destroy the instance, or throw. Dispatch UI work to the UI thread.
`IsConnected()` and `GetError()` return synchronized snapshots of the last completed
operation, without waiting for pending work.

Keep the instance and callback captures alive until all desired callbacks have
finished. Destruction rejects further submissions, discards queued work, cancels
active discovery and socket I/O, joins the worker, and closes the connection.
Cancelled work does not deliver completion callbacks. No callbacks remain running
after destruction returns. Discovery checks cancellation at intervals of at most
50 ms; network sockets use Lgi's cancellable waits instead of waiting for the full
configured timeout. An already-running callback must return before destruction
can finish. Platform DNS resolution and cryptographic work already in progress
may also delay shutdown because they cannot be interrupted by socket cancellation.
Destroy instances on their owning thread, not from a callback. If callbacks enqueue
follow-up work, keep the instance alive until that chain completes: follow-up
submissions are rejected once destruction begins. The command-line utility waits
for completion explicitly.
