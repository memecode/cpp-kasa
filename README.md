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
- Protocol-specific `DiscoverLegacy()` and `DiscoverModern()` methods are also
	available.
- Legacy device control uses XOR-over-TCP on port 9999, with IOT commands such
	as `get_sysinfo` and `set_relay_state`.
- Standard SMART switch control supports the advertised HTTP AES or KLAP v1/v2
	transport, account credentials, `get_device_info`, and `set_device_info` for
	the `device_on` state.

Modern control currently requires plain HTTP. HTTPS, cameras, hubs, robovacs,
child devices, and other specialized command families are not supported.
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
util discover-modern
util get <ip|deviceName>
util set <ip|deviceName> <on|off>
util smart-get <ip|deviceName> <username> <password>
util smart-set <ip|deviceName> <username> <password> <on|off>
```

`discover` runs both discovery backends. `discover-modern` runs only modern TDP
discovery. Device replies are pretty printed as JSON. The `get` and `set`
commands use legacy XOR control; `smart-get` and `smart-set` discover and log in
to a standard SMART switch. SMART commands require the device's account
username and password. Set commands use explicit on/off state.

For example, after building:

```sh
./build/util discover
./build/util get 192.168.1.50
./build/util set 192.168.1.50 on
./build/util smart-get 192.168.1.51 user@example.com password
./build/util smart-set 192.168.1.51 user@example.com password off
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
unicasts to a supplied IP address or hostname. `Discover()`, `DiscoverLegacy()`,
and `DiscoverModern()` take a `TDeviceCb` (`std::function<void(const LKasaDevice &)>`)
and call it as each device arrives, with its source IP and raw JSON response.
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

Completion callbacks run on the instance's worker. Combined discovery invokes
device callbacks serially on its discovery threads; protocol-specific discovery
invokes them on the worker. Callback references are only valid during the call.
Callbacks may enqueue more operations, but must not wait for those operations,
destroy the instance, or throw. Dispatch UI work to the UI thread.
`IsConnected()` and `GetError()` return synchronized snapshots of the last completed
operation, without waiting for pending work.

Keep the instance and callback captures alive until all desired callbacks have
finished. Destruction rejects further submissions, drains accepted work, joins the
worker, and then closes the connection; it can block until network timeouts expire.
Destroy instances on their owning thread, not from a callback. If callbacks enqueue
follow-up work, keep the instance alive until that chain completes: follow-up
submissions are rejected once destruction begins. The command-line utility waits
for completion explicitly.
