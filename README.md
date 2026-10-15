# cpp-kasa

`cpp-kasa` is a small C++ library for discovering Kasa devices and sending basic
commands to legacy Kasa devices on a local network. It uses Lgi for networking
and JSON handling.

## Protocol Support

- Combined discovery probes both legacy XOR discovery (UDP port 9999) and modern
	TDP discovery (UDP ports 20002 and 20004) concurrently. Results are deduplicated
	by source IP, preferring the modern response when both backends find the same
	address. Each backend has a five-second timeout.
- Protocol-specific `DiscoverLegacy()` and `DiscoverModern()` methods are also
	available.
- Device control currently supports the legacy XOR-over-TCP transport on port
	9999, with IOT JSON requests such as `get_sysinfo` and `set_relay_state`.

Modern discovery does not imply modern-device control support. HTTP AES, KLAP,
camera transports, authentication, and SMART commands are not currently
implemented. The protocol reference is in [docs/kasa-protocol.md](docs/kasa-protocol.md).

## Dependencies

- CMake 3.20 or newer
- A C++17 compiler
- OpenSSL Crypto development files
- The Lgi source tree at `../lgi/trunk`, relative to this project directory

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
```

`discover` runs both discovery backends. `discover-modern` runs only modern TDP
discovery. Device replies are printed as JSON with two-space indentation. The
`get` and `set` commands use the legacy XOR control transport; `set` sets the
relay to an explicit state.

For example, after building:

```sh
./build/util discover
./build/util get 192.168.1.50
./build/util set 192.168.1.50 on
```

## Library API

Include `cpp-kasa/cpp-kasa.h` and use `LKasaProtocol`:

```cpp
#include <cstdio>
LKasaProtocol kasa;
LArray<LKasaDevice> devices;

if (kasa.Discover(devices))
{
		for (auto &device : devices)
				printf("%s: %s\n", device.Ip.Get(), device.Response.Get());
}

LString response;
if (kasa.Connect("192.168.1.50") && kasa.GetSysInfo(response))
		printf("%s\n", response.Get());
```

`Discover()` uses directed broadcast addresses when no target is supplied, or
unicasts to a supplied IP address or hostname. Discovery returns each source IP
and the device's raw JSON response. Control methods return `false` on failure;
use `GetLastError()` for the associated Lgi error code and message.
