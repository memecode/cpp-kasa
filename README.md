# cpp-kasa

`cpp-kasa` is a small C++ library for discovering Kasa devices and sending basic
commands to legacy and standard SMART switches on a local network. It uses Lgi
for networking and JSON handling.

## Protocol Support

- Combined discovery probes both legacy XOR discovery (UDP port 9999) and modern
	TDP discovery (UDP ports 20002 and 20004) concurrently. Results are deduplicated
	by source IP, preferring the modern response when both backends find the same
	address. Each backend has a five-second timeout.
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
LArray<LKasaDevice> devices;

if (kasa.Discover(devices))
{
    for (auto &device : devices)
        printf("%s: %s\n", device.Ip.Get(), device.Response.Get());
}

LString response;
if (kasa.Connect("192.168.1.50") && kasa.GetSysInfo(response))
    printf("%s\n", response.Get());

if (kasa.DiscoverModern(devices) && devices.Length() &&
	kasa.ConnectSmart(devices[0], "username", "password") &&
	kasa.GetDeviceInfo(response))
	printf("%s\n", response.Get());
```

`Discover()` uses directed broadcast addresses when no target is supplied, or
unicasts to a supplied IP address or hostname. Discovery returns each source IP
and the device's raw JSON response. Control methods return `false` on failure;
use `GetLastError()` for the associated Lgi error code and message. SMART
switch commands use `ConnectSmart()` followed by `GetDeviceInfo()` or
`SetDeviceOn()`.
