# WPA3 External Supplicant Library - WPA3 SAE Authentication for ModusToolbox

# Overview

The **WPA3 External Supplicant** library provides WPA3 SAE (Simultaneous Authentication of Equals, also known as the Dragonfly Key Exchange) authentication support using the Hunting and Pecking (HnP) method ([RFC 7664](https://datatracker.ietf.org/doc/html/rfc7664)) and the Hash-to-Element (H2E) method ([draft-irtf-cfrg-hash-to-curve-10](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-10)), following the IEEE 802.11 specification (2016). This library is typically included as a dependency by Wi-Fi connection manager libraries and is not directly used by most application developers.

The library includes an SAE finite state machine, a cryptographic module supporting ECP Group 19 (NIST P-256 elliptic curve) operations via Mbed TLS or NetX Secure, and interfaces with the WiFi-Host-Driver (WHD) to set PMK/PMKID for WPA3 Access Point connectivity.

## Software Requirements
This version of the library was validated for compatibility with the following Software and Tools:

| Software and Tools                                      | Version |
| :---                                                    | :----:  |
| ModusToolbox&trade; software                            | 3.9     |
| ModusToolbox&trade; Device Configurator                 | 5.90.0  |
| GCC Compiler                                            | 14.2.1  |
| IAR Compiler (only for ModusToolbox&trade;)             | 9.50.2  |
| Arm® Compiler 6                                         | 6.22    |
| LLVM compiler                                           | 22.1.0  |

# Related Middleware and Dependencies

**This library is used by:**
- [Wi-Fi Connection Manager (WCM)](https://github.com/Infineon/wifi-connection-manager) - Manages Wi-Fi connections including WPA3 authentication
- WiFi Certified test infrastructure - Supports WPA3-R3 (Personal) certification

**This library depends on:**

- [Mbed TLS](https://github.com/Mbed-TLS/mbedtls) - Cryptographic operations (ECP, HMAC, HKDF) for the COMPONENT_MBEDTLS configuration
- [NetX Secure](https://github.com/eclipse-threadx/netxduo) - Cryptographic operations for the COMPONENT_NETXSECURE configuration
- [WiFi Host Driver (WHD)](https://github.com/Infineon/wifi-host-driver) - Wi-Fi driver interface for PMK/PMKID provisioning and EAPOL key exchange
- [Abstraction RTOS](https://github.com/Infineon/abstraction-rtos) - RTOS abstraction layer

# Release Notes and Changelog

- [RELEASE.md](./RELEASE.md) - Detailed release notes for all versions

# License

This library is subject to Infineon software license terms.

- [LICENSE](https://github.com/Infineon/wpa3-external-supplicant/blob/master/LICENSE.txt)

# Copyright

(c) 2026, Infineon Technologies AG, or an affiliate of Infineon
Technologies AG.  All rights reserved.

