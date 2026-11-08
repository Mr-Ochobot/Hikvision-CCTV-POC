<div align="center">

<img src="https://pngset.com/images/hikvision-europe-colorvu-camera-hikvision-cctv-camera-transparent-png-2854157.png" alt="Cctv" height="72">

# Hikvision CCTV — CVE-2017-7921 Proof of Concept

**Authorized security assessment tool for Hikvision camera and NVR devices**

<img src="https://img.shields.io/badge/DEVICE-CCTV%20%2F%20NVR-263238?style=for-the-badge&logo=securityscorecard&logoColor=white" alt="CCTV / NVR">
<img src="https://img.shields.io/badge/LANGUAGE-Python%203-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3">
<img src="https://img.shields.io/badge/CVE-2017--7921-B22222?style=for-the-badge" alt="CVE-2017-7921">

</div>

---

## Overview

This project is a single-target proof of concept (PoC) for assessing exposure to **CVE-2017-7921**, an authentication-bypass vulnerability affecting certain Hikvision IP camera and NVR firmware.

The script attempts to retrieve a device configuration file and, when the returned data matches the format implemented in this PoC, decrypts and parses it to identify administrator records. It can also attempt to retrieve a JPEG snapshot through the device's snapshot endpoint.

This tool is intended strictly for **authorized security testing**, such as assessing devices you own or systems for which you have explicit written permission.

> **Important:** A successful HTTP response does not, by itself, prove that a device is vulnerable. Firmware behavior, endpoint availability, configuration format, and device model can affect the result.

## Features

- Tests a single camera or NVR host.
- Checks a small set of authentication tokens used by this PoC.
- Requests the device configuration endpoint.
- Attempts to decrypt configuration data using the AES-128-ECB and per-file XOR steps implemented in the script.
- Searches the decoded configuration for administrator records.
- Masks discovered password values by default.
- Offers an explicit option to display full password values.
- Optionally saves the decoded configuration.
- Can attempt to retrieve a JPEG snapshot.
- Supports configurable port and request timeout.

## Technical workflow

At a high level, the script performs the following operations:

1. Builds an HTTP request to the target device.
2. Tries the predefined authentication tokens against `/System/configurationFile`.
3. Checks whether the response is successful and larger than the minimum expected size.
4. Truncates the response to a complete AES block boundary and attempts AES decryption.
5. Derives a per-file XOR value from the decrypted data and applies the XOR operation to 32-bit words.
6. Checks for the expected `SWKH` file signature.
7. Searches the decoded data for administrator records and extracts the associated password field.
8. Unless disabled, attempts to request a JPEG frame from `/onvif-http/snapshot`.

The implementation uses the first available AES provider:

- `pycryptodome` (`Crypto.Cipher.AES`), or
- `cryptography`.

The script does not automatically determine every affected Hikvision model or firmware version. Its result should be treated as an assessment signal and validated against the device's model, firmware, and vendor security guidance.

## Requirements

- Python 3.8 or later.
- Network connectivity to the authorized target.
- One of the supported AES libraries:
  - `pycryptodome`, or
  - `cryptography`.

The script uses Python standard-library modules for its HTTP and command-line operations.

## Installation

Clone or download this project, then open a terminal in the project directory.

Install one AES provider:

```bash
python3 -m pip install pycryptodome
```

Alternatively:

```bash
python3 -m pip install cryptography
```

No installation of both libraries is required.

## Usage

General syntax:

```bash
python3 hikvision.py <HOST> [OPTIONS]
```

Replace `<HOST>` with the IP address or hostname of a device that you own or are explicitly authorized to assess.

### Basic assessment

```bash
python3 hikvision.py 192.0.2.10
```

The default HTTP port is `80`. The script masks password values in its output.

### Specify a port

```bash
python3 hikvision.py 192.0.2.10 --port 8080
```

### Set the request timeout

```bash
python3 hikvision.py 192.0.2.10 --timeout 20
```

The timeout is specified in seconds.

### Save the decoded configuration

```bash
python3 hikvision.py 192.0.2.10 --save decoded-config.bin
```

The saved file contains decoded configuration data and may include sensitive information. Store it securely, restrict access to it, and remove it safely when it is no longer needed.

### Disable snapshot retrieval

```bash
python3 hikvision.py 192.0.2.10 --no-snapshot
```

### Choose the snapshot output path

```bash
python3 hikvision.py 192.0.2.10 --snapshot-out camera-frame.jpg
```

### Display full password values

```bash
python3 hikvision.py 192.0.2.10 --show
```

Use `--show` only when strictly necessary during an authorized assessment. Avoid terminal recordings, shared logs, screenshots, or reports that expose credentials. The default behavior masks password values.

## Example output

The following is an illustrative example of what a successful run may look like. The values shown are examples, not results from a real device.

```text
[*] Target: http://192.168.1.100:80
[+] Auth bypass accepted (token YWRtaW46MTIz...), got /System/configurationFile: 32768 bytes
[+] Server header: 'App-webs/'
[+] Decrypt OK: AES-128-ECB (key 279977f62f6c...) + derived per-file XOR (0x1A2B3C4D) -> magic 'SWKH' OK
[+] Vulnerable: 1 plaintext 'admin' record(s) in the downloaded configuration:
    rec#1  offset 0x000120  password: 'a****z' (6 chars)  [full: --show]
[+] Snapshot also works (45020 bytes JPEG) -> saved to snapshot_bypass.jpg
```

The password is masked by default. The `[full: --show]` note indicates that the complete value can be displayed by explicitly using `--show` during an authorized assessment. Actual output depends on the target device, firmware, response size, and whether the snapshot endpoint is available.

## Command-line options

| Option | Description | Default |
|---|---|---|
| `HOST` | Camera or NVR IP address / hostname | Required |
| `--port PORT` | HTTP service port | `80` |
| `--timeout SECONDS` | HTTP request timeout | `15` |
| `--show` | Display full password values instead of masking them | Disabled |
| `--save PATH` | Save the decoded configuration to a file | Not saved |
| `--no-snapshot` | Skip the snapshot request | Snapshot enabled |
| `--snapshot-out PATH` | Output path for the JPEG snapshot | `snapshot_bypass.jpg` |

## Understanding the output

Output messages should be interpreted carefully:

| Message or result | Meaning |
|---|---|
| `Auth bypass accepted` | The configuration endpoint returned a response accepted by this PoC. This is a strong indication that the tested access-control path should be investigated. |
| `Decrypt OK` | The response could be decoded using the algorithm and file signature expected by this script. |
| `Vulnerable` | The script found one or more administrator records in the decoded configuration. Treat the finding as evidence requiring controlled validation. |
| `Bypass not effective` | The endpoint did not return the expected response, or the device could not be reached. This does not conclusively prove that the device is secure. |
| `decrypt pipeline failed` | Data was retrieved, but it did not match the decoding format expected by this PoC. |
| `Snapshot also works` | The snapshot endpoint returned JPEG data. |
| `Snapshot channel unavailable` | The snapshot request did not return a JPEG image, or the device does not provide that channel. |

## Security considerations

This PoC handles potentially sensitive device information. Follow these precautions:

- Test only devices you own or are explicitly authorized to assess.
- Do not scan public IP ranges or unrelated devices.
- Do not publish configuration files, passwords, authentication tokens, or camera snapshots.
- Keep decoded configuration files and assessment output in access-controlled storage.
- Do not use `--show` unless full credential visibility is necessary.
- Use an isolated test environment whenever possible.
- Obtain authorization and define the permitted target, test window, and scope before testing.

The script communicates over **HTTP** as written. HTTP does not provide transport encryption. Do not assume that credentials or configuration data are protected in transit.

## Limitations

- The script targets one host per execution.
- It uses a fixed set of tokens and fixed decoding logic.
- It expects the configuration format and `SWKH` signature implemented in this PoC.
- It does not identify all Hikvision models or firmware versions affected by CVE-2017-7921.
- A failed test is not proof that a device is patched or otherwise secure.
- Snapshot retrieval depends on the endpoint and device video configuration.
- The script does not remediate vulnerabilities or change device settings.

## Recommended remediation

If an assessment indicates that a device may be affected:

1. Identify the exact device model, hardware revision, and firmware version.
2. Consult Hikvision's official security advisories and support resources for the applicable firmware.
3. Upgrade to a vendor-supported firmware version that addresses the vulnerability, where available.
4. Replace default or weak passwords with unique, strong credentials.
5. Restrict camera and NVR management interfaces to trusted networks.
6. Disable unnecessary services and remote access paths.
7. Avoid exposing camera management interfaces directly to the public internet.
8. Review access logs and investigate unexpected access to configuration or snapshot endpoints.
9. Re-test the device after remediation using an authorized, controlled process.

## Project structure

```text
.
├── hikvision.py
└── README.md
```

## Disclaimer

This repository is provided for educational purposes and authorized defensive security assessment. The author does not authorize or encourage unauthorized access, credential extraction, privacy violations, or disruption of devices and networks.

You are responsible for obtaining permission, complying with applicable laws, and ensuring that your testing remains within the agreed scope. The software is provided **as is**, without warranty of any kind.

## References

- [CVE-2017-7921 — National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2017-7921)
- [Hikvision — Official Website](https://www.hikvision.com/)
- [Python Documentation](https://docs.python.org/3/)

---

<div align="center">

**Python-based security assessment for authorized Hikvision CCTV environments**

</div>
