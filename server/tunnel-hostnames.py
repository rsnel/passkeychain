#!/usr/bin/env python3
"""List the tunnel server hostnames a browser can compute for itself.

A caBLE v2 (hybrid) phone tells the browser which tunnel server it uses with
a 16-bit number in its Bluetooth advert. Numbers 0-255 are a fixed list built
into the browser (0 is Google's cable.ua5v.com). For 256-65535 the browser
computes the hostname from the number (Chromium's tunnelserver::DecodeDomain):

    digest = SHA-256("caBLEv2 tunnel server domain" || number (2 bytes, LE) || 0x00)
    v      = the first 8 digest bytes as a little-endian integer
    tld    = ["com", "org", "net", "info"][v & 3]
    label  = base32 (a-z, 2-7) of v >> 2, least significant 5 bits first
    host   = "cable." + label + "." + tld

To run your own tunnel server, pick a number whose domain (label.tld) is
still free, register that domain and point cable.<label>.<tld> at the server.

Usage:
    tunnel-hostnames.py                       all 65280 hostnames
    tunnel-hostnames.py --tld org --limit 20  the first 20 ending in .org
    tunnel-hostnames.py --number 266          one number
    tunnel-hostnames.py --check --limit 10    look up (RDAP) until 10 seem free
    tunnel-hostnames.py --self-test           check against Chromium's test value
"""

import argparse
import hashlib
import json
import struct
import sys
import time
import urllib.error
import urllib.request

BASE32 = "abcdefghijklmnopqrstuvwxyz234567"
TLDS = ["com", "org", "net", "info"]
FIRST = 256  # below this the numbers are the browser's fixed list


def hostname(number: int) -> str:
    """The hostname a browser computes for tunnel server domain [number] (256-65535)."""
    if not FIRST <= number <= 0xFFFF:
        raise ValueError(f"computed domains are 256-65535, not {number}")
    data = b"caBLEv2 tunnel server domain" + struct.pack("<H", number) + b"\x00"
    v = struct.unpack("<Q", hashlib.sha256(data).digest()[:8])[0]
    tld = TLDS[v & 3]
    v >>= 2
    label = ""
    while v:
        label += BASE32[v & 31]
        v >>= 5
    return f"cable.{label}.{tld}"


def registrable(host: str) -> str:
    """The domain to register: the hostname without its "cable." prefix."""
    return host[len("cable."):]


def rdap_status(domain: str) -> str:
    """'taken', 'free?' or 'unknown (...)', from the registry's RDAP service via rdap.org."""
    request = urllib.request.Request(
        "https://rdap.org/domain/" + domain,
        headers={"Accept": "application/rdap+json", "User-Agent": "tunnel-hostnames"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            json.load(response)
            return "taken"
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return "free?"  # the registry has no record; confirm at a registrar
        return f"unknown (HTTP {e.code})"
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        return f"unknown ({e})"


def self_test() -> bool:
    # Chromium's v2_handshake_unittest.cc: KnownDomainID(266) -> cable.wufkweyy3uaxb.com
    got = hostname(266)
    ok = got == "cable.wufkweyy3uaxb.com"
    print(("ok" if ok else "FAILED") + f": 266 -> {got}")
    return ok


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--number", type=int, help="show the hostname for one number")
    p.add_argument("--tld", choices=TLDS, help="only hostnames ending in this TLD")
    p.add_argument("--start", type=int, default=FIRST, help="first number (default 256)")
    p.add_argument("--limit", type=int, help="stop after this many results (with --check: free ones)")
    p.add_argument("--check", action="store_true",
                   help="look each domain up via RDAP (rdap.org) and show only those that seem free")
    p.add_argument("--delay", type=float, default=1.0, help="seconds between RDAP lookups (default 1)")
    p.add_argument("--self-test", action="store_true", help="check the algorithm against Chromium")
    a = p.parse_args()

    if a.self_test:
        return 0 if self_test() else 1
    if a.number is not None:
        host = hostname(a.number)
        print(f"{a.number}\t{host}\tregister: {registrable(host)}")
        return 0

    found = 0
    for number in range(max(a.start, FIRST), 0x10000):
        host = hostname(number)
        if a.tld and not host.endswith("." + a.tld):
            continue
        if a.check:
            status = rdap_status(registrable(host))
            print(f"{number}\t{host}\t{status}", file=sys.stderr)
            time.sleep(a.delay)
            if status != "free?":
                continue
            print(f"{number}\t{host}\tregister: {registrable(host)}", flush=True)
        else:
            print(f"{number}\t{host}")
        found += 1
        if a.limit and found >= a.limit:
            break
    return 0


if __name__ == "__main__":
    sys.exit(main())
