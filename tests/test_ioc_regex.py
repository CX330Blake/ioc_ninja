#!/usr/bin/env python3
# English strings/comments per project rules.

import re
import sys
import os

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE not in sys.path:
    sys.path.insert(0, BASE)

import types

bn = types.ModuleType("binaryninja")
bn_log = types.ModuleType("binaryninja.log")


def _log_info(msg):
    pass


bn_log.log_info = _log_info
sys.modules["binaryninja"] = bn
sys.modules["binaryninja.log"] = bn_log

from core import ioc_logic


def run_tests():
    patterns = ioc_logic.IOC_PATTERNS
    tests = {}

    def add(kind, samples):
        tests.setdefault(kind, []).extend(samples)

    # IPv4
    add(
        "IPv4",
        [
            ("Contact 192.168.1.1 for access", True),
            ("Edge 255.255.255.255 ok", True),
            ("Invalid 256.0.0.1", False),
            ("Short 1.2.3", False),
            ("Leading zeros 001.002.003.004", True),
            ("1.2.3.4.5 extra", True),  # Matches '1.2.3.4'
            ("1.2.3.4x", False),
            ("1.2.3.4 ", True),
            ("foo1.2.3.4bar", False),
            ("0.0.0.0 is valid", True),
            ("An IP in brackets [10.0.0.1]", True),
            ("An IP with a port 127.0.0.1:8080", True),
        ],
    )

    # IPv6 (basic coverage)
    add(
        "IPv6",
        [
            ("dead:beef:0:0:0:8a2e:370:7334", True),
            ("::1 loopback", True),
            ("2001:db8::8a2e:370:7334", True),
            ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", True),  # Full
            (":::::::", False),
            ("2001:db8:::1", False),
            ("[2001:db8::1]", True),
            ("2001:db8::1g", False),
            ("2001:db8::1 ", True),
            ("not an ipv6", False),
            ("fe80::1%lo0", True),
            ("::ffff:192.168.1.1", True),  # IPv4-mapped
        ],
    )

    # Domain
    add(
        "Domain",
        [
            ("Visit example.com", True),
            ("sub.domain.co.uk", True),
            ("-bad.com", False),
            ("bad-.com", False),
            ("no_tld", False),
            ("a.b", False),  # TLD too short
            ("valid-hyphen.com", True),
            ("x" * 63 + ".com", True),  # Max label length
            ("x" * 64 + ".com", False),  # Label too long
            ("foo.example.com.", True),  # Trailing dot is not part of match
            ("example.c", False),  # TLD too short
            ("123.com", True),  # Numeric label
            ("domain.ending-with-hyphen-", False),
        ],
    )

    # URL
    add(
        "URL",
        [
            ("http://example.com", True),
            ("https://example.com/path?q=1", True),
            ("https://1.2.3.4:8080/", True),
            ("https://[2001:db8::1]/a", True),
            ("ftp://example.com", False),
            ("http://", False),
            ("https://bad host", False),
            ("https://example.com)", True),
            ("https://example.com]", True),
            ("https://example.com'", True),
            ("http://localhost:3000", True),
            ("https://example.com/a/b#fragment", True),
            ("http://user:pass@example.com", False),  # Basic auth not supported
        ],
    )

    # Email
    add(
        "Email",
        [
            ("user@example.com", True),
            ("USER+tag@sub.example.co", True),
            ("a@b", False),
            ("user.name@example.com", True),
            ("user_name@example.com", True),
            ("toolonglocalpart" * 10 + "@example.com", False),
            ("user@-bad.com", False),
            ("user@bad-.com", False),
            ("user@exa_mple.com", False),  # Underscore in domain
            ("user@example.comm", True),
            ("user@example", False),  # No TLD
            ("user@.example.com", False),
            (".user@example.com", True),  # local part can start with dot
            ("user.@example.com", True),  # local part can end with dot
        ],
    )

    # UUID
    add(
        "UUID",
        [
            ("550e8400-e29b-41d4-a716-446655440000", True),
            ("550e8400e29b41d4a716446655440000", False),
            ("g50e8400-e29b-41d4-a716-446655440000", False),
            ("00000000-0000-0000-0000-000000000000", True),
            ("uuid=550e8400-e29b-41d4-a716-446655440000", True),
            ("upper 550E8400-E29B-41D4-A716-446655440000", True),
            ("short 550e8400-e29b-41d4-a716-44665544000", False),
            ("550e8400-e29b-41d4-a716-446655440000x", False),
            ("{550e8400-e29b-41d4-a716-446655440000}", True),
        ],
    )

    # MAC
    add(
        "MAC",
        [
            ("aa:bb:cc:dd:ee:ff", True),
            ("AA-BB-CC-DD-EE-FF", True),
            ("aabb.ccdd.eeff", True),
            ("aa:bb:cc:dd:ee", False),
            ("aa:bb:cc:dd:ee:ff:00", False),
            ("gg:bb:cc:dd:ee:ff", False),
            ("random aabbccddeeff", False),
            ("aa-bb-cc-dd-ee-ff ", True),
            (" aabb.ccdd.eeff", True),
            ("AA:BB:CC:DD:EE:FG", False),
        ],
    )

    # Hashes
    add(
        "MD5",
        [
            ("d41d8cd98f00b204e9800998ecf8427e", True),
            ("D41D8CD98F00B204E9800998ECF8427E", True),
            ("too short d41d8cd98f00b204e9800998ecf8427", False),
            ("wrap d41d8cd98f00b204e9800998ecf8427ex", False),
            ("in text: d41d8cd98f00b204e9800998ecf8427e!", True),
            ("not hash: z41d8cd98f00b204e9800998ecf8427e", False),
            ("spaces d41d8cd98f00b204e9800998ecf8427e ", True),
            ("prefixmd5d41d8cd98f00b204e9800998ecf8427e", False),
            ("32chars but not hex: g" * 32, False),
            ("", False),
        ],
    )

    add(
        "SHA1",
        [
            ("da39a3ee5e6b4b0d3255bfef95601890afd80709", True),
            ("DA39A3EE5E6B4B0D3255BFEF95601890AFD80709", True),
            ("short da39a3ee5e6b4b0d3255bfef95601890afd8070", False),
            ("endx da39a3ee5e6b4b0d3255bfef95601890afd80709x", False),
            ("wrap da39a3ee5e6b4b0d3255bfef95601890afd80709.", True),
            ("g in sha g a39a3...", False),
            ("  da39a3ee5e6b4b0d3255bfef95601890afd80709 ", True),
            ("blah", False),
            ("A" * 40, True),
            ("A" * 39, False),
        ],
    )

    add(
        "SHA256",
        [
            ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", True),
            ("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855", True),
            ("short e3b0c44298fc1c1...", False),
            ("endx e3b0c4...b855x", False),
            (
                "trail e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855,",
                True,
            ),
            ("nonhex g3b0...", False),
            (
                "spaces e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 ",
                True,
            ),
            ("A" * 64, True),
            ("A" * 63, False),
            ("", False),
        ],
    )

    # Base64
    add(
        "Base64_block",
        [
            ("YWJjZGVmZ2hpamtsbW5vcA==", True),
            ("abcd", False),
            ("aGVsbG8= world", True),
            ("not/=base64==", False),
            ("Zg==", False),
            ("QUJDRA==", True),
            ("Zm9vYmFyYmF6", True),
            ("Zm9vYmFyYmF6=", True),
            ("Zm9v*YmFy", False),
            ("AAAAB3NzaC1yc2EAAAADAQABAAABAQC/+++==", True),
        ],
    )

    # WinPath
    add(
        "WinPath",
        [
            (r"C:\\Windows\\System32\\cmd.exe", True),
            (r"C:\\Program Files\\App\\app.exe", True),
            (r"C:/Windows/System32/cmd.exe", False),
            (r"\\\\server\\\\share\\\\dir\\\\file.txt", True),
            (r"C:\\bad|name\\x", False),
            (r"C:\\Trailing\\", True),
            (r"Z:\\a b\\c.txt", True),
            (r"C:\\con", True),
            (r"C:\\", True),
            (r"not\\a\\path", False),
        ],
    )

    # UnixPath
    add(
        "UnixPath",
        [
            ("/usr/bin/env", True),
            ("/var/log/syslog", True),
            ("/", False),
            ("relative/path", False),
            ("/a-b_c.d/e_f-g", True),
            ("/root/.hidden", True),
            ("/spaces not/ok", False),
            ("/tmp/..", True),
            ("/tmp/", True),
            ("/path/with:colon", False),
        ],
    )

    # Registry
    add(
        "Registry",
        [
            (r"HKEY_LOCAL_MACHINE\\Software\\Microsoft", True),
            (r"HKEY_CURRENT_USER\\Control Panel\\Desktop", True),
            (r"HKLM\\Software", False),
            (r"HKEY_LOCAL_MACHINE/Software", False),
            (r"HKEY_CLASSES_ROOT\\.txt", True),
            (r"HKEY_USERS\\S-1-5-21", True),
            (r"HKEY_\\Foo", False),
            (r"HKEY_LOCAL_MACHINE\\", True),
            (r"Not a key", False),
        ],
    )

    # UserAgent header
    add(
        "UserAgent_hdr",
        [
            ("User-Agent: curl/7.64.1", True),
            ("user-agent: Mozilla/5.0", True),
            (
                "require('https').request({ hostname: 'twist2katz.com', path: '/api/getapicn?key=%s', headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML",
                True,
            ),
            ("No header", False),
            ("User-Agent:", False),
            ("User-Agent: x", True),
            ("X-User-Agent: foo", False),
            ("User-Agent:Chrome", True),
            ("UA: foo", False),
            (" user-agent: bar", True),
            ("User-Agent: CR\nLF", True),
        ],
    )

    add(
        "UserAgent_js",
        [
            (
                r"'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML'",
                True,
            ),
            ("'User-Agent': 'curl/7.64.1'", True),
            ("'user-agent': 'Mozilla/5.0'", True),
            ("No header", False),
            ("'User-Agent':''", True),
            ("'User-Agent': 'x'", True),
            ("'X-User-Agent': 'foo'", False),
            ("'User-Agent':'Chrome'", True),
            ("UA: 'foo'", False),
            (" 'user-agent': 'bar'", True),
        ],
    )

    # JWT
    add(
        "JWT",
        [
            (
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0IiwibmFtZSI6IkpvZSIsImlhdCI6MTUxNjIzOTAyMn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                True,
            ),
            ("eyJ.x.y", True),
            ("notjwt.aaa", False),
            ("eyJ....", False),
            ("eyJabc.def.ghi", True),
            (" header eyJ... . ..", True),
            ("eyJ-._.", True),
            ("短", False),
            ("eyJ/abc.def.ghi", False),
            ("eyJabc.def", False),
        ],
    )

    # AWS access key
    add(
        "AWS_AK",
        [
            ("AKIA1234567890ABCD", True),
            ("ASIA1234567890ABCD", True),
            ("AKIA123", False),
            ("BKIA1234567890ABCD", False),
            ("AKIA1234567890ABCDE", False),
            ("prefixAKIA1234567890ABCDsuffix", True),
            (" akia1234567890abcd ", True),
            ("AKIA1234567890ABC1", True),
            ("AKIA1234567890ABC_", False),
            ("AKIAABCDEFGHIJKLMNOP", True),
        ],
    )

    # Google API
    add(
        "Google_API",
        [
            ("AIzaSyA-1234567890123456789012345678901", True),
            ("AIzaSyA_1234567890123456789012345678901", True),
            ("AIzaSy123", False),
            ("key=AIzaSyA-1234567890123456789012345678901&x", True),
            ("AIzaSyA-!234567890123456789012345678901", False),
            ("random AIzaSyA-1234567890123456789012345678901", True),
            ("A I z a", False),
            ("AIzaSyA-12345678901234567890123456789012", True),
            ("AIzaSyA-123456789012345678901234567890", False),
            ("", False),
        ],
    )

    # OpenAI secret
    add(
        "OpenAI_SG",
        [
            ("sk-1234567890abcdefghijklmnopqrstuvwx", True),
            ("SK-abcdef" * 6, True),
            ("sk-", False),
            (" sk-abc ", True),
            ("token sk_abcdef", False),
            ("sk-中文", False),
            ("ssk-abcdef", False),
            ("xsk-abcdef", True),
            ("sk-abcdefg=", False),
            ("sk-12345678901234567890123456789012", True),
        ],
    )

    # RSA PEM
    add(
        "RSA_PEM",
        [
            ("-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----", True),
            (
                "-----BEGIN RSA PRIVATE KEY-----\nAAA\n-----END RSA PRIVATE KEY-----",
                True,
            ),
            ("-----BEGIN PRIVATE KEY----- bad -----END PRIVATE KEY-----", True),
            ("-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----", False),
            ("BEGIN PRIVATE KEY-----", False),
            ("-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----", True),
            ("-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----", True),
            (
                "-----BEGIN DSA PRIVATE KEY-----\nAAA\n-----END DSA PRIVATE KEY-----",
                False,
            ),
            ("randomkey", False),
            ("-----END PRIVATE KEY-----", False),
        ],
    )

    add(
        "RSA_PUB_PEM",
        [
            ("-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----", True),
            (
                "-----BEGIN RSA PUBLIC KEY-----\nAAA\n-----END RSA PUBLIC KEY-----",
                False,
            ),
            ("no headers", False),
            ("BEGIN PUBLIC KEY-----", False),
            ("-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----", True),
            ("-----BEGIN PUBLIC KEY----- AAA -----END PUBLIC KEY-----", True),
            ("-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----", False),
            ("-----BEGIN PUBLIC KEY-----\nAAA\n---END---", False),
            (
                "xxxxx-----BEGIN PUBLIC KEY-----\nAAA\n-----END PUBLIC KEY-----yyyy",
                True,
            ),
            ("", False),
        ],
    )

    add(
        "Mutex",
        [
            ("Global\\MyAppMutex", True),
            ("name-mutex", True),
            ("short mtx", False),
            ("mutex", True),
            ("aaaMutex", True),
            ("Z_9-Mutex", True),
            ("__Mutex", False),
            ("toolong" * 20 + "Mutex", False),
            ("abc_mutex", True),
            ("abc-mutext", False),
        ],
    )

    add(
        "XOR_or_ROT_keyword",
        [
            ("xor", True),
            ("ROT13", True),
            ("rot", True),
            ("proto", False),
            ("xors", False),
            ("rotate", False),
            ("mix xor rot", True),
            ("XoR", True),
            ("r0t", False),
            ("", False),
        ],
    )

    add(
        "Process_or_Command",
        [
            ("/usr/bin/ls", True),
            ("/bin/sh", True),
            (r"C:\\Windows\\System32\\cmd.exe", True),
            (r"C:\\Windows\\SysWOW64\\powershell.exe", True),
            ("/opt/bin/custom", False),
            ("C:/Windows/System32/cmd.exe", False),
            ("/bin/", False),
            ("/usr/bin/../bin/bash", True),
            ("/usr/bin/python3.10", True),
            ("something.cmd", False),
        ],
    )

    # Now actually run tests
    total = 0
    failed = 0
    for kind, cases in tests.items():
        # Special handling for composite or validated types
        allowed_types = {kind}
        if kind in ("Base64", "Base64_block"):
            # Ensure both the regex pattern and the validation/decoding heuristic
            # are available when testing Base64 variants.
            allowed_types.update({"Base64", "Base64_block"})

        # Build a reduced pattern dict so the matcher only iterates required regexes.
        # This speeds up tests and mirrors how callers can optimize scanning by
        # limiting the pattern set.
        patterns_subset = {
            k: ioc_logic.IOC_PATTERNS[k]
            for k in allowed_types
            if k in ioc_logic.IOC_PATTERNS
        }

        for s, expect in cases:
            total += 1
            # Use the actual matching logic from the library, but restrict patterns
            # to the pre-filtered subset for performance.
            matches = ioc_logic.match_iocs_in_string(
                s, patterns=patterns_subset, allowed_types=allowed_types
            )
            ok = bool(matches.get(kind))

            if ok != expect:
                failed += 1
                print(f"[FAIL] {kind}: expect={expect} got={ok} | '{s}'")

    print(f"\nSummary: {total - failed}/{total} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(run_tests())
