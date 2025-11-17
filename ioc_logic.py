import re
import math
import base64
from typing import Optional, List, Dict, Set, Tuple
from binaryninja.log import log_info

# English comments/strings per project rules.
# Simple IoC extraction plugin for Binary Ninja.
# Scans strings exposed by the BinaryView and matches many IoC patterns.
# Results are shown in a pop-up with checkboxes and a result message box.

# Use explicit pattern variables for complex strings to avoid escaping issues.
# Windows path（支援在字串中匹配整段路徑）。
# 整體作為單一捕獲，內部用非捕獲群組，避免 findall 只回傳子群組。
WINPATH_PATTERN = r"""((?:[a-zA-Z]\:|\\\\[\w\s\.]+\\[\w\s\.$]+)\\(?:[\w\s\.]+\\)*[\w\s\.]*?)"""
REGISTRY_PATTERN = r"""\bHKEY_[A-Z_]+\\[A-Za-z0-9_.\\]+\\?"""

# Improved and more precise patterns
# IPv6: compressed, full, and IPv4-mapped forms (practical coverage)
IPV6_PATTERN = r"""
(?:(?<![A-Fa-f0-9:])(
  (?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}|
  (?:[A-Fa-f0-9]{1,4}:){1,7}:|               # :: at end
  :(?::[A-Fa-f0-9]{1,4}){1,7}|               # :: at start
  (?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}|
  (?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}|
  (?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}|
  (?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}|
  (?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}|
  [A-Fa-f0-9]{1,4}:(?::[A-Fa-f0-9]{1,4}){1,6}|
  :(?::[A-Fa-f0-9]{1,4}){1,7}:?|
  (?:[A-Fa-f0-9]{1,4}:){6}(?:\d{1,3}\.){3}\d{1,3}
)(?!(?:[A-Fa-f0-9:])))
"""

# Domain: labels start/end alnum, hyphen allowed inside, final TLD alpha 2-63
DOMAIN_PATTERN = r"""
(?<![A-Za-z0-9-])
(
  (?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+
  (?:[A-Za-z]{2,63})
)
(?![A-Za-z0-9-])
"""

# URL: scheme:// (IPv6/IPv4/domain/localhost) optional port and path, avoid trailing quotes/brackets
URL_PATTERN = r"""
\bhttps?://
(?:
  \[[0-9A-Fa-f:]+\]|
  localhost|
  (?:\d{1,3}\.){3}\d{1,3}|
  (?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:[A-Za-z]{2,63})
)
(?::\d{2,5})?
(?:/(?:[^\s\)\]\"\']*)?)?
"""

# Email: local part up to 64, domain labels as above
EMAIL_PATTERN = r"""
(?<![A-Za-z0-9._%+\-])
(
  [A-Za-z0-9._%+\-]{1,64}@
  (?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+
  [A-Za-z]{2,63}
)
(?![A-Za-z0-9._%+\-])
"""

# MAC: 6 octets with : or -, or Cisco dotted form
MAC_PATTERN = r"""
\b(?:
  (?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}|
  [0-9A-Fa-f]{4}(?:\.[0-9A-Fa-f]{4}){2}
)\b
"""

IOC_PATTERNS = {
    "IPv4": re.compile(r'\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b'),
    "IPv6": re.compile(IPV6_PATTERN, re.VERBOSE),
    "Domain": re.compile(DOMAIN_PATTERN, re.VERBOSE),
    "URL": re.compile(URL_PATTERN, re.VERBOSE | re.IGNORECASE),
    "Email": re.compile(EMAIL_PATTERN, re.VERBOSE),
    "UUID": re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'),
    "MAC": re.compile(MAC_PATTERN, re.VERBOSE),
    # Hashes: inline matches with word boundaries
    "MD5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
    "SHA1": re.compile(r'\b[0-9a-fA-F]{40}\b'),
    "SHA256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
    # Base64（字串內匹配），由後續 decode 驗證去誤報
    "Base64_block": re.compile(r'(?<![A-Za-z0-9+/=])(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?![A-Za-z0-9+/=])'),
    "WinPath": re.compile(WINPATH_PATTERN),
    "UnixPath": re.compile(r'\b/(?:[\w\-.]+/)*[\w\-.]+/?\b'),
    "Registry": re.compile(r'\bHKEY_[A-Z_]+\\[A-Za-z0-9_.\\]+\\?'),
    "UserAgent_hdr": re.compile(r'(?im)^\s*User-Agent:\s*([^\r\n]+)'),
    "JWT": re.compile(r'\b[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b'),
    "AWS_AK": re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b', re.IGNORECASE),
    "Google_API": re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b'),
    "OpenAI_SG": re.compile(r'\bsk-[0-9a-zA-Z]{32,}\b', re.IGNORECASE),
    "RSA_PEM": re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA )?PRIVATE KEY-----'),
    "RSA_PUB_PEM": re.compile(r'-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----'),
    "Mutex": re.compile(r'\b[A-Za-z0-9_\-]{3,64}(?:Mutex|mutex)\b'),
    "XOR_or_ROT_keyword": re.compile(r'\b(?:xor|rot13|rot)\b', re.IGNORECASE),
    "Process_or_Command": re.compile(r'(?:/usr/bin/|/bin/|C:\\Windows\\System32\\|C:\\Windows\\SysWOW64\\)[\w\-\./\\]+'),
}

# Heuristic patterns (less strict)
HASH_LIKELY = re.compile(r'\b[a-f0-9]{32,64}\b', re.IGNORECASE)

# Entropy threshold for high-entropy identifiers
ENTROPY_THRESHOLD = 4.5
MIN_ENTROPY_LENGTH = 16

def shannon_entropy(data: str) -> float:
    """Compute Shannon entropy for a string (ASCII-based)."""
    if not data:
        return 0.0
    freq = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    length = float(len(data))
    for count in freq.values():
        p = count / length
        entropy -= p * math.log(p, 2)
    return entropy

def is_printable(s: str) -> bool:
    try:
        s.encode('utf-8')
    except Exception:
        return False
    # require at least some printable chars
    return all((31 < ord(c) < 127 or c in '\r\n\t') for c in s)

def collect_strings_from_bv(bv) -> List[Tuple[Optional[int], str]]:
    """Collect user-visible strings from the BinaryView."""
    results: List[Tuple[Optional[int], str]] = []
    try:
        # many Binary Ninja builds expose bv.get_strings()
        for sref in bv.get_strings():
            try:
                val = sref.value if hasattr(sref, 'value') else str(sref)
            except Exception:
                val = str(sref)
            if val:
                addr = sref.start if hasattr(sref, 'start') else None
                results.append((addr, val))
    except Exception:
        # fallback: try to read ASCII-like ranges via bv.read
        try:
            # attempt to get file length safely
            length = getattr(bv, 'end', None)
            if length is None:
                try:
                    length = bv.file.metadata.get('_length', 0)
                except Exception:
                    length = 0
            raw = bv.read(0, length) if length else b''
            cur = bytearray()
            for i, b in enumerate(raw):
                if 32 <= b < 127:
                    cur.append(b)
                else:
                    if len(cur) >= 4:
                        results.append((i - len(cur), cur.decode(errors='ignore')))
                    cur = bytearray()
            if len(cur) >= 4:
                results.append((len(raw) - len(cur), cur.decode(errors='ignore')))
        except Exception:
            pass
    return results

def match_iocs_in_string(
    s: str,
    patterns: Optional[Dict[str, re.Pattern]] = None,
    allowed_types: Optional[Set[str]] = None,
) -> Dict[str, Set[str]]:
    """Run all regexes and heuristics against a single string, return dict of findings.
    Only IoC names present in allowed_types are included in the result. If
    allowed_types is None, it defaults to the keys of `patterns` (or IOC_PATTERNS).
    """
    if patterns is None:
        patterns = IOC_PATTERNS
    if allowed_types is None:
        allowed_types = set(patterns.keys())

    findings: Dict[str, Set[str]] = {}
    if not s or not is_printable(s):
        return findings

    # Strict patterns (driven by UI checkboxes)
    for name, regex in patterns.items():
        if name not in allowed_types:
            continue
        try:
            for m in regex.findall(s):
                # findall may return tuples; normalize to string
                if isinstance(m, tuple):
                    m = m[0]
                if m is None:
                    continue
                findings.setdefault(name, set()).add(m.strip() if isinstance(m, str) else str(m))
        except re.error:
            # ignore faulty regex for this run
            continue

    # Heuristics are also gated by allowed_types. They are included ONLY if
    # their name is explicitly allowed. This prevents unexpected results when
    # the user selects a narrow subset (e.g., only IPv4).
    if "MD5 (heuristic)" in allowed_types or "SHA1 (heuristic)" in allowed_types or "SHA256 (heuristic)" in allowed_types or "HexHash (heuristic)" in allowed_types:
        for m in HASH_LIKELY.findall(s):
            length = len(m)
            if length == 32 and "MD5 (heuristic)" in allowed_types:
                findings.setdefault("MD5 (heuristic)", set()).add(m)
            elif length == 40 and "SHA1 (heuristic)" in allowed_types:
                findings.setdefault("SHA1 (heuristic)", set()).add(m)
            elif length == 64 and "SHA256 (heuristic)" in allowed_types:
                findings.setdefault("SHA256 (heuristic)", set()).add(m)
            elif "HexHash (heuristic)" in allowed_types:
                findings.setdefault("HexHash (heuristic)", set()).add(m)

    if "Base64" in allowed_types:
        for m in IOC_PATTERNS["Base64_block"].findall(s):
            if isinstance(m, tuple):
                m = m[0]
            try:
                b = m.encode('ascii')
                padding = len(b) % 4
                if padding:
                    b += b'=' * (4 - padding)
                base64.b64decode(b, validate=True)
                findings.setdefault("Base64", set()).add(m)
            except Exception:
                pass

    if "HighEntropy" in allowed_types:
        tokens = re.split(r'[\s/:=\[\]",;]+', s)
        for t in tokens:
            if len(t) >= MIN_ENTROPY_LENGTH:
                ent = shannon_entropy(t)
                if ent >= ENTROPY_THRESHOLD:
                    findings.setdefault("HighEntropy", set()).add(f"{t} (entropy={ent:.2f})")

    return findings

def extract_iocs_from_bv(bv, patterns: Optional[Dict[str, re.Pattern]] = None) -> Tuple[List[Tuple[str, str, str]], int]:
    """Main extraction logic: collect strings, run detectors, aggregate results."""
    results: List[Tuple[str, str, str]] = []
    strings = collect_strings_from_bv(bv)
    scanned_count = 0
    allowed_types: Set[str] = set(patterns.keys()) if patterns is not None else set(IOC_PATTERNS.keys())
    for addr, s in strings:
        scanned_count += 1
        try:
            matches = match_iocs_in_string(s, patterns, allowed_types)
            for k, vals in matches.items():
                for v in vals:
                    addr_str = hex(addr) if isinstance(addr, int) else 'N/A'
                    results.append((k, v, addr_str))
        except Exception:
            log_info(f"Error scanning string at {addr}: {repr(s)[:200]}")
    return results, scanned_count
