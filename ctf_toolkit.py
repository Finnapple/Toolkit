#!/usr/bin/env python3
"""
CTF Crypto Toolkit
==================
Interactive terminal menu with automatic decoding and brute-force tools.
Pure Python 3 standard library - nothing to install.

Usage:
    python3 ctf_toolkit.py                 # interactive menu
    python3 ctf_toolkit.py auto "TEXT"     # auto-detect from the command line
    python3 ctf_toolkit.py auto @file.txt  # auto-detect from a file
"""
import base64
import binascii
import codecs
import os
import re
import string
import sys
import urllib.parse
from collections import Counter

# ---------------------------------------------------------------- colors
if os.name == "nt":
    os.system("")  # enables ANSI colors in Windows terminals
for _stream in (sys.stdout, sys.stderr):
    try:  # never crash on characters the terminal cannot display
        _stream.reconfigure(errors="replace")
    except (AttributeError, ValueError):
        pass
_COLORS = {"g": "\033[92m", "y": "\033[93m", "r": "\033[91m",
           "c": "\033[96m", "b": "\033[1m", "x": "\033[0m"}
if not sys.stdout.isatty():
    _COLORS = {k: "" for k in _COLORS}


def col(color, text):
    return f"{_COLORS[color]}{text}{_COLORS['x']}"


def info(msg):
    print(col("c", f"[*] {msg}"))


def ok(msg):
    print(col("g", f"[+] {msg}"))


def err(msg):
    print(col("r", f"[x] {msg}"))


# ---------------------------------------------------------------- errors
class DecodeError(Exception):
    """Raised when an input cannot be decoded; message is user-friendly."""


# ---------------------------------------------------------------- data
MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9", ".-.-.-": ".", "--..--": ",", "..--..": "?",
    ".----.": "'", "-.-.--": "!", "-..-.": "/", "-.--.": "(", "-.--.-": ")",
    ".-...": "&", "---...": ":", "-.-.-.": ";", "-...-": "=", ".-.-.": "+",
    "-....-": "-", "..--.-": "_", ".-..-.": '"', "...-..-": "$", ".--.-.": "@",
}

COMMON_WORDS = {
    "the", "and", "this", "that", "you", "for", "are", "with", "flag", "ctf",
    "hello", "world", "secret", "key", "password", "message", "welcome",
    "congratulations", "here", "your", "have", "not", "was", "can", "will",
    "from", "text", "decode", "encoded", "admin", "user", "login", "crypto",
    "easy", "test", "is", "to", "of", "in", "it", "my", "be", "on", "we",
}
FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,12}\{[A-Za-z0-9_][A-Za-z0-9_\-!@#$%^&*.,:+=]{2,99}\}")
MAX_FILE_BYTES = 5 * 1024 * 1024


# ---------------------------------------------------------------- helpers
def to_text(data):
    """bytes -> str, or DecodeError if the result looks like garbage."""
    if not data:
        raise DecodeError("Decoded result is empty.")
    try:
        s = data.decode("utf-8")
    except UnicodeDecodeError:
        s = data.decode("latin-1")
    printable = sum(1 for ch in s if ch in string.printable)
    if printable / len(s) < 0.85:
        raise DecodeError("Decoded data is not readable text (looks like binary/garbage).")
    return s


def score(s):
    """How much a string looks like English / a flag. Higher is better."""
    if not s:
        return 0.0
    n = len(s)
    printable = sum(1 for c in s if c in string.printable and c not in "\x0b\x0c") / n
    alpha = sum(1 for c in s if c.isalpha() or c == " ") / n
    tokens = re.findall(r"[a-z]+", s.lower())
    words = sum(1 for t in tokens if t in COMMON_WORDS)
    total = 0.5 * printable + 0.5 * alpha + 0.25 * min(words, 4)
    if FLAG_RE.search(s):
        total += 1.5
    return total


def has_common_words(s):
    toks = re.findall(r"[a-z]+", s.lower())
    return any(t in COMMON_WORDS and len(t) > 2 for t in toks)


def common_ratio(s):
    toks = [t for t in re.findall(r"[a-z]+", s.lower()) if len(t) > 2]
    if not toks:
        return 0.0
    return sum(t in COMMON_WORDS for t in toks) / len(toks)


def has_words(s):
    return has_common_words(s) or bool(FLAG_RE.search(s))


def get_bytes(text):
    """Hex input -> bytes; anything else -> raw bytes."""
    clean = re.sub(r"(0x|\\x|\s|,|:)", "", text, flags=re.I)
    if clean and len(clean) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", clean):
        return bytes.fromhex(clean)
    return text.encode("latin-1", errors="replace")


def require(text):
    if text is None or not text.strip():
        raise DecodeError("Input is empty.")
    return text


# ---------------------------------------------------------------- decoders
def d_rot13(t):
    return codecs.decode(require(t), "rot_13")


def caesar_shift(t, k):
    up, lo = string.ascii_uppercase, string.ascii_lowercase
    table = str.maketrans(up + lo, up[k:] + up[:k] + lo[k:] + lo[:k])
    return t.translate(table)


def d_atbash(t):
    up, lo = string.ascii_uppercase, string.ascii_lowercase
    return require(t).translate(str.maketrans(up + lo, up[::-1] + lo[::-1]))


def d_reverse(t):
    return require(t)[::-1]


def d_base64(t):
    s = re.sub(r"\s+", "", require(t))
    if not re.fullmatch(r"[A-Za-z0-9+/_\-]+={0,2}", s):
        raise DecodeError("Not valid Base64 (allowed: A-Z a-z 0-9 + / = and URL-safe - _).")
    s = s.replace("-", "+").replace("_", "/").rstrip("=")
    if len(s) % 4 == 1:
        raise DecodeError("Invalid Base64 length.")
    s += "=" * (-len(s) % 4)
    try:
        return to_text(base64.b64decode(s))
    except (binascii.Error, ValueError) as e:
        raise DecodeError(f"Base64 decoding failed: {e}")


def d_base32(t):
    s = re.sub(r"\s+", "", require(t)).upper()
    if not re.fullmatch(r"[A-Z2-7]+=*", s):
        raise DecodeError("Not valid Base32 (allowed: A-Z 2-7 and =).")
    s = s.rstrip("=")
    s += "=" * (-len(s) % 8)
    try:
        return to_text(base64.b32decode(s))
    except (binascii.Error, ValueError) as e:
        raise DecodeError(f"Base32 decoding failed: {e}")


def d_hex(t):
    s = re.sub(r"(0x|\\x|\s|,|:)", "", require(t), flags=re.I)
    if not re.fullmatch(r"[0-9a-fA-F]+", s):
        raise DecodeError("Not valid hex (allowed: 0-9 a-f, spaces, 0x, \\x).")
    if len(s) % 2:
        raise DecodeError("Hex string has an odd number of digits.")
    return to_text(bytes.fromhex(s))


def d_binary(t):
    s = re.sub(r"[\s,]", "", require(t))
    if not re.fullmatch(r"[01]+", s):
        raise DecodeError("Not valid binary (only 0 and 1 allowed).")
    if len(s) % 8:
        raise DecodeError(f"Binary length ({len(s)}) is not a multiple of 8.")
    return to_text(bytes(int(s[i:i + 8], 2) for i in range(0, len(s), 8)))


def d_url(t):
    require(t)
    if "%" not in t and "+" not in t:
        raise DecodeError("No URL-encoded characters (% or +) found.")
    out = urllib.parse.unquote_plus(t)
    if out == t:
        raise DecodeError("Nothing changed after URL decoding.")
    return out


def d_morse(t):
    s = require(t).strip().replace("_", "-")
    if not re.fullmatch(r"[.\-/|\s]+", s) or not re.search(r"[.\-]", s):
        raise DecodeError("Not valid Morse (use . and -, spaces between letters, / between words).")
    words = re.split(r"\s*[/|]\s*|\s{3,}", s)
    out = []
    for w in words:
        letters = []
        for code in w.split():
            if code not in MORSE:
                raise DecodeError(f"Unknown Morse sequence: {code}")
            letters.append(MORSE[code])
        out.append("".join(letters))
    return " ".join(out)


def d_decimal(t):
    parts = [p for p in re.split(r"[\s,;]+", require(t).strip()) if p]
    if not all(p.isdigit() for p in parts):
        raise DecodeError("Not valid ASCII decimal (numbers separated by spaces/commas).")
    nums = [int(p) for p in parts]
    bad = [n for n in nums if n > 255]
    if bad:
        raise DecodeError(f"Value out of byte range (0-255): {bad[0]}")
    return to_text(bytes(nums))


# ---------------------------------------------------------------- brute force
def caesar_all(t):
    """Shifts 1..26 (26 = original text)."""
    return [(k, caesar_shift(t, k)) for k in range(1, 27)]


def xor_brute(data):
    """Try all 256 single-byte keys; returns [(score, key, text)] best first."""
    if not data:
        raise DecodeError("Input is empty.")
    res = []
    for k in range(256):
        s = bytes(b ^ k for b in data).decode("latin-1")
        res.append((score(s), k, s))
    res.sort(key=lambda r: -r[0])
    return res


# ---------------------------------------------------------------- vigenere
ENG_FREQ = [8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966,
            0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987,
            6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074]
COMMON_KEYS = ["key", "secret", "flag", "ctf", "password", "crypto", "admin",
               "vigenere", "lemon", "cipher", "test", "hello", "pass", "root",
               "hack", "hacker", "code", "enigma", "love", "abc", "a", "b"]
_LETTERS = set(string.ascii_letters)


def clean_key(key):
    k = re.sub(r"[^A-Za-z]", "", key or "").upper()
    if not k:
        raise DecodeError("Key must contain at least one letter (A-Z).")
    return k


def vig_decrypt(text, key):
    """Decrypt Vigenere. Non-letters are kept and do not advance the key."""
    k = clean_key(key)
    out, i = [], 0
    for ch in text:
        if ch in _LETTERS:
            base = 65 if ch.isupper() else 97
            out.append(chr((ord(ch) - base - (ord(k[i % len(k)]) - 65)) % 26 + base))
            i += 1
        else:
            out.append(ch)
    return "".join(out)


def _ioc(columns):
    vals = []
    for c in columns:
        n = len(c)
        if n < 2:
            continue
        cnt = Counter(c)
        vals.append(sum(v * (v - 1) for v in cnt.values()) / (n * (n - 1)))
    return sum(vals) / len(vals) if vals else 0.0


def _best_shift(column):
    n, cnt = len(column), Counter(column)
    best = None
    for k in range(26):
        chi = 0.0
        for j in range(26):
            exp = ENG_FREQ[j] / 100 * n
            chi += (cnt.get((j + k) % 26, 0) - exp) ** 2 / exp
        if best is None or chi < best[0]:
            best = (chi, k)
    return best[1]


def _shortest_period(key):
    for p in range(1, len(key) + 1):
        if len(key) % p == 0 and key == key[:p] * (len(key) // p):
            return key[:p]
    return key


def _plain_chi(nums):
    """Letter-frequency chi-squared per letter vs English (lower = more English)."""
    n = len(nums)
    if not n:
        return 1e9
    cnt = Counter(nums)
    return sum((cnt.get(j, 0) - ENG_FREQ[j] / 100 * n) ** 2 / (ENG_FREQ[j] / 100 * n)
               for j in range(26)) / n


def _vig_key_for_length(nums, L):
    key = [_best_shift(nums[i::L]) for i in range(L)]
    plain = [(nums[i] - key[i % L]) % 26 for i in range(len(nums))]
    return "".join(chr(65 + k) for k in key), _plain_chi(plain)


def vigenere_crack(text, max_len=16, top=3):
    """Statistical attack (Index of Coincidence + frequency analysis).
    Returns [(key, plaintext)] best first. Works best with 50+ letters."""
    nums = [ord(c.upper()) - 65 for c in text if c in _LETTERS]
    if len(nums) < 20:
        raise DecodeError("Need at least ~20 letters to auto-crack Vigenere "
                          "(50+ works much better). Use a known key or crib instead.")
    max_len = max(1, min(max_len, len(nums) // 8))  # keep >= 8 letters per column
    by_len = {}
    for L in range(1, max_len + 1):
        key, chi = _vig_key_for_length(nums, L)
        by_len[L] = (key, chi, _ioc([nums[i::L] for i in range(L)]))
    best_chi = min(v[1] for v in by_len.values())
    best_ioc = max(v[2] for v in by_len.values())
    order = []
    # 1) smallest length whose plaintext is almost as English-like as the best one
    order.append(next(L for L in sorted(by_len) if by_len[L][1] <= best_chi * 1.25 + 0.01))
    # 2) smallest length whose IoC is close to the best IoC
    order.append(next(L for L in sorted(by_len) if by_len[L][2] >= 0.9 * best_ioc))
    # 3) remaining lengths by plaintext quality
    order += sorted(by_len, key=lambda L: by_len[L][1])
    results = []
    for L in order:
        key = _shortest_period(by_len[L][0])
        if all(key != k for k, _ in results):
            results.append((key, vig_decrypt(text, key)))
        if len(results) >= top:
            break
    return results


def vigenere_candidates(text):
    """Used by auto-detect: common-key dictionary + statistical crack."""
    n = sum(c in _LETTERS for c in text)
    out = []
    if n >= 6:
        out += [(k.upper(), vig_decrypt(text, k)) for k in COMMON_KEYS]
    if n >= 30:
        try:
            key, plain = vigenere_crack(text, top=1)[0]
            out.append((key, plain))
        except DecodeError:
            pass
    return out


def vig_rank(plain):
    """Sort key for Vigenere guesses: readable score first, letter statistics as tie-break."""
    nums = [ord(c.upper()) - 65 for c in plain if c in _LETTERS]
    return (round(score(plain), 2), -_plain_chi(nums))


def run_vig_crack(text):
    hits = [(k, o) for k, o in ((k.upper(), vig_decrypt(text, k)) for k in COMMON_KEYS)
            if has_words(o) and score(o) >= 1.2]
    if hits:
        ok("Common-key dictionary matches:")
        for k, o in hits[:3]:
            print(f"  key {k}: {o}")
        print()
    results = vigenere_crack(text)
    ok("Statistical crack (Index of Coincidence + frequency analysis):")
    for key, plain in results:
        flag = col("y", " [FLAG]") if FLAG_RE.search(plain) else ""
        shown = plain if len(plain) <= 200 else plain[:200] + "..."
        print(f"  key {col('b', key)} (len {len(key)}, score {score(plain):.2f}){flag}")
        print(f"    {shown}")
    info("Tip: short texts (<50 letters) give unreliable keys. If you know the "
         "start of the plaintext, use  crib:flag  as the key input.")


def run_crib(text, crib):
    crib = clean_key(crib)
    cipher = [c.upper() for c in text if c in _LETTERS]
    if len(cipher) < len(crib):
        raise DecodeError("Crib is longer than the ciphertext.")
    frag = "".join(chr((ord(cipher[i]) - ord(crib[i])) % 26 + 65) for i in range(len(crib)))
    ok(f"Key fragment (assuming '{crib}' is at the start of the plaintext): {col('b', frag)}")
    shown = set()
    for p in range(1, len(frag) + 1):
        if all(frag[i] == frag[i % p] for i in range(len(frag))):
            key = frag[:p]
            if p < len(frag) and key in shown:
                continue
            shown.add(key)
            note = "key repeats inside the fragment" if p < len(frag) else "full fragment (key may be longer)"
            plain = vig_decrypt(text, key)
            print(f"  key {col('b', key)} ({note}):")
            print(f"    {plain if len(plain) <= 200 else plain[:200] + '...'}")
            if p < len(frag):
                break


def run_vigenere(text):
    require(text)
    if not any(c in _LETTERS for c in text):
        raise DecodeError("Vigenere needs at least one letter (A-Z) in the input.")
    try:
        key = input(col("c", "Key (Enter = auto-crack | crib:flag = derive key from known text): ")).strip()
    except EOFError:
        key = ""
    print()
    if key.lower().startswith("crib:"):
        run_crib(text, key[5:])
    elif key:
        show_result(f"Vigenere (key={clean_key(key)})", vig_decrypt(text, key))
    else:
        run_vig_crack(text)


# ---------------------------------------------------------------- auto detect
STRICT = [
    ("Base64", d_base64), ("Base32", d_base32), ("Hex", d_hex),
    ("Binary", d_binary), ("URL", d_url), ("Morse", d_morse),
    ("ASCII Decimal", d_decimal),
]
LOOSE = [("ROT13", d_rot13), ("Atbash", d_atbash), ("Reverse", d_reverse)]


def auto_detect(text, max_depth=6):
    """Return a list of (score, chain, output) sorted best first."""
    results, seen = [], {text}

    def walk(t, chain, depth):
        if depth > max_depth:
            return
        # Layered encodings
        for name, fn in STRICT:
            try:
                out = fn(t)
            except (DecodeError, ValueError, binascii.Error):
                continue
            if not out or out in seen or len(out.strip()) < 2:
                continue
            if chain and score(out) < 0.6:
                continue  # skip junk produced by chaining decoders
            seen.add(out)
            c = chain + [name]
            results.append((score(out), c, out))
            walk(out, c, depth + 1)
        # Substitution ciphers / brute force: keep only if it looks like plaintext
        cands = []
        for name, fn in LOOSE:
            try:
                cands.append((name, fn(t)))
            except DecodeError:
                pass
        try:
            k, best = max(((k, s) for k, s in caesar_all(t) if k != 26),
                          key=lambda x: score(x[1]))
            cands.append((f"Caesar(+{k})", best))
            _, xk, xo = xor_brute(get_bytes(t))[0]
            cands.append((f"XOR(0x{xk:02x})", xo))
        except DecodeError:
            pass
        vc = vigenere_candidates(t)
        if vc:  # keep only the best Vigenere guess so partial-key junk does not clutter results
            vk, vo = max(vc, key=lambda kv: vig_rank(kv[1]))
            cands.append((f"Vigenere({vk})", vo))
        cur = score(t)
        if cur >= 1.2 and has_common_words(t) and common_ratio(t) >= 0.3:
            return  # already readable plaintext - no need to try ciphers
        for name, out in cands:
            if out in seen:
                continue
            sc = score(out)
            clean = all(c in string.printable and c not in "\r\x0b\x0c" for c in out)
            if clean and sc >= 1.2 and sc > cur + 0.15 and has_words(out):
                seen.add(out)
                c = chain + [name]
                results.append((sc, c, out))
                walk(out, c, depth + 1)

    walk(text, [], 1)
    results.sort(key=lambda r: (-r[0], len(r[1])))
    return results


# ---------------------------------------------------------------- identify
HASH_LENGTHS = {
    32: "MD5 / NTLM / MD4", 40: "SHA-1", 56: "SHA-224 / SHA3-224",
    64: "SHA-256 / SHA3-256", 96: "SHA-384", 128: "SHA-512 / SHA3-512",
}


def identify(text):
    """Guess what kind of string this is. Returns a list of descriptions."""
    t = text.strip()
    found = []
    if not t:
        return found
    one_line = "\n" not in t

    # --- specific formats ---
    m = FLAG_RE.search(t)
    if m:
        prefix = m.group(0).split("{")[0]
        if re.fullmatch(r"(?i)(flag|ctf|htb|thm|picoctf|ctfd|hackthebox|cyber\w*|\w*ctf)", prefix):
            found.append("CTF flag format (prefix{...})")
        else:
            found.append(f"Flag-like pattern, but prefix '{prefix}' is not a known flag prefix "
                         "- content may be encoded (try ROT13 / Caesar / Atbash / Vigenere)")
    if re.match(r"-----BEGIN [A-Z ]+-----", t):
        found.append("PEM block (key / certificate / encoded data)")
    if re.fullmatch(r"https?://\S+", t):
        found.append("URL")
    if re.fullmatch(r"[\w.+-]+@[\w-]+(\.[\w-]+)+", t):
        found.append("Email address")
    if re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", t):
        found.append("IPv4 address")
    if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", t):
        found.append("UUID")
    if re.fullmatch(r"\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}", t):
        found.append("bcrypt hash (cannot be decoded - crack with hashcat/john)")
    elif re.match(r"\$(1|5|6|y|argon2\w*)\$", t):
        found.append("Unix crypt / Argon2 hash (cannot be decoded - crack with hashcat/john)")
    if re.fullmatch(r"[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*", t):
        try:
            head = t.split(".")[0]
            head += "=" * (-len(head) % 4)
            if b'"alg"' in base64.urlsafe_b64decode(head):
                found.append("JWT (JSON Web Token) - decode header/payload as Base64URL")
        except Exception:
            pass

    # --- hex / hashes ---
    hex_clean = re.sub(r"(0x|\\x|\s|,|:)", "", t, flags=re.I)
    if re.fullmatch(r"[0-9a-fA-F]+", hex_clean) and not re.fullmatch(r"\d+", hex_clean):
        n = len(hex_clean)
        if n in HASH_LENGTHS and re.fullmatch(r"[0-9a-fA-F]+", t):
            found.append(f"Hex string, {n} chars - could be a {HASH_LENGTHS[n]} hash "
                         "(hashes cannot be decoded) or hex-encoded data")
        elif n % 2 == 0:
            found.append(f"Hexadecimal data ({n // 2} bytes)")
        else:
            found.append("Hex characters but odd length (possibly broken hex)")

    # --- binary / decimal ---
    bin_clean = re.sub(r"[\s,]", "", t)
    if re.fullmatch(r"[01]+", bin_clean) and len(bin_clean) >= 8:
        if len(bin_clean) % 8 == 0:
            found.append(f"Binary ({len(bin_clean) // 8} bytes)")
        else:
            found.append(f"Binary digits, but length {len(bin_clean)} is not a multiple of 8")
    parts = [p for p in re.split(r"[\s,;]+", t) if p]
    if len(parts) > 1 and all(p.isdigit() for p in parts) and not re.fullmatch(r"[01]+", bin_clean):
        nums = [int(p) for p in parts]
        if all(n <= 255 for n in nums):
            found.append(f"ASCII decimal codes ({len(nums)} values)")
        else:
            found.append("List of integers (values > 255: maybe RSA numbers / coordinates / custom cipher)")
    elif len(parts) == 1 and t.isdigit():
        if len(t) in (9, 10):
            found.append("Number - possible Unix timestamp")
        elif len(t) > 30:
            found.append(f"Very large integer ({len(t)} digits) - maybe RSA n / c / big number")
        else:
            found.append("Plain number")

    # --- morse / url / base32 / base64 ---
    if re.fullmatch(r"[.\-_/|\s]+", t) and re.search(r"[.\-]", t):
        found.append("Morse code")
    if re.search(r"%[0-9A-Fa-f]{2}", t):
        found.append("URL-encoded (percent-encoding)")
    compact = re.sub(r"\s+", "", t)
    is_b32 = bool(one_line and len(compact) >= 8 and re.fullmatch(r"[A-Z2-7]+=*", compact)
                  and (compact.endswith("=") or len(compact) % 8 == 0))
    if is_b32:
        found.append("Base32" + (" (has = padding)" if "=" in compact else ""))
    if not is_b32 and len(compact) >= 4 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact) and len(compact) % 4 == 0 \
            and not re.fullmatch(r"[0-9a-fA-F]+", compact) and not re.fullmatch(r"\d+", compact):
        strong = "=" in compact or (len(compact) >= 16 and re.search(r"[A-Z]", compact)
                                    and re.search(r"[a-z]", compact))
        if strong or not has_common_words(compact):
            found.append("Base64" + (" (likely)" if strong else " (possible)"))
    elif not found and len(compact) >= 8 and re.fullmatch(r"[A-Za-z0-9_\-]+", compact) and ("-" in compact or "_" in compact) \
            and not re.fullmatch(r"[A-Za-z0-9_]*[a-z]+(_[a-z0-9]+)+", compact):
        found.append("Base64URL (possible)")

    # --- plain text classification ---
    letters = sum(c.isalpha() for c in t)
    if letters >= 4 and not found:
        if has_common_words(t) and score(t) >= 1.0:
            found.append("Readable English text (already plain)")
        elif has_common_words(t[::-1]):
            found.append("Possibly reversed text")
        elif letters / len(t) > 0.6:
            found.append("Letters only - possible Caesar / ROT13 / Atbash / Vigenere / substitution cipher")
    if not found:
        found.append("Unknown / unrecognized format")
    return found


def print_types(types):
    info("Detected type:")
    for ty in types:
        print(f"    - {ty}")
    print()


def run_identify(text):
    print_types(identify(require(text)))


# ---------------------------------------------------------------- UI
def show_result(label, out):
    ok(f"{label} result:")
    print(out)
    m = FLAG_RE.search(out)
    if m:
        print(col("y", f"\n[FLAG] {m.group(0)}"))


def run_auto(text):
    require(text)
    print_types(identify(text))
    results = auto_detect(text)
    if not results and has_common_words(text) and score(text) >= 1.0:
        ok("Input already looks like readable plaintext - nothing to decode.")
        return
    if not results:
        err("No clear decoding found. Type :m to try the individual tools "
            "(Caesar / XOR brute force) manually.")
        return
    ok(f"{len(results)} candidate(s) found. Top results:\n")
    for sc, chain, out in results[:8]:
        tag = col("y", "[FLAG] ") if FLAG_RE.search(out) else ""
        shown = out if len(out) <= 200 else out[:200] + "..."
        print(f"{tag}{col('b', ' -> '.join(chain))}  (score {sc:.2f})")
        print(f"   {shown}\n")


def run_caesar(text):
    require(text)
    if not re.search(r"[A-Za-z]", text):
        raise DecodeError("Caesar cipher needs at least one letter (A-Z).")
    res = caesar_all(text)
    best = max(res, key=lambda r: score(r[1]))[0]
    for k, s in res:
        mark = col("g", "  <-- best guess") if k == best and k != 26 else ""
        print(f"shift {k:>2}: {s}{mark}")


def run_xor(text):
    results = xor_brute(get_bytes(require(text)))[:10]
    ok("Top 10 XOR keys:")
    for sc, k, s in results:
        shown = "".join(c if c in string.printable and c not in "\r\n\t\x0b\x0c" else "."
                        for c in s)
        flag = col("y", " [FLAG]") if FLAG_RE.search(s) else ""
        print(f"key 0x{k:02x} ({k:>3})  score {sc:.2f}  {shown[:80]}{flag}")


def read_input(prompt="Input (or @filename to read a file): "):
    """Returns the entered text, or None if cancelled / unreadable."""
    try:
        t = input(col("c", prompt))
    except EOFError:
        return None
    t = t.strip()
    if not t:
        err("Input is empty.")
        return None
    if t.startswith("@"):
        return read_file(t[1:].strip())
    return t


def read_file(path):
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_FILE_BYTES + 1)
    except FileNotFoundError:
        err(f"File not found: {path}")
        return None
    except IsADirectoryError:
        err(f"That is a directory, not a file: {path}")
        return None
    except PermissionError:
        err(f"Permission denied: {path}")
        return None
    except OSError as e:
        err(f"Cannot read file: {e}")
        return None
    if len(raw) > MAX_FILE_BYTES:
        err("File is too large (limit 5 MB).")
        return None
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        err("File is empty.")
        return None
    info(f"Loaded {len(raw)} bytes from {path}")
    return text


MENU = [
    ("Automatic Detection", run_auto),
    ("ROT13", lambda t: show_result("ROT13", d_rot13(t))),
    ("Caesar Cipher (all 26 shifts)", run_caesar),
    ("Base64", lambda t: show_result("Base64", d_base64(t))),
    ("Base32", lambda t: show_result("Base32", d_base32(t))),
    ("Hexadecimal", lambda t: show_result("Hex", d_hex(t))),
    ("Binary", lambda t: show_result("Binary", d_binary(t))),
    ("URL Decode", lambda t: show_result("URL", d_url(t))),
    ("Morse Code", lambda t: show_result("Morse", d_morse(t))),
    ("Atbash", lambda t: show_result("Atbash", d_atbash(t))),
    ("Single-byte XOR Brute Force", run_xor),
    ("String Reverse", lambda t: show_result("Reverse", d_reverse(t))),
    ("ASCII Decimal Decode", lambda t: show_result("ASCII Decimal", d_decimal(t))),
    ("Identify String Type", run_identify),
    ("Vigenere Cipher (key / auto-crack / crib)", run_vigenere),
]


def run_tool(func, text):
    """Run a tool with a full error handler so the menu never crashes."""
    try:
        func(text)
    except DecodeError as e:
        err(str(e))
    except (ValueError, binascii.Error, UnicodeError) as e:
        err(f"Could not process this input: {e}")
    except RecursionError:
        err("Input is too deeply nested to decode.")
    except MemoryError:
        err("Input is too large to process.")
    except Exception as e:  # last-resort safety net
        err(f"Unexpected error ({type(e).__name__}): {e}")


def print_menu():
    print(col("b", "\n========== CTF CRYPTO TOOLKIT =========="))
    for i, (name, _) in enumerate(MENU, 1):
        print(f" {i:>2}. {name}")
    print("  0. Back to quick mode")


def main():
    args = sys.argv[1:]
    if args:
        if args[0] != "auto" or len(args) < 2:
            print(__doc__)
            sys.exit(2)
        target = " ".join(args[1:])
        text = read_file(target[1:]) if target.startswith("@") else target
        if text is None:
            sys.exit(1)
        run_tool(run_auto, text)
        return

    quick_mode()


def manual_menu():
    """Full tool menu (pick a specific decoder / brute-force)."""
    while True:
        print_menu()
        try:
            choice = input(col("c", "\nSelect an option > ")).strip().lower()
        except EOFError:
            print()
            break
        except KeyboardInterrupt:
            print()
            info("Press 0 to go back.")
            continue
        if choice in ("0", "q", "b", "back", "exit"):
            break
        if not choice.isdigit() or not 1 <= int(choice) <= len(MENU):
            err(f"Invalid option. Enter a number from 0 to {len(MENU)}.")
            continue
        name, func = MENU[int(choice) - 1]
        try:
            text = read_input()
        except KeyboardInterrupt:
            print()
            info("Cancelled.")
            continue
        if text is None:
            continue
        print()
        try:
            run_tool(func, text)
        except KeyboardInterrupt:
            print()
            info("Cancelled.")


QUICK_HELP = ("Paste or type any text and it is decoded automatically.\n"
              "  @file.txt = read from a file   :m = full tool menu   :q = quit")


def quick_mode():
    """Default mode: type text -> automatic decoding right away."""
    print(col("b", "\n========== CTF CRYPTO TOOLKIT =========="))
    print(QUICK_HELP)
    while True:
        try:
            text = input(col("c", "\nInput > ")).strip()
        except EOFError:
            print()
            break
        except KeyboardInterrupt:
            print()
            info("Type :q to quit.")
            continue
        if not text:
            continue
        low = text.lower()
        if low in (":q", ":quit", ":exit", "exit", "quit"):
            break
        if low in (":m", ":menu"):
            manual_menu()
            print(QUICK_HELP)
            continue
        if low in (":h", ":help", "help", "?"):
            print(QUICK_HELP)
            continue
        if text.startswith("@"):
            text = read_file(text[1:].strip())
            if text is None:
                continue
        print()
        try:
            run_tool(run_auto, text)
        except KeyboardInterrupt:
            print()
            info("Cancelled.")
    info("Goodbye!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
    except BrokenPipeError:
        pass
