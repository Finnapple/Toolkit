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
import math
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


KNOWN_FLAG_PREFIX = re.compile(r"(?i)(flag|ctf|htb|thm|picoctf|ctfd|hackthebox|cyber\w*|\w*ctf)")


def flag_bonus(s):
    """Full bonus only for well-known flag prefixes. An unknown prefix gets a small
    bonus: a still-encrypted flag (e.g. 'qpmu{...}') also matches FLAG_RE and must not
    look as good as a real decryption, and random junk with braces must not win."""
    best = 0.0
    for m in FLAG_RE.finditer(s):
        if KNOWN_FLAG_PREFIX.fullmatch(m.group(0).split("{")[0]):
            return 1.5
        best = 0.5
    return best


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
    return total + flag_bonus(s)


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
COMMON_KEYS = [
    "key", "secret", "flag", "ctf", "password", "crypto", "admin", "vigenere",
    "lemon", "cipher", "test", "hello", "pass", "root", "hack", "hacker", "code",
    "enigma", "love", "abc", "a", "b", "keyword", "hidden", "puzzle", "challenge",
    "python", "linux", "kali", "cyber", "security", "random", "message", "orange",
    "apple", "queen", "king", "shadow", "matrix", "monkey", "dragon", "master",
    "letmein", "welcome", "picoctf", "pico", "crypt", "cryptography", "decrypt",
    "encrypt", "attack", "dawn", "bacon", "spy", "agent", "ninja", "zebra",
    "wonderland", "alice", "sesame", "open", "unlock", "access", "login", "user",
    "account", "private", "public", "hash", "cracker", "winner", "player", "gamer",
    "table", "chess", "river", "tiger", "eagle", "wolf", "fox", "stone", "silver",
    "golden", "dark", "light", "moon", "sun", "star", "fire", "water", "earth",
]
_LETTERS = set(string.ascii_letters)
_LOGF = [math.log(f / 100) for f in ENG_FREQ]
_KEY_PENALTY = 3.0      # fitness lost per key letter - stops long keys from "overfitting"
_SAMPLE = 400           # letters used for the key search (more adds time, not accuracy)

# Common English bigrams/trigrams give a short ciphertext enough extra signal to find the key
_BI_W = [0.0] * 676
for _g in ("TH HE IN ER AN RE ON AT EN ND TI ES OR TE OF ED IS IT AL AR ST TO NT NG SE HA AS OU "
           "IO LE VE CO ME DE HI RI RO IC NE EA RA CE LI CH LL BE MA SI OM UR").split():
    _BI_W[(ord(_g[0]) - 65) * 26 + ord(_g[1]) - 65] = 0.4
_TRI_W = [0.0] * 17576
for _g in ("THE AND ING ENT ION HER FOR THA NTH INT ERE TIO TER EST ERS ATI HAT ATE ALL ETH HES "
           "VER HIS OFT ITH FTH STH OTH RES ONT").split():
    _TRI_W[((ord(_g[0]) - 65) * 26 + ord(_g[1]) - 65) * 26 + ord(_g[2]) - 65] = 1.2

_WORDS = set((
    "the and for are but not you all any can had her was one our out day get has him his how man new now "
    "old see two way who boy did its let put say she too use that with have this will your from they know "
    "want been good much some time very when come here just like long make many over such take than them "
    "well were what said each which their there about would these other words could write first water "
    "after where right think three years place sound great again still every small found those never "
    "under might while house world below asked going large until along shall being often earth began "
    "since study night light above paper parts young story point times heard whole white given means "
    "music miles thing today later using money lived plain leave watch color face wood main enough plant "
    "cover soon girl sleep body stand flag ctf key secret password crypto cipher decode encoded message "
    "welcome congratulations hidden attack dawn meet bridge river tonight quick brown fox jumps lazy dog "
    "hello admin user login test easy challenge solved solve answer found find keep safe share anyone "
    "please competition contest team player round level next last only also into over then more most "
    "both between through during before without within against another because people should really "
    "something nothing everything inside outside open close start end begin finish hack hacker code "
    "program computer network server data file text string number letter simple secure security "
    "private public access token cookie session request response").split())
_WORDS = sorted((w.upper() for w in _WORDS if len(w) >= 3), key=len, reverse=True)

FLAG_PREFIXES = ["flag", "ctf", "htb", "thm", "pico", "picoctf", "ductf", "utctf", "uiuctf",
                 "hackthebox", "cyber", "angstromctf", "csictf", "bsidessf", "wgmy"]


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


def _letter_nums(text):
    return [ord(c.upper()) - 65 for c in text if c in _LETTERS]


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


def _fit(p):
    """English log-likelihood-ish fitness of a list of 0..25 (higher = more English)."""
    s = 0.0
    for c in p:
        s += _LOGF[c]
    for i in range(len(p) - 1):
        s += _BI_W[p[i] * 26 + p[i + 1]]
    for i in range(len(p) - 2):
        s += _TRI_W[(p[i] * 26 + p[i + 1]) * 26 + p[i + 2]]
    return s


def _vig_search(nums, L, fixed=None):
    """Best key of length L: per-column frequency guess, then coordinate ascent on the whole
    plaintext fitness. `fixed` = {position: shift} for key letters that are already known."""
    n = len(nums)
    fixed = fixed or {}
    key = [fixed[i] if i in fixed else _best_shift(nums[i::L]) for i in range(L)]
    free = [i for i in range(L) if i not in fixed]

    def fitness():
        return _fit([(nums[i] - key[i % L]) % 26 for i in range(n)])

    best = fitness()
    for _ in range(6):
        changed = False
        for i in free:
            cur, bk = key[i], key[i]
            for k in range(26):
                if k == cur:
                    continue
                key[i] = k
                f = fitness()
                if f > best + 1e-9:
                    best, bk = f, k
            key[i] = bk
            if bk != cur:
                changed = True
        if not changed:
            break
    return key, best


def _vig_lengths(nums, max_len):
    """Shortlist of plausible key lengths (IoC + per-column frequency analysis)."""
    info = {}
    for L in range(1, max_len + 1):
        key = [_best_shift(nums[i::L]) for i in range(L)]
        plain = [(nums[i] - key[i % L]) % 26 for i in range(len(nums))]
        info[L] = (_plain_chi(plain), _ioc([nums[i::L] for i in range(L)]))
    best_chi = min(v[0] for v in info.values())
    best_ioc = max(v[1] for v in info.values())
    picks = [next(L for L in sorted(info) if info[L][0] <= best_chi * 1.25 + 0.01),
             next(L for L in sorted(info) if info[L][1] >= 0.9 * best_ioc)]
    picks += sorted(info, key=lambda L: info[L][0])[:4]
    seen, out = set(), []
    for L in picks:
        if L not in seen:
            seen.add(L)
            out.append(L)
    return out


def vigenere_crack(text, max_len=16, top=3):
    """Statistical attack: Index of Coincidence + frequency analysis, refined with
    bigram/trigram hill-climbing. Returns [(key, plaintext)] best first."""
    nums = _letter_nums(text)
    if len(nums) < 20:
        raise DecodeError("Need at least ~20 letters to auto-crack Vigenere "
                          "(50+ works much better). Use a known key or crib instead.")
    sample = nums[:_SAMPLE]
    max_len = max(1, min(max_len, len(sample) // 6))
    scored = []
    for L in _vig_lengths(sample, max_len):
        key, f = _vig_search(sample, L)
        scored.append((f - _KEY_PENALTY * L, "".join(chr(65 + k) for k in key)))
    scored.sort(reverse=True)
    results = []
    for _, key in scored:
        key = _shortest_period(key)
        if all(key != k for k, _ in results):
            results.append((key, vig_decrypt(text, key)))
        if len(results) >= top:
            break
    return results


def _crib_constraints(text):
    """'xxxx{' in the ciphertext is probably a flag prefix. Yield (prefix, letters_before, token)."""
    for m in re.finditer(r"([A-Za-z]{2,12})\{", text):
        tok = m.group(1).upper()
        off = sum(c in _LETTERS for c in text[:m.start(1)])
        for p in FLAG_PREFIXES:
            if len(p) == len(tok):
                yield p.upper(), off, tok


def vig_crib_candidates(text, max_len=12):
    """Use the flag format (flag{ / ctf{ / picoCTF{ ...) as known plaintext to recover the key.
    Returns [(key, plaintext, strong)]. strong=True only for dictionary keys that agree with
    the crib; keys solved statistically are forced to produce the prefix, so the prefix alone
    proves nothing about them."""
    nums = _letter_nums(text)
    res, seen = [], set()
    for prefix, off, tok in _crib_constraints(text):
        shifts = [(ord(tok[i]) - ord(prefix[i])) % 26 for i in range(len(prefix))]
        for w in COMMON_KEYS:  # 1) dictionary keys that agree with the crib
            kw = [ord(c) - 65 for c in w.upper()]
            if all(kw[(off + i) % len(kw)] == shifts[i] for i in range(len(prefix))):
                if w.upper() not in seen:
                    seen.add(w.upper())
                    res.append((w.upper(), vig_decrypt(text, w), True))
        stat = []  # 2) unknown key: lock the known letters, solve the rest statistically
        for L in range(1, min(max_len, max(1, len(nums) // 3)) + 1):  # >=3 letters per key letter
            fixed, good = {}, True
            for i, s in enumerate(shifts):
                if fixed.setdefault((off + i) % L, s) != s:
                    good = False
                    break
            if not good or len(fixed) >= len(nums):
                continue
            key, f = _vig_search(nums[:_SAMPLE], L, fixed)
            stat.append((f - _KEY_PENALTY * (L - len(fixed)), "".join(chr(65 + k) for k in key)))
        stat.sort(reverse=True)
        for _, key in stat[:2]:
            key = _shortest_period(key)
            if key not in seen:
                seen.add(key)
                res.append((key, vig_decrypt(text, key), False))
    return res


def word_coverage(s):
    """Fraction of letters that belong to common English words (substring search)."""
    letters = "".join(c for c in s[:6000].upper() if c in string.ascii_uppercase)
    n = len(letters)
    if not n:
        return 0.0
    mark = bytearray(n)
    for w in _WORDS:
        i = letters.find(w)
        while i != -1:
            mark[i:i + len(w)] = b"\x01" * len(w)
            i = letters.find(w, i + 1)
    return sum(mark) / n


def eng_quality(s):
    """Higher = more like English. Independent of the flag regex."""
    nums = _letter_nums(s[:6000])
    if len(nums) < 4:
        return -9.0
    return _fit(nums) / len(nums) + 2.0 * word_coverage(s)


def looks_english(s):
    nums = _letter_nums(s[:6000])
    if len(nums) < 8:
        return False
    fit = _fit(nums) / len(nums)
    cov = word_coverage(s)
    if len(nums) < 40:  # few letters: chance matches are common, so demand clearly real words
        return cov >= 0.6 and fit > -3.0
    # calibrated: real English fit > -2.85 / coverage > 0.3; wrong-key output fit < -3.0 / coverage < 0.1
    return (fit > -3.0 and cov >= 0.25) or (fit > -2.7 and cov >= 0.15)


def vigenere_candidates(text):
    """Used by auto-detect: flag-format crib + common-key dictionary + statistical crack.
    Returns [(key, plaintext, strong)]."""
    n = sum(c in _LETTERS for c in text)
    out = []
    if n >= 4:
        out += vig_crib_candidates(text)
    if n >= 6:
        head = text[:2000]  # rank keys on a sample, decrypt the whole text only for the best few
        ranked = []
        for k in COMMON_KEYS:
            ph = vig_decrypt(head, k)
            strong = flag_bonus(ph) >= 1.5 and flag_bonus(head) < 1.5
            ranked.append((vig_rank(ph, strong), k, strong))
        ranked.sort(reverse=True)
        for _, k, strong in ranked[:3]:
            out.append((k.upper(), vig_decrypt(text, k), strong))
    if n >= 30:
        try:
            out += [(k, p, False) for k, p in vigenere_crack(text, top=2)]
        except DecodeError:
            pass
    return out


def vig_rank(plain, strong=False):
    """Sort key for Vigenere guesses (higher is better)."""
    return eng_quality(plain) + (1.0 if strong else 0.0)


def vig_crib_hint(text):
    """For 'xxxx{...}' that is not a known prefix: what key start would make it a known one?"""
    for prefix, off, tok in _crib_constraints(text):
        if off != 0:
            continue
        frag = "".join(chr((ord(tok[i]) - ord(prefix[i])) % 26 + 65) for i in range(len(prefix)))
        return (f"If '{tok.lower()}' is a Vigenere-encrypted '{prefix.lower()}', the key starts with "
                f"'{frag}' (menu option 15, key input:  crib:{prefix.lower()})")
    return None


def vig_hint(text):
    """If the letter statistics look polyalphabetic, return a hint string for identify()."""
    nums = _letter_nums(text)
    n = len(nums)
    compact = re.sub(r"\s", "", text)
    if n < 25 or n / max(1, len(compact)) < 0.7:
        return None
    if looks_english(text):
        return None  # already readable (e.g. a pangram has flat letter statistics but is plain)
    ic = _ioc([nums])
    if ic >= 0.056:
        return None  # English-like letter statistics: plain text or a monoalphabetic cipher
    guess = ""
    cols = {L: _ioc([nums[i::L] for i in range(L)]) for L in range(2, min(16, n // 8) + 1)}
    if cols:
        top = max(cols.values())
        if top >= 0.052:
            L = next(L for L in sorted(cols) if cols[L] >= 0.92 * top)
            guess = f"; estimated key length ~{L}"
    return (f"Letter statistics are flattened (IoC {ic:.3f}; English ~0.066, random ~0.038) - "
            f"looks polyalphabetic, likely Vigenere{guess}")


def run_vig_crack(text):
    shown_keys = set()
    cribs = vig_crib_candidates(text)
    if cribs:
        ok("Flag-format crib (assuming the prefix before '{' is a known flag prefix):")
        for k, o, _strong in cribs[:4]:
            shown_keys.add(k)
            shown = o if len(o) <= 200 else o[:200] + "..."
            print(f"  key {col('b', k)}: {shown}")
        print()
    hits = [(k, o) for k, o in ((k.upper(), vig_decrypt(text, k)) for k in COMMON_KEYS)
            if k not in shown_keys and looks_english(o)]
    if hits:
        ok("Common-key dictionary matches:")
        for k, o in hits[:3]:
            print(f"  key {k}: {o}")
        print()
    results = vigenere_crack(text)
    ok("Statistical crack (Index of Coincidence + frequency + n-gram refinement):")
    for key, plain in results:
        flag = col("y", " [FLAG]") if flag_bonus(plain) >= 1.5 else ""
        shown = plain if len(plain) <= 200 else plain[:200] + "..."
        tag = "" if looks_english(plain) else col("r", " (does not read as English - probably wrong)")
        print(f"  key {col('b', key)} (len {len(key)}, score {score(plain):.2f}){flag}{tag}")
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


def _xor_plausible(t):
    """Single-byte XOR only makes sense for hex-encoded bytes or raw non-text bytes."""
    s = re.sub(r"(0x|\\x|\s|,|:)", "", t, flags=re.I)
    if s and len(s) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", s):
        return True
    return any(c not in string.printable for c in t)


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
            if _xor_plausible(t):  # XOR-ing ordinary letters only produces noise
                _, xk, xo = xor_brute(get_bytes(t))[0]
                cands.append((f"XOR(0x{xk:02x})", xo))
        except DecodeError:
            pass
        vig = None
        vc = vigenere_candidates(t)
        if vc:  # keep only the best Vigenere guess so partial-key junk does not clutter results
            vk, vo, vs = max(vc, key=lambda kv: vig_rank(kv[1], kv[2]))
            vig = (f"Vigenere({vk})", vo, vs)
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
        if vig and vig[1] not in seen:
            name, out, strong = vig  # strong = dictionary key that yields a known flag prefix
            if (looks_english(out) or strong) and vig_rank(out, strong) > vig_rank(t) + 0.3:
                seen.add(out)
                c = chain + [name]
                results.append((score(out), c, out))
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
    no_blank = not re.search(r"[ \t]", t)  # Base32/64 never contain spaces (line wraps are fine)
    is_b32 = bool(no_blank and one_line and len(compact) >= 8 and re.fullmatch(r"[A-Z2-7]+=*", compact)
                  and (compact.endswith("=") or len(compact) % 8 == 0))
    if is_b32:
        found.append("Base32" + (" (has = padding)" if "=" in compact else ""))
    if no_blank and not is_b32 and len(compact) >= 4 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact) and len(compact) % 4 == 0 \
            and not re.fullmatch(r"[0-9a-fA-F]+", compact) and not re.fullmatch(r"\d+", compact):
        strong = "=" in compact or (len(compact) >= 16 and re.search(r"[A-Z]", compact)
                                    and re.search(r"[a-z]", compact))
        if strong:  # weak "(possible)" guesses were mostly false alarms, so they are not reported
            found.append("Base64 (likely)")

    # --- Vigenere hints ---
    if found and found[0].startswith("Flag-like pattern, but prefix"):
        crib = vig_crib_hint(t)
        if crib:
            found.append(crib)
    if not any(w in f for f in found for w in ("Base", "Hex", "hash", "Binary", "decimal", "Morse", "PEM", "JWT", "bcrypt")):
        hint = vig_hint(t)
        if hint:
            found.append(hint)

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


# ------------------------------------------------ hex / XOR / reverse decoder
def parse_xor_key(key_input):
    """Hex key text (e.g. '0x41', '41 42', '4142') -> bytes."""
    if key_input is None or not key_input.strip():
        raise DecodeError("Empty XOR key. Enter a hex key such as 0x41 or 4142.")
    cleaned = re.sub(r"(0x|\\x|[\s,:])", "", key_input, flags=re.I)
    if not cleaned:
        raise DecodeError("Empty XOR key after cleaning.")
    if not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
        raise DecodeError("XOR key contains non-hex characters (allowed: 0-9 a-f, 0x, spaces, commas).")
    if len(cleaned) % 2:
        raise DecodeError(f"XOR key has an odd number of hex digits ({len(cleaned)}).")
    return bytes.fromhex(cleaned)


def parse_hex_data(hex_input):
    """Pasted encrypted HEX ('0x41, 0x42' or '4142') -> bytes."""
    require(hex_input)
    values = re.findall(r"0x([0-9a-fA-F]{1,2})", hex_input, flags=re.I)
    if values:
        return bytes(int(x, 16) for x in values)
    cleaned = re.sub(r"[^0-9a-fA-F]", "", hex_input)
    if not cleaned:
        raise DecodeError("No valid HEX characters found in the input.")
    if len(cleaned) % 2:
        raise DecodeError(f"Invalid HEX length ({len(cleaned)} digits, must be even).")
    return bytes.fromhex(cleaned)


def xor_repeating(data, key):
    """Repeating-key XOR."""
    if not key:
        raise DecodeError("Empty XOR key.")
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def run_hex_xor_reverse(_text=None):
    """Asks for the hex key first, then the encrypted hex values."""
    try:
        key_input = input(col("c", "[?] Enter XOR key (hex): "))
    except EOFError:
        raise DecodeError("No XOR key entered.")
    key = parse_xor_key(key_input)

    hex_input = read_input("[?] Paste encrypted HEX values (or @filename): ")
    if hex_input is None:  # empty / unreadable file / cancelled (already reported)
        return
    data = parse_hex_data(hex_input)

    xor_result = xor_repeating(data, key)
    reversed_result = xor_result[::-1]

    def view(b):
        return b.decode("utf-8", errors="replace")

    info(f"{len(data)} byte(s) of data, {len(key)}-byte key")
    ok("[1] XOR result:")
    print(view(xor_result))
    ok("[2] Reversed result:")
    print(view(reversed_result))
    ok("[3] Hex output:")
    print(reversed_result.hex())
    for label, b in (("XOR", xor_result), ("Reversed", reversed_result)):
        m = FLAG_RE.search(view(b))
        if m:
            print(col("y", f"\n[FLAG] ({label}) {m.group(0)}"))


run_hex_xor_reverse.interactive = True


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
    ("Hex -> XOR (key) -> Reverse Decoder", run_hex_xor_reverse),
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
        if getattr(func, "interactive", False):
            text = None  # this tool asks for its own inputs
        else:
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
        # keep the result on screen until the user decides where to go next
        try:
            nxt = input(col("c", "\n[Enter] = back to menu   [0] = back to home > ")).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if nxt in ("0", "q", "b", "back", "home", "exit"):
            break


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
