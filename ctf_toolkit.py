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
        cur = score(t)
        if cur >= 1.2 and has_common_words(t):
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


# ---------------------------------------------------------------- UI
def show_result(label, out):
    ok(f"{label} result:")
    print(out)
    m = FLAG_RE.search(out)
    if m:
        print(col("y", f"\n[FLAG] {m.group(0)}"))


def run_auto(text):
    require(text)
    results = auto_detect(text)
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
