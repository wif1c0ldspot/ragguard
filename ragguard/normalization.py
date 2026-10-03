"""Text normalization and matching surfaces shared by scanning rules."""

from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass

# --- Canonicalisation -------------------------------------------------------

_ZERO_WIDTH_RE = re.compile(
    r"[\u00ad\u034f\u061c\u180e\u200b-\u200f\u202a-\u202e"
    r"\u2060-\u206f\ufe00-\ufe0f\ufeff\U000e0100-\U000e01ef]"
)
_WHITESPACE_RE = re.compile(r"\s+")


def _pre_canonical(text: str) -> str:
    """Canonical text before whitespace collapsing (keeps word separation intact)."""
    decoded = html.unescape(text)
    normalised = unicodedata.normalize("NFKC", decoded)
    return _ZERO_WIDTH_RE.sub("", normalised).lower()


def canonicalize(text: str) -> str:
    """Normalise text so obfuscated payloads match plain-text rules.

    Decodes HTML entities, applies NFKC normalisation, strips zero-width and
    bidi control characters, collapses all whitespace to single spaces and
    lowercases the result.
    """
    return _WHITESPACE_RE.sub(" ", _pre_canonical(text))


# --- Deobfuscation ------------------------------------------------------------

# Curated confusables skeleton in the spirit of Unicode TS #39: lowercase
# Cyrillic, Greek and Latin-extension look-alikes folded to ASCII. Fullwidth and
# mathematical alphanumerics are already folded by NFKC during canonicalisation.
_CONFUSABLES = str.maketrans({
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ё": "e", "о": "o", "р": "p", "с": "c", "у": "y",
    "х": "x", "і": "i", "ї": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l",
    "ԛ": "q", "ԝ": "w", "к": "k", "ո": "n", "ս": "u", "т": "t", "м": "m", "н": "h",
    # Greek
    "α": "a", "β": "b", "γ": "y", "ε": "e", "ζ": "z", "η": "n", "ι": "i", "κ": "k",
    "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ω": "w", "ϲ": "c",
    "ϳ": "j", "ς": "c",
    # Latin extensions and IPA
    "ɡ": "g", "ı": "i", "ȷ": "j", "ɑ": "a", "ɩ": "i", "ɪ": "i", "ʏ": "y", "ɴ": "n",
    "ʀ": "r", "ꜱ": "s", "ᴏ": "o", "ᴄ": "c", "ᴅ": "d", "ᴇ": "e", "ᴜ": "u", "ᴠ": "v",
    "ᴡ": "w", "ᴢ": "z", "ʜ": "h", "ʟ": "l", "ᴍ": "m", "ᴛ": "t", "ᴋ": "k", "ᴘ": "p",
})
# Runs of >=4 single letters joined by one consistent single separator.
_SPACED_LETTERS_RE = re.compile(r"(?<![a-z0-9])[a-z]([ .\-])[a-z](?:\1[a-z]){2,}(?![a-z0-9])")
_SPACED_SEPARATORS_RE = re.compile(r"[ .\-]")
# Tokens holding at least one leetspeak character; folded only if they hold letters.
_LEET_TOKEN_RE = re.compile(r"(?<![a-z0-9@$])[a-z@$]*[0-9@$][a-z0-9@$]*")
_LEET_MAP = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s",
})
_ASCII_LETTER_RE = re.compile(r"[a-z]")


def _fold_leet(match: re.Match[str]) -> str:
    token = match.group(0)
    return token.translate(_LEET_MAP) if _ASCII_LETTER_RE.search(token) else token


def _deobfuscate(pre_canonical: str) -> str:
    """Confusables skeleton, letter-spacing collapse and leetspeak folding."""
    skeleton = pre_canonical.translate(_CONFUSABLES)
    collapsed = _SPACED_LETTERS_RE.sub(
        lambda m: _SPACED_SEPARATORS_RE.sub("", m.group(0)), skeleton
    )
    return _LEET_TOKEN_RE.sub(_fold_leet, collapsed)


@dataclass(frozen=True)
class _Surfaces:
    """All match surfaces of one text, computed once per text."""
    raw: str
    canonical: str
    deobfuscated: str | None  # None when identical to ``canonical``


def _surfaces(text: str) -> _Surfaces:
    pre = _pre_canonical(text)
    canonical = _WHITESPACE_RE.sub(" ", pre)
    deobfuscated = _WHITESPACE_RE.sub(" ", _deobfuscate(pre))
    return _Surfaces(text, canonical, None if deobfuscated == canonical else deobfuscated)


