#!/usr/bin/env python3
"""Check index.html for the retired brand and encoded emoji characters."""

import html
import re
import sys


EMOJI_RANGES = (
    (0x1F000, 0x1FAFF),
    (0x2600, 0x27BF),
    (0x2B00, 0x2BFF),
    (0xFE0F, 0xFE0F),
    (0x200D, 0x200D),
)


def decode_javascript_escapes(value):
    """Decode JavaScript Unicode escapes, including surrogate pairs."""
    value = re.sub(
        r"\\u([0-9A-Fa-f]{4})",
        lambda match: chr(int(match.group(1), 16)),
        value,
    )
    decoded = []
    index = 0
    while index < len(value):
        codepoint = ord(value[index])
        if (
            0xD800 <= codepoint <= 0xDBFF
            and index + 1 < len(value)
            and 0xDC00 <= ord(value[index + 1]) <= 0xDFFF
        ):
            low = ord(value[index + 1])
            decoded.append(chr(0x10000 + ((codepoint - 0xD800) << 10) + low - 0xDC00))
            index += 2
        else:
            decoded.append(value[index])
            index += 1
    return "".join(decoded)


def is_emoji(codepoint):
    if 0x2190 <= codepoint <= 0x21FF:  # Arrows are intentionally allowed.
        return False
    return any(start <= codepoint <= end for start, end in EMOJI_RANGES)


def main():
    try:
        source = open("index.html", encoding="utf-8").read()
    except OSError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    decoded = decode_javascript_escapes(html.unescape(source))
    occurrences = []
    for line_number, line in enumerate(decoded.splitlines(), 1):
        for character_number, character in enumerate(line, 1):
            if is_emoji(ord(character)):
                occurrences.append((line_number, character_number))

    voda_count = len(re.findall("voda", decoded, flags=re.IGNORECASE))
    print(f"emoji count: {len(occurrences)}")
    print(f"emoji locations: {occurrences}")
    print(f"voda count: {voda_count}")
    return 1 if occurrences or voda_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
