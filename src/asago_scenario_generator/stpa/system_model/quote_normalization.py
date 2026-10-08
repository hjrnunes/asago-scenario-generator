"""Index-preserving text normalization for quote matching.

Stated-rule matching and ``rule_span`` repair compare a model's quotation with
source text after casefolding, collapsing whitespace runs and folding
typographic punctuation.  Each keeps its own fold table and its own set of
ignored characters, so a caller passes both.  The normalized text maps every
character back to the source index it came from.
"""

from __future__ import annotations

_QUOTES_AND_DASHES = {
    "\u2018": "'",
    "\u2019": "'",
    "\u201c": '"',
    "\u201d": '"',
    "\u2010": "-",
    "\u2011": "-",
    "\u2013": "-",
    "\u2014": "-",
    "\u2212": "-",
}

# The folds the stated-rule matcher applies.
MATCHER_FOLD = str.maketrans(_QUOTES_AND_DASHES)
# Markdown emphasis and code markers carry no wording; models routinely drop
# them when quoting, so the matcher ignores them on both sides.
MATCHER_IGNORED = frozenset("*`")

# The folds the ``rule_span`` repair applies: the matcher's plus further
# low-9, reversed, prime and bar variants.  The repair ignores nothing,
# because a published span must stay a substring of its rule.
REPAIR_FOLD = str.maketrans(
    {
        **_QUOTES_AND_DASHES,
        "\u201a": "'",
        "\u201b": "'",
        "\u2032": "'",
        "\u201e": '"',
        "\u201f": '"',
        "\u2033": '"',
        "\u2012": "-",
        "\u2015": "-",
    }
)
REPAIR_IGNORED: frozenset[str] = frozenset()


def normalize_with_index(
    text: str, fold: dict[int, str], ignored: frozenset[str]
) -> tuple[str, list[int]]:
    """Normalize ``text`` and map each output character to its source index.

    ``fold`` is a ``str.translate`` table and ``ignored`` the characters
    dropped before whitespace is collapsed.  A whitespace run becomes one
    space at the index of its first character; none leads the result.
    """
    chars: list[str] = []
    index: list[int] = []
    pending_space: int | None = None
    for position, char in enumerate(text):
        if char in ignored:
            continue
        if char.isspace():
            if chars and pending_space is None:
                pending_space = position
            continue
        if pending_space is not None:
            chars.append(" ")
            index.append(pending_space)
            pending_space = None
        for folded in char.translate(fold).casefold():
            chars.append(folded)
            index.append(position)
    return "".join(chars), index
