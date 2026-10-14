"""Text clean-up shared by training and the running app, so both see the same tokens."""
from __future__ import annotations

import re

_URL = re.compile(r"(?:h(?:tt|xx)ps?\s?:\s?/\s?/\s?|www\s?\.\s?)\S+", re.I)
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_MONEY = re.compile(
    r"(?:rs\.?|inr|usd|₹|\$|£|€)\s?\d[\d,]*(?:\.\d+)?|\d[\d,]*(?:\.\d+)?\s?(?:rupees|dollars|pounds|lakhs?|crores?|p\b|ppm\b|pm\b)",
    re.I,
)
_PHONE = re.compile(r"\+?\d[\d\s-]{6,}\d")
_NUM = re.compile(r"\d+(?:[.,]\d+)*")
_SPACE = re.compile(r"\s+")

# Placeholder -> words shown to the user in explanations.
PLACEHOLDERS = {
    "urltoken": "a link",
    "emailtoken": "an e-mail address",
    "moneytoken": "a money amount",
    "phonetoken": "a phone or long number",
    "numtoken": "a number",
}

# Function words carry no meaning on their own; leaving them out keeps explanations readable.
STOP_WORDS = sorted({
    "a", "an", "the", "and", "or", "of", "to", "in", "on", "at", "is", "are", "was", "were", "be",
    "been", "being", "it", "its", "this", "that", "these", "those", "for", "with", "as", "by",
    "from", "i", "me", "my", "we", "us", "our", "he", "she", "him", "his", "her", "they", "them",
    "their", "am", "do", "does", "did", "has", "have", "had", "but", "if", "so", "than", "then",
    "there", "here", "what", "which", "who", "whom", "when", "where", "how", "not", "no", "can",
    "will", "would", "could", "should", "shall", "may", "might", "must", "about", "into", "up",
    "out", "all", "any", "some", "re", "ll", "ve", "nt", "im", "ur",
})


# Words that only identify where the training e-mails came from (one company's staff and
# one mailing list). They say nothing about scams, so the model must not use them.
CORPUS_ARTIFACTS = {
    "enron", "ect", "hou", "vince", "kaminski", "louise", "houston", "linguistics", "linguist",
    "paliourg", "hpl", "daren", "farmer", "corp", "kitchen", "shirley", "crenshaw", "stinson", "spamassassin", "sightings",
}
STOP_WORDS = sorted(set(STOP_WORDS) | CORPUS_ARTIFACTS)
_STOP = set(STOP_WORDS)


def normalise(text: str) -> str:
    """Lower-case and replace links, e-mails, money and numbers with placeholders.

    A UK phone number and an Indian one become the same token, so the model learns
    'this message contains a phone number', not one country's number format.
    """
    t = text.lower()
    t = _URL.sub(" urltoken ", t)
    t = _EMAIL.sub(" emailtoken ", t)
    t = _MONEY.sub(" moneytoken ", t)
    t = _PHONE.sub(" phonetoken ", t)
    t = _NUM.sub(" numtoken ", t)
    return _SPACE.sub(" ", t).strip()


TOKEN_PATTERN = r"(?u)\b[^\W\d_][^\W\d_]+\b"
_TOKEN = re.compile(TOKEN_PATTERN)


def tokens(text: str) -> list[str]:
    """Tokens exactly as the model's vectoriser sees them (before stop-word removal)."""
    return _TOKEN.findall(normalise(text))


def content_tokens(text: str) -> list[str]:
    """Meaningful words only: no placeholders, no stop words."""
    return [t for t in tokens(text) if t not in PLACEHOLDERS and t not in _STOP]
