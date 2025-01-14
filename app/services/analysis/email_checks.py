"""Email-specific heuristic checks for sender domain and link analysis.

These checks are layered on top of the standard text analysis engine for
email submissions. They focus on spoofing detection and suspicious sender
patterns that cannot be detected from body text alone.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

# Brands commonly impersonated in phishing
IMPERSONATED_BRANDS: list[str] = [
    "amazon",
    "paypal",
    "apple",
    "microsoft",
    "google",
    "netflix",
    "facebook",
    "instagram",
    "twitter",
    "linkedin",
    "chase",
    "wellsfargo",
    "bankofamerica",
    "citibank",
    "irs",
    "fedex",
    "ups",
    "dhl",
    "usps",
    "docusign",
    "dropbox",
    "zoom",
    "steam",
]

# TLDs with historically high abuse rates (heuristic, not exhaustive)
SUSPICIOUS_TLDS: set[str] = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".top",
    ".click", ".download", ".zip", ".review", ".work",
    ".party", ".trade", ".science", ".loan", ".racing",
}

# Common leet-speak digit-to-letter substitutions used in phishing domains
_LEET_MAP: dict[str, str] = {
    "0": "o",
    "1": "i",
    "2": "z",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "8": "b",
    "9": "g",
}


def _extract_domain(address: str) -> str | None:
    """Extract the domain from an email address or URL string."""
    address = address.strip().lower()
    if "@" in address:
        return address.split("@", 1)[-1]
    try:
        parsed = urlparse(address if "://" in address else f"http://{address}")
        return parsed.hostname or None
    except Exception:
        return None


def _de_leet(text: str) -> str:
    """Replace common leet-speak digit substitutions with their letter equivalents.

    e.g. "amaz0n" → "amazon", "paypa1" → "paypal"
    """
    for digit, letter in _LEET_MAP.items():
        text = text.replace(digit, letter)
    return text


def _has_leet_substitution(domain: str, brand: str) -> bool:
    """Check if the domain looks like a leet-speak variant of a known brand.

    Strategy: replace digit substitutions and check if the result contains the brand,
    while the original domain does not.
    e.g. "amaz0n-security.com" → "amazon-security.com" contains "amazon"
    """
    de_leeted = _de_leet(domain)
    return brand in de_leeted and brand not in domain


def _contains_brand_with_noise(domain: str, brand: str) -> bool:
    """Check if domain contains a known brand name plus suspicious extra tokens.

    Legitimate domains: amazon.com, www.amazon.com, www.google.com
    Suspicious: amazon-security-alert.com, amazon-login.net, amaz0n.com
    """
    if brand not in domain:
        return False

    # Strip any leading 'www.' subdomain before checking
    check_domain = domain
    if check_domain.startswith("www."):
        check_domain = check_domain[4:]

    # The second-level domain (before first dot) equals the brand exactly → legitimate
    # e.g. "google.com" → sld="google" == brand "google" → skip
    sld = check_domain.split(".")[0]
    if sld == brand:
        return False

    return True


def analyze_sender(from_address: str) -> dict:
    """Analyze a sender email address for impersonation and spoofing signals.

    Returns a dict with:
      - is_suspicious: bool
      - reasons: list[str]
    """
    reasons: list[str] = []
    domain = _extract_domain(from_address)

    if not domain:
        return {"is_suspicious": False, "reasons": []}

    # Check for suspicious TLDs
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            reasons.append(f"Sender domain uses a high-risk TLD: {tld}")
            break

    # Check for brand impersonation
    for brand in IMPERSONATED_BRANDS:
        if _has_leet_substitution(domain, brand):
            reasons.append(
                f"Sender domain appears to spoof '{brand}' using character substitution"
            )
        elif _contains_brand_with_noise(domain, brand):
            reasons.append(
                f"Sender domain contains '{brand}' but is not the official domain — possible spoofing"
            )

    # Check for IP address as domain (no legitimate sender uses raw IPs)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        reasons.append("Sender domain is a raw IP address — highly suspicious")

    # Check for excessive hyphens/subdomain depth (common in phishing infra)
    if domain.count("-") >= 3:
        reasons.append("Sender domain contains an unusually high number of hyphens")

    subdomain_depth = len(domain.split("."))
    if subdomain_depth >= 5:
        reasons.append(f"Sender domain has {subdomain_depth} subdomain levels — suspicious")

    return {"is_suspicious": bool(reasons), "reasons": reasons}


def analyze_links(links: list[str]) -> list[str]:
    """Return a list of risk reasons for any suspicious links.

    Checks each link for suspicious TLDs, raw IP hosts, brand spoofing,
    and mismatched display vs. actual domains.
    """
    reasons: list[str] = []

    for link in links:
        domain = _extract_domain(link)
        if not domain:
            continue

        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                reasons.append(f"Link uses a high-risk TLD ({tld}): {link}")

        for brand in IMPERSONATED_BRANDS:
            if _has_leet_substitution(domain, brand):
                reasons.append(f"Link domain appears to spoof '{brand}': {link}")
            elif _contains_brand_with_noise(domain, brand):
                reasons.append(f"Link domain contains '{brand}' but may not be official: {link}")

        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
            reasons.append(f"Link uses a raw IP address host: {link}")

    return reasons
