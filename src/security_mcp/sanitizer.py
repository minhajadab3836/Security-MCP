import re
from urllib.parse import urlparse

# Strict POSIX domain name regex
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# IPv4 address regex
IPV4_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

def sanitize_target(target: str) -> str:
    """
    Validates domain names or IP addresses.
    Blocks option flags (-) and shell characters.
    """
    target = target.strip()

    if not target:
        raise ValueError("Target cannot be empty.")

    # Guard against argument injection (e.g., target passed as "-o /etc/passwd")
    if target.startswith("-"):
        raise ValueError(f"Flag injection attempt detected: '{target}'")

    if DOMAIN_REGEX.match(target) or IPV4_REGEX.match(target):
        return target

    raise ValueError(f"Invalid domain or IP format: '{target}'")


def sanitize_url(url: str) -> str:
    """
    Validates HTTP/HTTPS URLs.
    """
    url = url.strip()

    if url.startswith("-"):
        raise ValueError(f"Flag injection attempt detected: '{url}'")

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported protocol scheme: '{parsed.scheme}'. Only HTTP/HTTPS allowed.")

    if not parsed.netloc:
        raise ValueError(f"Invalid URL structure: missing hostname in '{url}'")

    # Sanitize the underlying domain/host
    hostname = parsed.hostname or ""
    if hostname.startswith("-"):
        raise ValueError(f"Flag injection attempt detected in hostname: '{hostname}'")

    return url
