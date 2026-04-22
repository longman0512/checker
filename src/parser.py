"""
parser.py
---------
Responsible for reading and parsing credential files.

Supported line formats:
    url:username:password
    url|username|password
    url;username;password
    https://url/path:username:password
    https://url:port/path:username:password

Lines starting with '#' are treated as comments and ignored.
"""

import re
from urllib.parse import urlparse

# Matches lines with an explicit http/https scheme.
#
# Group 1 – URL:  scheme + host (+ optional :port) + optional path
#   (?::\d{1,5})?  — port is ONLY digits (1-5), not mistaken for credentials
#   (?:/[^:|;]*)?  — path segment(s) up to the first separator char
#
# Group 2 – separator: one of  :  |  ;
# Group 3 – username: everything up to the next separator (may include @)
# Group 4 – separator again (same char)
# Group 5 – password: the rest of the line (may contain :, @, etc.)
_URL_RE = re.compile(
    r'^(https?://[^/:|;]+(?::\d{1,5})?(?:/[^:|;]*)?)'  # URL (incl. optional port + path)
    r'([:|;])'                                           # separator after URL
    r'([^:|;]*)'                                         # username
    r'\2'                                                # same separator
    r'(.+)$',                                            # password
    re.IGNORECASE,
)

# Fallback for lines without a scheme:  host/path SEP user SEP pass
_NOSCHEME_RE = re.compile(
    r'^([^:|;\s]+)'   # host (+ optional path), no separator chars
    r'([:|;])'        # separator
    r'([^:|;]*)'      # username
    r'\2'             # same separator
    r'(.+)$',         # password
)


def parse_credential_line(line: str) -> dict | None:
    """
    Parse a single credential line into a dictionary.

    Returns None for blank lines, comments, or malformed entries.
    Handles passwords that contain ':', '@', etc.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    m = _URL_RE.match(line) or _NOSCHEME_RE.match(line)
    if not m:
        return None

    url_part, _sep, username, password = m.group(1), m.group(2), m.group(3), m.group(4)

    if not url_part.lower().startswith("http"):
        url_part = "https://" + url_part

    try:
        parsed = urlparse(url_part)
        # hostname strips port; fall back to netloc (minus port) then path component
        domain = parsed.hostname or parsed.netloc.split(":")[0] or parsed.path.split("/")[0]
    except ValueError:
        # urlparse raises ValueError for malformed IPv6 addresses — skip the line
        return None

    return {
        "url":      url_part,
        "domain":   domain,
        "username": username,
        "password": password,
        "status":   "Pending",
    }


def load_credentials(filepath: str) -> list[dict]:
    """
    Read a credential file and return a list of parsed entry dicts.

    Invalid / blank lines are silently skipped.
    """
    credentials = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            entry = parse_credential_line(line)
            if entry:
                credentials.append(entry)
    return credentials
