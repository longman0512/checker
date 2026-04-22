"""
credential_filter.py
--------------------
Credential deduplication and filtering.

Features:
- Remove exact duplicates (domain + username + password)
- Detect suspicious patterns (same username, many passwords)
- Normalize domains for accurate comparison
- Generate filtering reports
- Integration with batch processor

Usage:
    from src.credential_filter import filter_credentials, FilterReport
    
    filtered, report = filter_credentials(credentials)
    print(f"Removed {report.duplicates_count} duplicates")
"""

import hashlib
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse
from collections import defaultdict


# ─────────────────────────────────────────────────────────────────────────────
# Data Classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class FilterReport:
    """Report of filtering operations"""
    total_input: int = 0
    total_output: int = 0
    duplicates_count: int = 0
    duplicates: list[dict] = field(default_factory=list)
    
    # Same username, different passwords (potential issue)
    suspicious_accounts: dict[str, list] = field(default_factory=dict)
    
    # Same domain, many credentials
    high_volume_domains: dict[str, int] = field(default_factory=dict)
    
    # Invalid or malformed credentials
    skipped: list[dict] = field(default_factory=list)
    
    def summary(self) -> str:
        """Get text summary of filtering"""
        return f"""
Credential Filtering Report
═══════════════════════════════════════════════════════════════
Input:          {self.total_input} credentials
Output:         {self.total_output} credentials
Removed:        {self.duplicates_count} duplicates ({(self.duplicates_count/self.total_input*100) if self.total_input else 0:.1f}%)

Suspicious Accounts:    {len(self.suspicious_accounts)}
High-Volume Domains:    {len(self.high_volume_domains)}
Skipped/Invalid:        {len(self.skipped)}
═══════════════════════════════════════════════════════════════
"""


# ─────────────────────────────────────────────────────────────────────────────
# Utility Functions
# ─────────────────────────────────────────────────────────────────────────────

def normalize_domain(url: str) -> str:
    """
    Extract and normalize domain from URL.
    
    Examples:
        https://example.com/login → example.com
        portal.example.com:443/auth → portal.example.com
        example.com → example.com
    """
    if not url:
        return ""
    
    # Parse URL if it has scheme
    if "://" in url:
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path.split("/")[0]
        except Exception:
            domain = url.split("/")[0]
    else:
        # No scheme — assume domain-only or domain/path
        domain = url.split("/")[0]
    
    # Remove port if present
    if ":" in domain:
        domain = domain.split(":")[0]
    
    # Normalize to lowercase
    return domain.lower().strip()


def get_credential_fingerprint(domain: str, username: str, password: str) -> str:
    """
    Generate unique fingerprint for credential deduplication.
    
    Same domain + username + password = same fingerprint = duplicate
    """
    normalized_domain = normalize_domain(domain)
    fingerprint_str = f"{normalized_domain}||{username.strip().lower()}||{password}"
    return hashlib.sha256(fingerprint_str.encode()).hexdigest()


def is_valid_credential(cred: dict) -> tuple[bool, Optional[str]]:
    """
    Validate credential has required fields.
    
    Returns: (is_valid, error_message)
    """
    if not isinstance(cred, dict):
        return False, "Not a dict"
    
    username = cred.get("username", "").strip()
    password = cred.get("password", "").strip()
    
    if not username:
        return False, "Missing username"
    if not password:
        return False, "Missing password"
    
    url = cred.get("url", "").strip()
    if url and "://" not in url:
        # Allow domain-only URLs, they'll be handled
        pass
    
    return True, None


# ─────────────────────────────────────────────────────────────────────────────
# Main Filter Function
# ─────────────────────────────────────────────────────────────────────────────

def filter_credentials(
    credentials: list[dict],
    remove_duplicates: bool = True,
    detect_suspicious: bool = True,
) -> tuple[list[dict], FilterReport]:
    """
    Filter and deduplicate credentials.
    
    Parameters
    ----------
    credentials : list[dict]
        Input credentials with keys: username, password, url, (optional) domain
    remove_duplicates : bool
        Remove exact duplicates (same domain + username + password)
    detect_suspicious : bool
        Detect suspicious patterns (same username, many passwords)
    
    Returns
    -------
    (filtered_credentials, report) where:
        filtered_credentials : list of deduplicated credentials
        report : FilterReport with detailed statistics
    
    Examples
    --------
    >>> creds = [
    ...     {"username": "user1", "password": "pass1", "url": "https://example.com"},
    ...     {"username": "user1", "password": "pass1", "url": "https://example.com"},  # duplicate
    ...     {"username": "user2", "password": "pass2", "url": "https://example.com"},
    ... ]
    >>> filtered, report = filter_credentials(creds)
    >>> len(filtered)
    2
    >>> report.duplicates_count
    1
    """
    report = FilterReport(total_input=len(credentials))
    filtered = []
    seen_fingerprints = set()
    
    # Track domain usage and username usage
    domain_counts = defaultdict(int)
    username_passwords = defaultdict(set)  # username → set of passwords
    
    # First pass: validate and collect statistics
    valid_credentials = []
    for cred in credentials:
        is_valid, error = is_valid_credential(cred)
        if not is_valid:
            report.skipped.append({
                "credential": cred,
                "reason": error,
            })
            continue
        valid_credentials.append(cred)
        
        # Collect statistics
        domain = normalize_domain(cred.get("url", cred.get("domain", "")))
        username = cred.get("username", "").strip().lower()
        password = cred.get("password", "").strip()
        
        domain_counts[domain] += 1
        username_passwords[username].add(password)
    
    # Identify high-volume domains (more than 10 creds for same domain)
    for domain, count in domain_counts.items():
        if count > 10:
            report.high_volume_domains[domain] = count
    
    # Identify suspicious accounts (same username, many different passwords)
    for username, passwords in username_passwords.items():
        if len(passwords) > 1:
            report.suspicious_accounts[username] = list(passwords)[:5]  # Show first 5
    
    # Second pass: deduplicate
    for cred in valid_credentials:
        domain = normalize_domain(cred.get("url", cred.get("domain", "")))
        username = cred.get("username", "").strip()
        password = cred.get("password", "").strip()
        
        fingerprint = get_credential_fingerprint(domain, username, password)
        
        if fingerprint in seen_fingerprints:
            # Duplicate found
            if remove_duplicates:
                report.duplicates.append({
                    "domain": domain,
                    "username": username,
                    "password": password[:10] + "..." if len(password) > 10 else password,
                })
                report.duplicates_count += 1
                continue
        
        seen_fingerprints.add(fingerprint)
        filtered.append(cred)
    
    report.total_output = len(filtered)
    return filtered, report


# ─────────────────────────────────────────────────────────────────────────────
# Advanced Filtering Functions
# ─────────────────────────────────────────────────────────────────────────────

def filter_by_domain(credentials: list[dict], domain: str) -> list[dict]:
    """Filter credentials for a specific domain"""
    normalized = normalize_domain(domain)
    return [
        c for c in credentials
        if normalize_domain(c.get("url", c.get("domain", ""))) == normalized
    ]


def filter_by_username(credentials: list[dict], username: str) -> list[dict]:
    """Filter credentials for a specific username"""
    username_lower = username.lower()
    return [
        c for c in credentials
        if c.get("username", "").strip().lower() == username_lower
    ]


def group_by_domain(credentials: list[dict]) -> dict[str, list[dict]]:
    """Group credentials by domain"""
    grouped = defaultdict(list)
    for cred in credentials:
        domain = normalize_domain(cred.get("url", cred.get("domain", "")))
        grouped[domain].append(cred)
    return dict(grouped)


def detect_credential_reuse(credentials: list[dict]) -> dict[str, list[dict]]:
    """
    Find credentials that are reused across multiple domains.
    
    Returns: {username: list of credentials with that username}
    """
    reuse = defaultdict(list)
    for cred in credentials:
        username = cred.get("username", "").strip().lower()
        reuse[username].append(cred)
    
    # Only return users with multiple credentials
    return {u: c for u, c in reuse.items() if len(c) > 1}


# ─────────────────────────────────────────────────────────────────────────────
# Batch Processing Integration
# ─────────────────────────────────────────────────────────────────────────────

def prepare_batch(
    credentials: list[dict],
    remove_duplicates: bool = True,
    verbose: bool = True,
) -> tuple[list[dict], FilterReport]:
    """
    Prepare credentials for batch processing.
    
    This is the recommended preprocessing step before calling
    try_login_batch_parallel().
    
    Parameters
    ----------
    credentials : list[dict]
        Raw credential list (may contain duplicates)
    remove_duplicates : bool
        Remove exact duplicates
    verbose : bool
        Print filtering report to console
    
    Returns
    -------
    (prepared_credentials, report)
    
    Example
    -------
    >>> from src.parser import parse_credential_line
    >>> from src.credential_filter import prepare_batch
    >>> from src.checker import try_login_batch_parallel
    >>> 
    >>> # Load credentials
    >>> raw_creds = [parse_credential_line(line) for line in open("creds.txt")]
    >>> 
    >>> # Clean and prepare
    >>> clean_creds, report = prepare_batch(raw_creds)
    >>> print(report.summary())
    >>> 
    >>> # Run batch check
    >>> results = try_login_batch_parallel(clean_creds, max_workers=8)
    """
    filtered, report = filter_credentials(
        credentials,
        remove_duplicates=remove_duplicates,
        detect_suspicious=True,
    )
    
    if verbose:
        print(report.summary())
        
        if report.suspicious_accounts:
            print("\n⚠️  Suspicious Accounts (same user, many passwords):")
            for user, passwords in list(report.suspicious_accounts.items())[:5]:
                print(f"  • {user}: {len(passwords)} different passwords")
        
        if report.high_volume_domains:
            print("\n🔍 High-Volume Domains:")
            for domain, count in sorted(report.high_volume_domains.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"  • {domain}: {count} credentials")
    
    return filtered, report


# ─────────────────────────────────────────────────────────────────────────────
# CLI Tool Integration
# ─────────────────────────────────────────────────────────────────────────────

def get_filter_stats(credentials: list[dict]) -> dict:
    """Get comprehensive filter statistics"""
    filtered, report = filter_credentials(credentials)
    
    reuse = detect_credential_reuse(filtered)
    grouped = group_by_domain(filtered)
    
    return {
        "total_initial": report.total_input,
        "total_after_dedup": report.total_output,
        "duplicates_removed": report.duplicates_count,
        "unique_domains": len(grouped),
        "credential_reuse": len(reuse),
        "suspicious_accounts": len(report.suspicious_accounts),
        "high_volume_domains": len(report.high_volume_domains),
        "invalid_skipped": len(report.skipped),
    }
