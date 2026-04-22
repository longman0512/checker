"""
page_analyzer.py
----------------
Advanced webpage analysis for detecting login success/failure indicators.

Features:
- Toast notification detection
- Error message scanning
- Success message detection
- Alert popup detection
- Page state analysis
- Visual element inspection
- Multi-language support

Usage:
    from src.page_analyzer import analyze_page_for_result
    
    result, confidence, details = analyze_page_for_result(page, html)
    print(f"Result: {result} (confidence: {confidence}%)")
"""

import re
from typing import Tuple, Dict, Optional
from enum import Enum


class ResultConfidence(Enum):
    """Confidence level of result detection"""
    VERY_HIGH = 95       # Clear indicators found
    HIGH = 80            # Strong indicators found
    MEDIUM = 60          # Some indicators found
    LOW = 40             # Weak indicators
    UNCERTAIN = 20       # Uncertain, need other methods


# ─────────────────────────────────────────────────────────────────────────────
# Toast/Notification Selectors
# ─────────────────────────────────────────────────────────────────────────────

# Common toast notification containers
TOAST_SELECTORS = [
    # Generic toast containers
    ".toast", ".toast-message", ".notification", ".alert",
    "[role='alert']", "[role='status']",
    ".message", ".banner", ".popup",
    
    # Bootstrap alerts
    ".alert-success", ".alert-danger", ".alert-error", ".alert-warning",
    ".alert-info",
    
    # Material Design
    ".mdc-snackbar", ".mdl-snackbar",
    
    # Tailwind
    "[aria-live]", "[aria-atomic]",
    
    # Common frameworks
    ".toastr", ".notify", ".notice",
    ".message-box", ".info-box", ".error-box", ".success-box",
    
    # React packages
    ".Toastify__toast", ".react-toast",
    
    # jQuery
    ".jGrowl", ".pnotify",
    
    # Custom implementations
    ".notification-message", ".system-message",
    "[data-notify]", "[data-toast]", "[data-message]",
    
    # Angular
    "ngx-toastr", ".ng-toast",
    
    # Vue
    ".v-notification", ".vue-notification",
]

# Success indicator selectors
SUCCESS_SELECTORS = [
    ".toast-success", ".alert-success", ".success",
    "[class*='success']", "[class*='Success']",
]

# Error/Failure indicator selectors
ERROR_SELECTORS = [
    ".toast-error", ".alert-danger", ".alert-error", ".error",
    "[class*='error']", "[class*='Error']", "[class*='danger']",
    "[class*='Danger']", "[class*='failed']", "[class*='Failed']",
]

# Warning selectors (may require investigation)
WARNING_SELECTORS = [
    ".alert-warning", ".warning", "[class*='warning']",
]


# ─────────────────────────────────────────────────────────────────────────────
# Keyword Patterns
# ─────────────────────────────────────────────────────────────────────────────

SUCCESS_PATTERNS = [
    # English
    r'\bsuccess\b', r'\blogged\s+in\b', r'\blogin\s+success\b',
    r'\bauthenticated\b', r'\bwelcome\b', r'\bpassed\b',
    r'\bverified\b', r'\bauthorized\b', r'\bgranted\b',
    r'\bdashboard\b', r'\bportal\b', r'\baccount\b',
    
    # English - positive feedback
    r'\byou are now\b', r'\byou have been\b', r'\baccess granted\b',
    r'\blogin successful\b', r'\bauthentication successful\b',
    
    # Bulgarian
    r'\bуспешно\b', r'\bус\b', r'\bвход\s+успеш\b', r'\bверифици\b',
    
    # Polish
    r'\budanę\b', r'\buzytkownik\b', r'\bpanelu\b', r'\bpanel\b',
    r'\bzalogowałem\b', r'\bautentykacj\b', r'\bsukces\b',
]

FAILURE_PATTERNS = [
    # English
    r'\binvalid\b', r'\bincorrect\b', r'\bwrong\b',
    r'\bfailed\b', r'\bdenied\b', r'\bunauthorized\b',
    r'\bunknown\s+user\b', r'\buser\s+not\s+found\b',
    r'\bno\s+account\b', r'\bdisabled\b', r'\blocked\b',
    r'\bexpired\b', r'\binactive\b', r'\bsuspended\b',
    # English - negative feedback
    r'\bcredentials?\s+invalid\b', r'\blogon\s+failed\b',
    r'\bauthentication\s+failed\b', r'\berror.*login\b', r'\blogin.*error\b',
    r'\bincorrect.*password\b', r'\bwrong.*password\b',
    # WHMCS / Bootstrap alert-danger specific phrases
    r'\blogin\s+details\s+incorrect\b',
    r'\bdetails\s+incorrect\b',
    r'\busername\s+or\s+password\s+is\s+incorrect\b',
    r'\busername.*password.*combination\b',
    # Bulgarian
    r'\bгрешна\b', r'\bневалиден\b', r'\bнедействителен\b',
    r'\bнебезопас\b', r'\bи\d\b', r'\bотказ\b', r'\bфейл\b',
    # Polish
    r'\bniewłaściwym\b', r'\bneprawidł\b', r'\bbłąd\b',
    r'\bnieudane\b', r'\bnieudany\b', r'\bfail\b', r'\bwłog\b',
]

TWO_FACTOR_PATTERNS = [
    # English
    r'\b2fa\b', r'\bmfa\b', r'\btwo.?factor\b', r'\bmulti.?factor\b',
    r'\bverification\s+code\b', r'\bauthenticator\b', r'\botp\b',
    r'\benter\s+code\b', r'\bsend.*code\b', r'\bverify.*identity\b',
    r'\bone.?time\s+password\b', r'\bsecond.*factor\b',
    
    # Bulgarian
    r'\bдвуфактор\b', r'\bерификацион\b', r'\bкод\b',
    
    # Polish
    r'\bautentykator\b', r'\bdwuetapow\b', r'\bweryfikacj\b',
]

CAPTCHA_PATTERNS = [
    r'\bcaptcha\b', r'\brecaptcha\b', r'\bhcaptcha\b',
    r'\bbot\s+check\b', r'\bverify.*human\b', r'\bprove.*human\b',
    r'\brobotic\b', r'\bchallenge\b',
]


# ─────────────────────────────────────────────────────────────────────────────
# HTML Analysis Functions
# ─────────────────────────────────────────────────────────────────────────────

def find_visible_elements(page, selectors: list[str]) -> list[Tuple[str, str]]:
    """
    Find visible elements matching selectors.
    
    Returns: list of (selector, element_text)
    """
    from playwright.sync_api import TimeoutError as PWTimeout
    
    found = []
    for selector in selectors:
        try:
            if page.is_visible(selector, timeout=500):
                try:
                    text = page.inner_text(selector)
                    if text.strip():
                        found.append((selector, text.strip()[:200]))
                except Exception:
                    pass
        except PWTimeout:
            pass
        except Exception:
            pass
    
    return found


def extract_text_from_html(html: str) -> str:
    """Extract readable text from HTML"""
    from bs4 import BeautifulSoup
    try:
        soup = BeautifulSoup(html, "html.parser")
        # Remove script and style
        for tag in soup(["script", "style", "meta", "link"]):
            tag.decompose()
        return soup.get_text(separator=" ", strip=True)
    except Exception:
        return html


def find_pattern_matches(text: str, patterns: list[str]) -> list[Tuple[str, str]]:
    """
    Find text matching regex patterns.
    
    Returns: list of (pattern, matched_text)
    """
    matches = []
    text_lower = text.lower()
    
    for pattern in patterns:
        try:
            found_matches = re.finditer(pattern, text_lower, re.IGNORECASE)
            for match in found_matches:
                match_text = text_lower[max(0, match.start()-30):match.end()+30]
                matches.append((pattern, match_text.strip()))
        except Exception:
            pass
    
    return matches[:5]  # Return top 5 matches


def analyze_page_structure(page) -> Dict[str, int]:
    """Analyze page structure for success/failure indicators"""
    from playwright.sync_api import TimeoutError as PWTimeout
    
    indicators = {
        "password_fields_visible": 0,
        "login_forms_visible": 0,
        "error_messages_visible": 0,
        "success_messages_visible": 0,
        "notification_messages_visible": 0,
    }
    
    # Check for visible password fields (indicator of login form still present)
    try:
        if page.is_visible("input[type='password']", timeout=500):
            indicators["password_fields_visible"] = 1
    except PWTimeout:
        pass
    
    # Check for login form
    try:
        if page.is_visible("form[action*='login'], form[id*='login'], [class*='login']", timeout=500):
            indicators["login_forms_visible"] = 1
    except PWTimeout:
        pass
    
    # Check for error indicators
    for selector in ERROR_SELECTORS[:5]:
        try:
            if page.is_visible(selector, timeout=300):
                indicators["error_messages_visible"] += 1
                break
        except Exception:
            pass
    
    # Check for success indicators
    for selector in SUCCESS_SELECTORS[:5]:
        try:
            if page.is_visible(selector, timeout=300):
                indicators["success_messages_visible"] += 1
                break
        except Exception:
            pass
    
    # Check for notifications
    for selector in TOAST_SELECTORS[:10]:
        try:
            if page.is_visible(selector, timeout=300):
                indicators["notification_messages_visible"] += 1
                break
        except Exception:
            pass
    
    return indicators


def scan_for_notifications(page, html: str) -> Dict[str, list]:
    """Scan page and HTML for notification/toast messages"""
    from bs4 import BeautifulSoup
    
    notifications = {
        "visible": [],      # Currently visible on page
        "in_html": [],      # Found in HTML
    }
    
    # Look for visible notifications on page
    visible_notifications = find_visible_elements(page, TOAST_SELECTORS)
    notifications["visible"] = visible_notifications
    
    # Parse HTML for notification elements
    try:
        soup = BeautifulSoup(html, "html.parser")
        
        # Find all potential notification containers
        for selector_base in TOAST_SELECTORS[:20]:
            # Convert CSS selector to BeautifulSoup format
            class_patterns = [s.strip('.[]') for s in selector_base.split('.') if s.strip('.[]')]
            if class_patterns:
                for elem in soup.find_all(class_=class_patterns[0]):
                    text = elem.get_text(strip=True)
                    if text and len(text) < 300:
                        notifications["in_html"].append((selector_base, text[:150]))
    
    except Exception:
        pass
    
    return notifications


def analyze_error_messages(page, html: str) -> Dict[str, list]:
    """Find and analyze error messages on page"""
    from bs4 import BeautifulSoup
    
    errors = {
        "visible": [],      # Visible error elements
        "patterns": [],     # Pattern matches in text
        "details": [],      # Detailed error info
    }
    
    # Find visible error elements
    visible_errors = find_visible_elements(page, ERROR_SELECTORS)
    errors["visible"] = visible_errors
    
    # Extract and analyze text for error patterns
    try:
        text = extract_text_from_html(html)
        error_matches = find_pattern_matches(text, FAILURE_PATTERNS)
        errors["patterns"] = error_matches
        
        # Look for common error message structures
        soup = BeautifulSoup(html, "html.parser")
        for elem in soup.find_all(class_=re.compile(r'error|alert|danger', re.I)):
            error_text = elem.get_text(strip=True)
            if error_text and 20 < len(error_text) < 300:
                errors["details"].append(error_text[:150])
    
    except Exception:
        pass
    
    return errors


def analyze_success_indicators(page, html: str) -> Dict[str, list]:
    """Find and analyze success indicators on page"""
    from bs4 import BeautifulSoup
    
    success = {
        "visible": [],      # Visible success elements
        "patterns": [],     # Pattern matches
        "redirected": False, # URL changed from login
    }
    
    # Find visible success elements
    visible_success = find_visible_elements(page, SUCCESS_SELECTORS)
    success["visible"] = visible_success
    
    # Extract and analyze text for success patterns
    try:
        text = extract_text_from_html(html)
        success_matches = find_pattern_matches(text, SUCCESS_PATTERNS)
        success["patterns"] = success_matches
    except Exception:
        pass
    
    return success


# ─────────────────────────────────────────────────────────────────────────────
# Main Analysis Function
# ─────────────────────────────────────────────────────────────────────────────

def analyze_page_for_result(
    page,
    html: str,
    login_url: str = "",
    verbose: bool = False,
) -> Tuple[str, int, Dict]:
    """
    Comprehensive page analysis to determine login result.
    
    Parameters
    ----------
    page : Playwright Page
        Current page object (for live element inspection)
    html : str
        HTML content of the page
    login_url : str
        Original login URL for comparison
    verbose : bool
        Print detailed analysis
    
    Returns
    -------
    (result, confidence, details) where:
        result : str - "SUCCESS" | "FAILED" | "2FA_REQUIRED" | "CAPTCHA" | "UNKNOWN"
        confidence : int - 20-95 (confidence percentage)
        details : dict - Detailed analysis information
    
    Example
    -------
    >>> result, conf, details = analyze_page_for_result(page, html)
    >>> print(f"{result} ({conf}% confidence)")
    >>> if details['notifications']:
    ...     print(f"Notifications: {details['notifications']}")
    """
    
    details = {
        "notifications": [],
        "errors": {},
        "success_indicators": {},
        "page_structure": {},
        "2fa_detected": False,
        "captcha_detected": False,
        "url_changed": False,
    }
    
    current_url = page.url.lower() if hasattr(page, 'url') else ""
    login_url_lower = login_url.lower() if login_url else ""
    
    # ── 1. Page Structure Analysis ─────────────────────────────────────────
    page_structure = analyze_page_structure(page)
    details["page_structure"] = page_structure
    
    if verbose:
        print("[Analysis] Page structure:")
        for key, value in page_structure.items():
            print(f"  {key}: {value}")
    
    # ── 2. Scan for Notifications/Toast Messages ──────────────────────────
    notifications = scan_for_notifications(page, html)
    details["notifications"] = notifications
    
    if verbose and notifications["visible"]:
        print("[Analysis] Visible notifications:")
        for selector, text in notifications["visible"][:3]:
            print(f"  {selector}: {text[:60]}")
    
    # ── 3. Check for Error Messages ────────────────────────────────────────
    error_messages = analyze_error_messages(page, html)
    details["errors"] = error_messages
    
    if verbose and error_messages["visible"]:
        print("[Analysis] Error elements:")
        for selector, text in error_messages["visible"][:3]:
            print(f"  {selector}: {text[:60]}")
    
    # ── 4. Check for Success Indicators ────────────────────────────────────
    success_indicators = analyze_success_indicators(page, html)
    details["success_indicators"] = success_indicators
    
    if verbose and success_indicators["visible"]:
        print("[Analysis] Success elements:")
        for selector, text in success_indicators["visible"][:3]:
            print(f"  {selector}: {text[:60]}")
    
    # ── 5. Check for 2FA ─────────────────────────────────────────────────
    text = extract_text_from_html(html)
    two_factor_matches = find_pattern_matches(text, TWO_FACTOR_PATTERNS)
    if two_factor_matches:
        details["2fa_detected"] = True
        if verbose:
            print("[Analysis] 2FA detected!")
    
    # ── 6. Check for CAPTCHA ─────────────────────────────────────────────
    captcha_matches = find_pattern_matches(text, CAPTCHA_PATTERNS)
    if captcha_matches:
        details["captcha_detected"] = True
        if verbose:
            print("[Analysis] CAPTCHA detected!")
    
    # ── 7. URL Analysis ──────────────────────────────────────────────────
    if login_url_lower and current_url != login_url_lower:
        details["url_changed"] = True
        if verbose:
            print(f"[Analysis] URL changed: {login_url_lower} → {current_url}")
    
    # ── 8. Determine Result ──────────────────────────────────────────────
    result = "UNKNOWN"
    confidence = ResultConfidence.UNCERTAIN.value
    
    # Quick check priorities
    if details["captcha_detected"]:
        return "CAPTCHA", ResultConfidence.HIGH.value, details
    
    if details["2fa_detected"]:
        return "2FA_REQUIRED", ResultConfidence.HIGH.value, details
    
    # Strong error signals
    if error_messages["visible"] and error_messages["patterns"]:
        result = "FAILED"
        confidence = ResultConfidence.VERY_HIGH.value
    elif error_messages["visible"]:
        result = "FAILED"
        confidence = ResultConfidence.HIGH.value
    elif error_messages["patterns"]:
        result = "FAILED"
        confidence = ResultConfidence.MEDIUM.value
    
    # Strong success signals
    elif success_indicators["visible"] and not page_structure["password_fields_visible"]:
        result = "SUCCESS"
        confidence = ResultConfidence.VERY_HIGH.value
    elif success_indicators["visible"]:
        result = "SUCCESS"
        confidence = ResultConfidence.HIGH.value
    elif success_indicators["patterns"]:
        result = "SUCCESS"
        confidence = ResultConfidence.MEDIUM.value
    
    # Page structure signals
    elif page_structure["password_fields_visible"]:
        result = "FAILED"  # Still on login page = failed
        confidence = ResultConfidence.HIGH.value
    elif page_structure["error_messages_visible"]:
        result = "FAILED"
        confidence = ResultConfidence.MEDIUM.value
    elif page_structure["success_messages_visible"]:
        result = "SUCCESS"
        confidence = ResultConfidence.MEDIUM.value
    
    # URL-based signal
    elif details["url_changed"] and not page_structure["password_fields_visible"]:
        result = "SUCCESS"
        confidence = ResultConfidence.MEDIUM.value
    elif login_url_lower and current_url == login_url_lower:
        result = "FAILED"  # Still on login page
        confidence = ResultConfidence.LOW.value
    
    if verbose:
        print(f"\n[Result] {result} ({confidence}% confidence)")
    
    return result, confidence, details


# ─────────────────────────────────────────────────────────────────────────────
# Summary Report
# ─────────────────────────────────────────────────────────────────────────────

def generate_analysis_report(result: str, confidence: int, details: Dict) -> str:
    """Generate human-readable analysis report"""
    report = f"""
LOGIN ANALYSIS REPORT
═══════════════════════════════════════════════════════════════════════════
Result:                    {result}
Confidence:                {confidence}%

NOTIFICATIONS FOUND
───────────────────────────────────────────────────────────────────────────
Visible:                   {len(details['notifications'].get('visible', []))}
In HTML:                   {len(details['notifications'].get('in_html', []))}

ERROR INDICATORS
───────────────────────────────────────────────────────────────────────────
Visible elements:          {len(details['errors'].get('visible', []))}
Pattern matches:           {len(details['errors'].get('patterns', []))}
Details found:             {len(details['errors'].get('details', []))}

SUCCESS INDICATORS
───────────────────────────────────────────────────────────────────────────
Visible elements:          {len(details['success_indicators'].get('visible', []))}
Pattern matches:           {len(details['success_indicators'].get('patterns', []))}

SPECIAL DETECTIONS
───────────────────────────────────────────────────────────────────────────
2FA Detected:              {"YES" if details.get('2fa_detected') else "NO"}
CAPTCHA Detected:          {"YES" if details.get('captcha_detected') else "NO"}
URL Changed:               {"YES" if details.get('url_changed') else "NO"}

PAGE STRUCTURE
───────────────────────────────────────────────────────────────────────────
Password fields visible:   {details['page_structure'].get('password_fields_visible', 0)}
Login forms visible:       {details['page_structure'].get('login_forms_visible', 0)}
Error messages visible:    {details['page_structure'].get('error_messages_visible', 0)}
Success messages visible:  {details['page_structure'].get('success_messages_visible', 0)}
Notifications visible:     {details['page_structure'].get('notification_messages_visible', 0)}
═══════════════════════════════════════════════════════════════════════════
"""
    
    # Add notification details
    if details['notifications']['visible']:
        report += "\nVISIBLE NOTIFICATIONS:\n"
        for selector, text in details['notifications']['visible'][:3]:
            report += f"  • {text[:80]}\n"
    
    # Add error details
    if details['errors']['visible']:
        report += "\nERROR MESSAGES:\n"
        for selector, text in details['errors']['visible'][:3]:
            report += f"  • {text[:80]}\n"
    
    return report
