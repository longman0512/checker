"""
form_cache.py
─────────────

Domain-based caching for login form detection and result patterns.

Caches:
1. **Form Field Selectors** — username, password fields, login button per domain
2. **Result Detection Patterns** — what indicators worked for a domain
3. **Notification Selectors** — which toast/alert selectors found indicators

This speeds up repeated logins to the same domain and improves result detection
accuracy by learning from previous successful checks.

Usage:
    from src.form_cache import FormCache
    
    cache = FormCache("cache.json")
    
    # Check cache for form fields
    cached = cache.get_form_fields("example.com")
    if cached:
        username_field, password_field, submit_button = cached
    else:
        # Detect form fields
        username_field, password_field = _detect_fields(html)
        submit_button = _detect_submit_button(page)
        # Cache the result
        cache.set_form_fields("example.com", username_field, password_field, submit_button)
    
    # Check cache for result patterns
    cached_result = cache.get_result_pattern("example.com", html)
    if cached_result:
        result = cached_result  # Use cached pattern
    else:
        # Detect result normally
        result = analyze_page_for_result(page, html)
        # Cache what worked
        cache.add_result_pattern("example.com", result, indicator_selector, indicator_text)
    
    # Save cache to disk
    cache.save()
"""

import json
import re
from typing import Optional, Tuple, Dict, List
from pathlib import Path
from urllib.parse import urlparse


class FormCache:
    """
    Domain-based cache for login form selectors and result patterns.
    
    Structure:
    {
        "domains": {
            "example.com": {
                "form_fields": {
                    "username_field": "input[name='user']",
                    "password_field": "input[type='password']",
                    "submit_button": "button[type='submit']",
                    "last_used": 1234567890
                },
                "result_patterns": [
                    {
                        "result": "SUCCESS",
                        "selector": ".alert-success",
                        "text_pattern": "logged in",
                        "count": 5,
                        "success_rate": 1.0
                    },
                    ...
                ]
            }
        }
    }
    """
    
    def __init__(self, cache_file: str = "form_cache.json"):
        """Initialize cache from file if it exists"""
        self.cache_file = Path(cache_file)
        self.data = {"domains": {}}
        
        if self.cache_file.exists():
            try:
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                    if isinstance(loaded, dict) and "domains" in loaded:
                        self.data = loaded
            except Exception as e:
                print(f"[FormCache] Warning: Could not load cache from {cache_file}: {e}")
    
    # ─────────────────────────────────────────────────────────────────────────
    # Domain Extraction
    # ─────────────────────────────────────────────────────────────────────────
    
    @staticmethod
    def extract_domain(url: str) -> str:
        """
        Extract domain from URL.
        
        Examples:
            https://my.superhosting.bg/login → superhosting.bg
            https://panel.home.pl/admin → home.pl
            https://example.co.uk → example.co.uk
        """
        try:
            parsed = urlparse(url.lower())
            domain = parsed.netloc or url.lower()
            
            # Remove 'www.' prefix
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Remove port if present
            domain = domain.split(':')[0]
            
            return domain
        except Exception:
            return url.lower()
    
    # ─────────────────────────────────────────────────────────────────────────
    # Form Field Caching
    # ─────────────────────────────────────────────────────────────────────────
    
    def get_form_fields(self, domain: str) -> Optional[Tuple[str, str, str]]:
        """
        Get cached form field selectors for a domain.
        
        Returns:
            (username_field, password_field, submit_button) or None if not cached
        """
        domain = domain.lower().strip()
        
        if domain not in self.data["domains"]:
            return None
        
        form_data = self.data["domains"][domain].get("form_fields")
        if not form_data:
            return None
        
        username = form_data.get("username_field")
        password = form_data.get("password_field")
        submit = form_data.get("submit_button")
        
        if username and password and submit:
            return (username, password, submit)
        
        return None
    
    def set_form_fields(
        self,
        domain: str,
        username_field: str,
        password_field: str,
        submit_button: str,
    ) -> None:
        """
        Cache form field selectors for a domain.
        """
        domain = domain.lower().strip()
        
        if domain not in self.data["domains"]:
            self.data["domains"][domain] = {}
        
        self.data["domains"][domain]["form_fields"] = {
            "username_field": username_field,
            "password_field": password_field,
            "submit_button": submit_button,
            "last_used": self._get_timestamp(),
        }
    
    # ─────────────────────────────────────────────────────────────────────────
    # Result Pattern Caching
    # ─────────────────────────────────────────────────────────────────────────
    
    def get_result_pattern(
        self,
        domain: str,
        html: str,
    ) -> Optional[Tuple[str, int]]:
        """
        Check cached result patterns for a domain against HTML content.
        
        Matches HTML against known patterns for the domain.
        
        Returns:
            (result, confidence) or None if no pattern matched
        """
        domain = domain.lower().strip()
        
        if domain not in self.data["domains"]:
            return None
        
        patterns = self.data["domains"][domain].get("result_patterns", [])
        if not patterns:
            return None
        
        # Sort by success rate (highest first)
        patterns = sorted(
            patterns,
            key=lambda p: p.get("success_rate", 0),
            reverse=True
        )
        
        html_lower = html.lower()
        
        # Try each pattern against HTML
        for pattern in patterns:
            if self._pattern_matches(html_lower, pattern):
                result = pattern.get("result", "UNKNOWN")
                confidence = int(pattern.get("confidence", 80))
                return (result, confidence)
        
        return None
    
    def add_result_pattern(
        self,
        domain: str,
        result: str,
        selector: Optional[str] = None,
        text_pattern: Optional[str] = None,
        confidence: int = 80,
    ) -> None:
        """
        Add a successful result pattern for a domain.
        
        Parameters:
            domain — Domain to cache for
            result — Result status (SUCCESS, FAILED, 2FA_REQUIRED, CAPTCHA)
            selector — CSS selector that indicated this result (e.g., ".alert-success")
            text_pattern — Text pattern that indicated this result (e.g., "logged in")
            confidence — Confidence level (20-95)
        """
        domain = domain.lower().strip()
        
        if domain not in self.data["domains"]:
            self.data["domains"][domain] = {}
        
        if "result_patterns" not in self.data["domains"][domain]:
            self.data["domains"][domain]["result_patterns"] = []
        
        patterns = self.data["domains"][domain]["result_patterns"]
        
        # Check if pattern already exists
        existing = None
        for p in patterns:
            if p.get("result") == result and p.get("selector") == selector:
                existing = p
                break
        
        if existing:
            # Update existing pattern
            existing["count"] = existing.get("count", 1) + 1
            # Update success rate (incrementally)
            old_rate = existing.get("success_rate", 0.5)
            existing["success_rate"] = (old_rate + 1.0) / (existing.get("count", 2))
            existing["last_used"] = self._get_timestamp()
        else:
            # Add new pattern
            patterns.append({
                "result": result,
                "selector": selector,
                "text_pattern": text_pattern,
                "confidence": confidence,
                "count": 1,
                "success_rate": 0.9,
                "last_used": self._get_timestamp(),
            })
        
        # Keep only top 10 patterns per domain (by success rate)
        if len(patterns) > 10:
            patterns.sort(key=lambda p: p.get("success_rate", 0), reverse=True)
            self.data["domains"][domain]["result_patterns"] = patterns[:10]
    
    def _pattern_matches(self, html: str, pattern: Dict) -> bool:
        """Check if HTML matches a cached pattern"""
        # Text pattern matching
        if pattern.get("text_pattern"):
            try:
                if re.search(pattern["text_pattern"], html, re.IGNORECASE):
                    return True
            except Exception:
                pass
        
        # Selector matching (text search for now, since we only have HTML)
        if pattern.get("selector"):
            selector = pattern["selector"]
            # Simple text-based matching: look for selector class/id in HTML
            selector_text = selector.replace(".", " ").replace("#", " ").replace("[", " ").replace("]", " ")
            if any(part in html for part in selector_text.split() if part and len(part) > 2):
                return True
        
        return False
    
    # ─────────────────────────────────────────────────────────────────────────
    # Notification Selector Caching
    # ─────────────────────────────────────────────────────────────────────────
    
    def get_notification_selectors(self, domain: str) -> List[str]:
        """
        Get cached notification selectors that worked for this domain.
        
        Returns most successful selectors first (by usage count).
        """
        domain = domain.lower().strip()
        
        if domain not in self.data["domains"]:
            return []
        
        selectors_data = self.data["domains"][domain].get("notification_selectors", {})
        
        # Sort by success count
        sorted_selectors = sorted(
            selectors_data.items(),
            key=lambda x: x[1].get("count", 0),
            reverse=True
        )
        
        return [selector for selector, _ in sorted_selectors]
    
    def add_notification_selector(self, domain: str, selector: str) -> None:
        """Mark that a notification selector worked for this domain"""
        domain = domain.lower().strip()
        
        if domain not in self.data["domains"]:
            self.data["domains"][domain] = {}
        
        if "notification_selectors" not in self.data["domains"][domain]:
            self.data["domains"][domain]["notification_selectors"] = {}
        
        selectors = self.data["domains"][domain]["notification_selectors"]
        
        if selector not in selectors:
            selectors[selector] = {"count": 0, "last_used": None}
        
        selectors[selector]["count"] += 1
        selectors[selector]["last_used"] = self._get_timestamp()
    
    # ─────────────────────────────────────────────────────────────────────────
    # Persistence
    # ─────────────────────────────────────────────────────────────────────────
    
    def save(self) -> bool:
        """Save cache to disk"""
        try:
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.data, f, indent=2)
            return True
        except Exception as e:
            print(f"[FormCache] Error saving cache: {e}")
            return False
    
    def load(self) -> bool:
        """Reload cache from disk"""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                    if isinstance(loaded, dict) and "domains" in loaded:
                        self.data = loaded
                        return True
        except Exception as e:
            print(f"[FormCache] Error loading cache: {e}")
        return False
    
    def clear(self) -> None:
        """Clear all cache data"""
        self.data = {"domains": {}}
    
    def clear_domain(self, domain: str) -> None:
        """Clear cache for a specific domain"""
        domain = domain.lower().strip()
        if domain in self.data["domains"]:
            del self.data["domains"][domain]
    
    # ─────────────────────────────────────────────────────────────────────────
    # Statistics
    # ─────────────────────────────────────────────────────────────────────────
    
    def get_stats(self) -> Dict:
        """Get cache statistics"""
        total_domains = len(self.data["domains"])
        total_form_fields = sum(
            1 for d in self.data["domains"].values()
            if d.get("form_fields")
        )
        total_patterns = sum(
            len(d.get("result_patterns", []))
            for d in self.data["domains"].values()
        )
        
        return {
            "total_domains": total_domains,
            "cached_form_fields": total_form_fields,
            "cached_result_patterns": total_patterns,
            "cache_file": str(self.cache_file),
        }
    
    def print_stats(self) -> None:
        """Print cache statistics"""
        stats = self.get_stats()
        print("\n" + "=" * 70)
        print("FORM CACHE STATISTICS")
        print("=" * 70)
        print(f"  Domains cached:          {stats['total_domains']}")
        print(f"  Form field sets cached:  {stats['cached_form_fields']}")
        print(f"  Result patterns cached:  {stats['cached_result_patterns']}")
        print(f"  Cache file:              {stats['cache_file']}")
        print("=" * 70 + "\n")
    
    # ─────────────────────────────────────────────────────────────────────────
    # Utility
    # ─────────────────────────────────────────────────────────────────────────
    
    @staticmethod
    def _get_timestamp() -> int:
        """Get current timestamp"""
        import time
        return int(time.time())


# Global cache instance
_global_cache = None


def get_global_cache(cache_file: str = "form_cache.json") -> FormCache:
    """Get or create global cache instance"""
    global _global_cache
    if _global_cache is None:
        _global_cache = FormCache(cache_file)
    return _global_cache


def reset_global_cache() -> None:
    """Reset global cache (useful for testing)"""
    global _global_cache
    _global_cache = None
