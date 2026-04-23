"""
styles.py
---------
Centralised colour palette and ttk style configuration.
Import and call apply_styles(root) once at app startup.
"""

import tkinter as tk
from tkinter import ttk


# ---------------------------------------------------------------------------
# Tooltip helper
# ---------------------------------------------------------------------------

class Tooltip:
    """Show a small floating label when the mouse hovers over a widget."""

    def __init__(self, widget: tk.Widget, text: str, delay: int = 500):
        self._widget = widget
        self._text   = text
        self._delay  = delay
        self._id     = None
        self._top: tk.Toplevel | None = None
        widget.bind("<Enter>",    self._on_enter,  add="+")
        widget.bind("<Leave>",    self._on_leave,  add="+")
        widget.bind("<ButtonPress>", self._on_leave, add="+")

    def _on_enter(self, _event=None):
        self._id = self._widget.after(self._delay, self._show)

    def _on_leave(self, _event=None):
        if self._id:
            self._widget.after_cancel(self._id)
            self._id = None
        if self._top:
            self._top.destroy()
            self._top = None

    def _show(self):
        if self._top:
            return
        x = self._widget.winfo_rootx() + 20
        y = self._widget.winfo_rooty() + self._widget.winfo_height() + 4
        self._top = tk.Toplevel(self._widget)
        self._top.wm_overrideredirect(True)
        self._top.wm_geometry(f"+{x}+{y}")
        lbl = tk.Label(
            self._top,
            text=self._text,
            background="#2a2a3e",
            foreground="#cdd6f4",
            relief="flat",
            borderwidth=1,
            font=("Segoe UI", 9),
            padx=6, pady=3,
            wraplength=380,
            justify="left",
        )
        lbl.pack()


# ---------------------------------------------------------------------------
# Colour palette  (Catppuccin Mocha – dark theme)
# ---------------------------------------------------------------------------

PALETTE = {
    "bg":          "#1e1e2e",   # main background
    "surface":     "#313244",   # slightly lighter surface
    "heading":     "#181825",   # darkest — tree headings
    "fg":          "#cdd6f4",   # primary text
    "accent":      "#89b4fa",   # blue accent (buttons, headings)
    "green":       "#a6e3a1",   # success
    "red":         "#f38ba8",   # failed / error
    "yellow":      "#f9e2af",   # unknown / warning
    "muted":       "#6c7086",   # placeholder / muted text
    "hover":       "#74c7ec",   # button hover
    "disabled":    "#45475a",   # disabled element
    "select":      "#585b70",   # treeview selection
    "row_odd":     "#313244",
    "row_even":    "#1e1e2e",
}


# ---------------------------------------------------------------------------
# Public helper
# ---------------------------------------------------------------------------

def apply_styles(root: tk.Tk) -> dict:
    """
    Configure all ttk styles for *root* and return the PALETTE dict
    so callers can use the colours directly.
    """
    root.configure(bg=PALETTE["bg"])

    style = ttk.Style(root)
    style.theme_use("clam")

    # Base
    style.configure(".",
        background=PALETTE["bg"],
        foreground=PALETTE["fg"],
        font=("Segoe UI", 10),
    )

    # Frames & labels
    style.configure("TFrame",  background=PALETTE["bg"])
    style.configure("TLabel",  background=PALETTE["bg"], foreground=PALETTE["fg"])

    # Buttons
    style.configure("TButton",
        background=PALETTE["accent"],
        foreground=PALETTE["bg"],
        font=("Segoe UI", 10, "bold"),
        borderwidth=0,
        focusthickness=0,
        padding=6,
    )
    style.map("TButton",
        background=[("active", PALETTE["hover"]), ("disabled", PALETTE["disabled"])],
        foreground=[("disabled", PALETTE["muted"])],
    )

    # Checkbuttons (clearer checked/unchecked contrast)
    style.configure("TCheckbutton",
        background=PALETTE["bg"],
        foreground=PALETTE["fg"],
        font=("Segoe UI", 9, "bold"),
        padding=(6, 3),
        indicatorcolor=PALETTE["surface"],
        indicatormargin=(2, 2, 6, 2),
    )
    style.map("TCheckbutton",
        foreground=[
            ("selected", PALETTE["green"]),
            ("!selected", PALETTE["muted"]),
            ("disabled", PALETTE["disabled"]),
        ],
        indicatorcolor=[
            ("selected", PALETTE["green"]),
            ("!selected", PALETTE["surface"]),
        ],
        background=[("active", PALETTE["bg"])],
    )

    # Entry / Combobox
    style.configure("TEntry",
        fieldbackground=PALETTE["surface"],
        foreground=PALETTE["fg"],
        insertcolor=PALETTE["fg"],
        borderwidth=1,
    )
    style.configure("TCombobox",
        fieldbackground=PALETTE["surface"],
        foreground=PALETTE["fg"],
        selectbackground=PALETTE["select"],
    )
    style.map("TCombobox",
        fieldbackground=[("readonly", PALETTE["surface"])],
        foreground=[("readonly", PALETTE["fg"])],
    )

    # Treeview
    style.configure("Treeview",
        background=PALETTE["row_even"],
        foreground=PALETTE["fg"],
        fieldbackground=PALETTE["row_even"],
        rowheight=26,
        font=("Segoe UI", 10),
    )
    style.configure("Treeview.Heading",
        background=PALETTE["heading"],
        foreground=PALETTE["accent"],
        font=("Segoe UI", 10, "bold"),
    )
    style.map("Treeview",
        background=[("selected", PALETTE["select"])],
        foreground=[("selected", PALETTE["fg"])],
    )

    # Scrollbar
    style.configure("TScrollbar",
        background=PALETTE["surface"],
        troughcolor=PALETTE["bg"],
        arrowcolor=PALETTE["muted"],
    )

    return PALETTE
