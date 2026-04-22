"""
main.py
-------
Entry point for the Login Credential Checker application.
Run with:
    python src/main.py
"""

import sys
import os

# Ensure the project root is on sys.path so 'src.*' imports work
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.gui.app import App


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
