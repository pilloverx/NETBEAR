# main.py
"""
NetBear Security Framework - Main Entry Point
Unified CLI for web crawling (NetBear) and NextCloud assessment
"""

import sys
import os

# Add current directory to path for local imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from interactive_cli import main

if __name__ == "__main__":
    main()
