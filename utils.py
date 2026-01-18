# utils.py
import os, re

def sanitize_filename(name: str) -> str:
    return re.sub(r'[^a-zA-Z0-9_-]', '_', name)

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)
