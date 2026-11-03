import os
import sys

# Add project root directory to sys.path so app and project assets can be found
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import app

# Vercel Serverless Function entry point
# Exposes 'app' WSGI callable for the Vercel Python runtime
