"""Vercel ASGI entry point for the Blast Radius API."""

from pathlib import Path
import sys

# Make the repository root explicit for the Vercel Python runtime, so the
# backend package is available during cold starts as well as local execution.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.main import app
