"""
Runner script for ShieldGuard AI Spam & Scam Detection System.
Launches the FastAPI backend and web dashboard.
"""

import sys
import webbrowser
import time
import threading

# Ensure UTF-8 output encoding on Windows consoles
if sys.stdout.encoding != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

import uvicorn

def open_browser():
    time.sleep(1.5)
    print("\n[+] Opening Web Dashboard at http://127.0.0.1:8000 ...")
    webbrowser.open("http://127.0.0.1:8000")

if __name__ == "__main__":
    print("=" * 60)
    print("   [#] Starting ShieldGuard AI - Spam & Scam Detection System")
    print("   [#] Dashboard URL : http://127.0.0.1:8000")
    print("   [#] API Swagger   : http://127.0.0.1:8000/docs")
    print("=" * 60)

    # Launch browser automatically in a separate thread
    threading.Thread(target=open_browser, daemon=True).start()

    # Start Uvicorn Server
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
