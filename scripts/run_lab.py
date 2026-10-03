#!/usr/bin/env python3
"""
Direct script to launch the KRYPT vulnerable training laboratory.
"""

import uvicorn
from lab.app import app

if __name__ == "__main__":
    print("[*] Launching KRYPT Training Laboratory on http://127.0.0.1:8888 ...")
    uvicorn.run(app, host="127.0.0.1", port=8888, log_level="info")
