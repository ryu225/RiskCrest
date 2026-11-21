"""Capture real, current RiskCrest pages using temporary demo data only.

Usage: python -m scripts.capture_screenshots
Install Playwright and its Chromium browser first. Nothing is hosted publicly.
"""
from __future__ import annotations

import os
import socket
import ssl
import tempfile
import threading
import time
from pathlib import Path
from urllib.request import urlopen

import uvicorn
from playwright.sync_api import sync_playwright

from app.db import connect
from app.main import create_app
from app.security import PASSWORD_HASHER
from lab.main import create_lab
from scripts.create_dev_cert import create_certificate

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "screenshots"


def available_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for(url):
    context = ssl._create_unverified_context()
    for _ in range(90):
        try:
            with urlopen(url, timeout=2, context=context) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.25)
    raise RuntimeError("Local capture server failed: " + url)


def capture(page, name, url):
    response = page.goto(url, wait_until="networkidle", timeout=30000)
    if response is None or response.status != 200:
        raise RuntimeError("Cannot capture " + name)
    page.locator("main h1").first.wait_for()
    page.evaluate("() => document.fonts.ready.then(() => true)")
    page.screenshot(path=str(OUT / name), full_page=True, animations="disabled")
    print("Captured", name, flush=True)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="riskcrest-capture-") as temporary:
        root = Path(temporary)
        cert, key = create_certificate(root / "certs")
        secure_db, lab_db = root / "secure.sqlite3", root / "lab.sqlite3"
        secure = create_app(database=secure_db, keys_dir=root / "keys")
        with connect(secure_db) as db:
            for username, role, email in (
                ("demo_member", "user", "member@example.test"),
                ("demo_admin", "admin", "admin@example.test"),
            ):
                db.execute(
                    "INSERT INTO users (username, password_hash, role, email_encrypted) "
                    "VALUES (?, ?, ?, ?)",
                    (username, PASSWORD_HASHER.hash("ScreenshotOnly1!"), role,
                     secure.state.protection.encrypt_data(email)),
                )
            member = db.execute(
                "SELECT id FROM users WHERE username = ?", ("demo_member",)
            ).fetchone()["id"]
            for note in (
                "Review account permissions and session protection.",
                "Confirm SQL injection and XSS checks pass.",
            ):
                db.execute("INSERT INTO notes(user_id, content) VALUES (?, ?)",
                           (member, note))

        secure_port, lab_port = available_port(), available_port()
        while lab_port == secure_port:
            lab_port = available_port()
        secure_url = f"https://127.0.0.1:{secure_port}"
        lab_url = f"http://127.0.0.1:{lab_port}"
        servers = [
            uvicorn.Server(uvicorn.Config(
                secure, host="127.0.0.1", port=secure_port,
                ssl_certfile=str(cert), ssl_keyfile=str(key),
                log_level="error", access_log=False)),
            uvicorn.Server(uvicorn.Config(
                create_lab(database=lab_db), host="127.0.0.1", port=lab_port,
                log_level="error", access_log=False)),
        ]
        threads = [threading.Thread(target=s.run, daemon=True) for s in servers]
        for thread in threads:
            thread.start()
        try:
            wait_for(secure_url)
            wait_for(lab_url)
            with sync_playwright() as p:
                settings = {"headless": True, "args": ["--no-sandbox"]}
                if os.getenv("RISKCREST_BROWSER_EXECUTABLE"):
                    settings["executable_path"] = os.environ["RISKCREST_BROWSER_EXECUTABLE"]
                browser = p.chromium.launch(**settings)
                try:
                    desktop = browser.new_context(
                        viewport={"width": 1440, "height": 900},
                        device_scale_factor=1, ignore_https_errors=True)
                    page = desktop.new_page()
                    capture(page, "01-home.png", secure_url + "/")
                    capture(page, "02-registration.png", secure_url + "/register")
                    capture(page, "03-login.png", secure_url + "/login")
                    page.locator("#username").fill("demo_member")
                    page.locator("#password").fill("ScreenshotOnly1!")
                    page.locator('button[type="submit"]').first.click()
                    page.wait_for_url("**/dashboard")
                    capture(page, "04-dashboard.png", secure_url + "/dashboard")

                    admin_context = browser.new_context(
                        viewport={"width": 1440, "height": 900},
                        device_scale_factor=1, ignore_https_errors=True)
                    admin = admin_context.new_page()
                    admin.goto(secure_url + "/login", wait_until="networkidle")
                    admin.locator("#username").fill("demo_admin")
                    admin.locator("#password").fill("ScreenshotOnly1!")
                    admin.locator('button[type="submit"]').first.click()
                    admin.wait_for_url("**/dashboard")
                    capture(admin, "05-administration.png", secure_url + "/admin")

                    mobile = browser.new_context(
                        viewport={"width": 390, "height": 844},
                        device_scale_factor=1, is_mobile=True, has_touch=True,
                        ignore_https_errors=True)
                    capture(mobile.new_page(), "06-mobile-home.png", secure_url + "/")
                    capture(desktop.new_page(), "07-vulnerable-lab-login.png",
                            lab_url + "/login")
                    desktop.close()
                    admin_context.close()
                    mobile.close()
                finally:
                    browser.close()
        finally:
            for server in servers:
                server.should_exit = True
            for thread in threads:
                thread.join(timeout=10)
    files = sorted(OUT.glob("*.png"))
    if len(files) != 7:
        raise RuntimeError(f"Expected seven screenshots, found {len(files)}")
    print("Success: seven latest-version screenshots captured", flush=True)


if __name__ == "__main__":
    main()
