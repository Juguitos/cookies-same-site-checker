#!/usr/bin/env python3
"""Local backend for Cookie SameSite Checker. Run this, then open index.html locally."""

from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
from http.cookies import SimpleCookie
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)
CORS(app)

UA = "Mozilla/5.0 (Pentest Evidence Collector; Cookie SameSite Checker)"
SUSPICIOUS_TOKENS = ("session", "auth", "token", "sid", "sess", "jwt", "login")


def _fetch(url, timeout=10):
    return requests.get(
        url, timeout=timeout, allow_redirects=True,
        headers={"User-Agent": UA}
    )


def _get_set_cookie_headers(resp):
    try:
        hdrs = resp.raw.headers.getlist("Set-Cookie")
        if hdrs:
            return hdrs
    except Exception:
        pass
    one = resp.headers.get("Set-Cookie")
    return [one] if one else []


def _parse_cookie(header_value):
    c = SimpleCookie()
    try:
        c.load(header_value)
    except Exception:
        return None
    if not c:
        return None
    name = next(iter(c.keys()))
    morsel = c[name]
    samesite = morsel["samesite"] or None
    if samesite:
        samesite = samesite.strip().capitalize()
    return {
        "name": name,
        "samesite": samesite,
        "secure": bool(morsel["secure"]),
        "httponly": bool(morsel["httponly"]),
        "domain": morsel["domain"] or "",
        "path": morsel["path"] or "/",
    }


def _classify_risk(cookie):
    samesite = cookie["samesite"]
    secure = cookie["secure"]
    httponly = cookie["httponly"]
    name = cookie["name"].lower()
    sensitive = any(t in name for t in SUSPICIOUS_TOKENS)

    if samesite is None:
        return "ALTO", "Sin SameSite"
    if samesite == "None" and not secure:
        return "ALTO", "SameSite=None sin Secure"
    if samesite == "None" and secure:
        if sensitive and not httponly:
            return "ALTO", "SameSite=None y sin HttpOnly en cookie sensible"
        return "MEDIO", "SameSite=None con Secure"
    if samesite in ("Lax", "Strict"):
        if sensitive and not httponly:
            return "MEDIO", "Cookie sensible sin HttpOnly"
        return "INFORMATIVO", f"SameSite={samesite}"
    return "INFORMATIVO", f"SameSite={samesite}"


def _check_domain(domain):
    last_exc: Exception = Exception("Error desconocido")
    for url in [f"https://{domain}", f"http://{domain}"]:
        try:
            resp = _fetch(url)
            cookies = []
            for sc in _get_set_cookie_headers(resp):
                c = _parse_cookie(sc)
                if c:
                    risk, issue = _classify_risk(c)
                    c.update({"risk": risk, "issue": issue})
                    cookies.append(c)
            return {"domain": domain, "cookies": cookies, "error": None}
        except Exception as e:
            last_exc = e
    return {"domain": domain, "cookies": [], "error": str(last_exc)}


@app.route("/check")
def check():
    raw = request.args.get("domains", "")
    domains = list({d.strip().lower() for d in raw.split(",") if d.strip()})
    if not domains:
        return jsonify({"error": "No domains provided"}), 400

    results = []
    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = {ex.submit(_check_domain, d): d for d in domains}
        for fut in as_completed(futs):
            results.append(fut.result())

    return jsonify(results)


if __name__ == "__main__":
    print("Backend running on http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
