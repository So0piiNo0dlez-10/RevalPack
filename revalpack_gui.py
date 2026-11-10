#!/usr/bin/env python3
"""
RevalPack GUI — Security Revalidation Scanner
=========================================================
Author : Suprit Mangde
Author: Suprit Mangde | Offensive Security
Version: 4.0 (FastVulnVerify Edition)

Standalone GUI application. Runs scans directly inside the app.
Build to EXE:  pyinstaller --onefile --windowed --name RevalPack revalpack_gui.py
"""

import os, re, sys, ssl, csv, json, socket, datetime, threading, subprocess, queue
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import urllib3, requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Output directory ───────────────────────────────────────────────────────
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(sys.executable
             if getattr(sys, 'frozen', False) else __file__)), "revalpack_output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── Colours  (Light Blue theme) ───────────────────────────────────────────
DARK    = "#0d2340"   # lighter navy (was #060e1a)
DARK2   = "#1a3a6e"   # medium blue panel (was #0b1829)
SIDEBAR = "#0a1e3d"   # sidebar slightly lighter (was #04080f)
GREEN   = "#1976d2"   # primary accent — medium blue (was #1565c0)
GREEN_L = "#90caf9"   # very light blue for safe / highlights (was #64b5f6)
CARD    = "#1a3560"   # card background (was #0d1f38)
LINE    = "#2a5090"   # border lines (was #1a3a60)
TEXT    = "#ddeeff"   # near-white text (was #cce4ff)
MUTED   = "#6a90c0"   # muted text, lighter (was #4a6a99)
RED     = "#ef5350"
AMBER   = "#ffa726"
BLUE    = "#64b5f6"   # info colour, lighter (was #42a5f5)
WHITE   = "#f0f7ff"   # near white (was #e8f4ff)
MONO    = ("Consolas", 10)

# ══════════════════════════════════════════════════════════════════════════
#  SCAN ENGINE  (same logic as revalpack.py, all inline)
# ══════════════════════════════════════════════════════════════════════════

def normalise_url(target, scheme="http"):
    t = target.strip()
    if not t: return ""
    return t if "://" in t else f"{scheme}://{t}"

def hostname_from(target):
    try: return urlparse(normalise_url(target)).hostname or target
    except: return target

SECURITY_HEADERS = [
    "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options",
    "Content-Security-Policy", "Referrer-Policy", "Permissions-Policy", "X-XSS-Protection",
]
DANGEROUS_METHODS = {"PUT","DELETE","TRACE","CONNECT","PATCH","MOVE","COPY","PROPFIND"}
_VERSION_RX = re.compile(r"\d+\.\d+", re.IGNORECASE)
_PRODUCT_RX = re.compile(
    r"(Apache|nginx|IIS|Tomcat|LiteSpeed|lighttpd|Kestrel|Gunicorn|PHP|ASP\.NET|Express|Jetty)",
    re.IGNORECASE)
WEAK_SSH_ALGOS = {
    "aes128-cbc","3des-cbc","rijndael-cbc@lysator.liu.se","aes256-cbc","aes192-cbc",
    "blowfish-cbc","cast128-cbc","diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group1-sha1","gss-gex-sha1-","gss-group1-sha1-","gss-group14-sha1-",
    "rsa1024-sha1","hmac-sha1","hmac-sha1-96",
}
TOMCAT_PATTERNS = [re.compile(r, re.I) for r in
    ["tomcat","apache-coyote","apache tomcat","coyote/1\\."]]
_TLS_VERSIONS = {
    "TLSv1.0": getattr(ssl.TLSVersion,"TLSv1",   None),
    "TLSv1.1": getattr(ssl.TLSVersion,"TLSv1_1", None),
    "TLSv1.2": getattr(ssl.TLSVersion,"TLSv1_2", None),
    "TLSv1.3": getattr(ssl.TLSVersion,"TLSv1_3", None),
}

def _req(url, method="GET", timeout=10, verify=False, **kw):
    fn = {"GET":requests.get,"HEAD":requests.head,"OPTIONS":requests.options}.get(method, requests.get)
    return fn(url, timeout=timeout, verify=verify, **kw)

class ScanEngine:
    def __init__(self, emit):
        self.emit = emit   # emit(status, target, detail) → "VULNERABLE"|"SAFE"|"WARNING"|"INFO"|"ERROR"
        self.stop_flag = lambda: False   # replaced by GUI to signal cancellation

    # ── helpers ─────────────────────────────────────────────────────────
    def _v(self, tgt, msg): self.emit("VULNERABLE", tgt, msg)
    def _s(self, tgt, msg): self.emit("SAFE",       tgt, msg)
    def _w(self, tgt, msg): self.emit("WARNING",    tgt, msg)
    def _i(self, tgt, msg): self.emit("INFO",       tgt, msg)
    def _e(self, tgt, msg): self.emit("ERROR",      tgt, msg)
    def _stopped(self):     return self.stop_flag()

    def _get(self, url, scheme="https", **kw):
        for s in (scheme, "http" if scheme=="https" else "https"):
            u = normalise_url(url, s)
            try:
                r = requests.get(u, timeout=10, verify=False, allow_redirects=True, **kw)
                if r.status_code < 500: return r, u
            except: pass
        return None, url

    # ── 1. TLS Version ──────────────────────────────────────────────────
    def tls_version(self, targets, port):
        WEAK = {"TLSv1.0","TLSv1.1","SSLv2","SSLv3"}
        for raw in targets:
            host = hostname_from(raw)
            found = set()
            # Try nmap first
            try:
                r = subprocess.run(["nmap","--script","ssl-enum-ciphers","-Pn","-p",str(port),host],
                    capture_output=True,text=True,timeout=60)
                found = set(re.findall(r"^\|\s+(SSLv\d+|TLSv1(?:\.\d)?):",r.stdout,re.M))
            except FileNotFoundError:
                pass
            except subprocess.TimeoutExpired:
                pass
            # Python fallback
            if not found:
                for vn, vc in _TLS_VERSIONS.items():
                    if vc is None: continue
                    try:
                        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                        ctx.minimum_version = vc; ctx.maximum_version = vc
                        if vn in ("TLSv1.0","TLSv1.1"):
                            try: ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
                            except: pass
                        with socket.create_connection((host,port),timeout=5) as sock:
                            with ctx.wrap_socket(sock,server_hostname=host): found.add(vn)
                    except: pass
            # Try SSLv3 via socket (Python 3.10+ dropped OP_NO_SSLv3 but we attempt anyway)
            try:
                ctx3 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx3.check_hostname = False; ctx3.verify_mode = ssl.CERT_NONE
                ctx3.options |= getattr(ssl, "OP_NO_TLSv1_3", 0)
                ctx3.options |= getattr(ssl, "OP_NO_TLSv1_2", 0)
                ctx3.options |= getattr(ssl, "OP_NO_TLSv1_1", 0)
                ctx3.options |= getattr(ssl, "OP_NO_TLSv1",   0)
                try: ctx3.set_ciphers("DEFAULT:@SECLEVEL=0")
                except: pass
                with socket.create_connection((host,port),timeout=5) as sock:
                    with ctx3.wrap_socket(sock,server_hostname=host): found.add("SSLv3")
            except: pass
            weak = found & WEAK
            tgt = f"{host}:{port}"
            if weak:    self._v(tgt, f"VULNERABLE — Supports deprecated protocol(s): {', '.join(sorted(weak))}")
            elif found: self._s(tgt, f"Only {', '.join(sorted(found))} (OK)")
            else:       self._i(tgt, "No SSL/TLS detected or port closed")

    # ── 2. SSL Complete ──────────────────────────────────────────────────
    def ssl_complete(self, targets, port):
        WEAK_MAP = {
            "SWEET32 (3DES)":   r"(3des|des[-_]cbc|des_ede)",
            "RC4":              r"\brc4\b",
            "EXPORT/FREAK":     r"(export|rsa_export|des40|exp[-_])",
            "NULL Cipher":      r"\bnull\b",
            "ANON Cipher":      r"\banon\b",
            "MD5 Hash":         r"\bmd5\b",
            "CBC/BEAST":        r"\bcbc\b",
            "Weak RSA":         r"rsa.{0,10}(512|768|1024)",
        }
        for raw in targets:
            host = hostname_from(raw)
            try:
                r = subprocess.run(["nmap","-Pn","--script","ssl-enum-ciphers","-p",str(port),host],
                    capture_output=True,text=True,timeout=120)
                out = r.stdout
            except FileNotFoundError:
                self._e(f"{host}:{port}", "nmap not installed"); continue
            except subprocess.TimeoutExpired:
                self._e(f"{host}:{port}", "nmap timed out"); continue
            ciphers = re.findall(r"([A-Z0-9_-]+WITH[A-Z0-9_-]+)",out,re.I)
            weak = []
            seen = set()
            for c in ciphers:
                for name, pat in WEAK_MAP.items():
                    key = f"{c}|{name}"
                    if key not in seen and re.search(pat,c,re.I):
                        seen.add(key); weak.append(f"{c} → {name}")
            tgt = f"{host}:{port}"
            if weak: self._v(tgt, f"{len(weak)} weak cipher(s): {'; '.join(weak[:4])}{'…' if len(weak)>4 else ''}")
            else:    self._s(tgt, "No weak cipher patterns found")

    # ── 2b. Vulnerable Ciphers — testssl-style checks ─────────────────────
    def ssl_vuln_ciphers(self, targets, port):
        """
        testssl.sh-style vulnerability scanner (pure Python, no nmap/testssl required).
        Checks: BEAST, BREACH, CRIME, LUCKY13, POODLE, SWEET32/3DES, RC4, FREAK,
                LOGJAM (DHE export), DROWN (SSLv2), NULL/ANON ciphers.
        Strategy:
          1. Connect normally → get negotiated cipher + TLS version
          2. Try cipher-group handshakes (CBC, RC4, 3DES, EXPORT, NULL) using
             grouped cipher strings so ONE connection reveals if group is accepted.
          3. HTTP-level checks for BREACH (gzip on HTTPS) and CRIME (HTTP compression header).
        """

        def _connect(host, p, ciphers=None, min_ver=None, max_ver=None, timeout=6):
            """Attempt TLS handshake; return (cipher_name, tls_version) or None."""
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                if ciphers:
                    try: ctx.set_ciphers(ciphers)
                    except ssl.SSLError: return None
                if min_ver:
                    try: ctx.minimum_version = min_ver
                    except Exception: return None
                if max_ver:
                    try: ctx.maximum_version = max_ver
                    except Exception: pass
                with socket.create_connection((host, p), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ss:
                        return ss.cipher()[0], ss.version()
            except Exception:
                return None

        def _check_breach(host, p):
            """BREACH: HTTPS serving compressed HTML/JSON."""
            try:
                scheme = "https"
                url = f"{scheme}://{host}" + (f":{p}" if p != 443 else "")
                r = requests.get(url, timeout=10, verify=False,
                                 headers={"Accept-Encoding": "gzip, deflate, br"},
                                 allow_redirects=True)
                enc = r.headers.get("Content-Encoding", "")
                ct  = r.headers.get("Content-Type", "")
                is_compressed = bool(enc and any(x in enc.lower()
                    for x in ("gzip","deflate","br","compress","zstd")))
                is_dynamic = any(x in ct.lower()
                    for x in ("text/html","application/json","text/javascript"))
                if is_compressed and is_dynamic:
                    return "VULNERABLE", f"gzip/HTTP compression on HTTPS+HTML/JSON ({enc}) — potentially NOT ok (same as testssl BREACH warning)"
                elif is_compressed:
                    return "WARNING", f"HTTP compression ({enc}) on HTTPS but Content-Type={ct.split(';')[0]} (lower risk)"
                return "SAFE", "No HTTP compression on HTTPS"
            except Exception as e:
                return "ERROR", str(e)

        def _check_crime(host, p):
            """CRIME: TLS-level compression (rare, mostly historical)."""
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                with socket.create_connection((host, p), timeout=6) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ss:
                        comp = ss.compression()
                        if comp and comp != "NULL":
                            return "VULNERABLE", f"TLS compression enabled: {comp} (CRIME CVE-2012-4929)"
                return "SAFE", "No TLS compression"
            except Exception as e:
                return "ERROR", str(e)

        def _try_tls10_cbc(host, p):
            """BEAST: negotiate CBC cipher over TLS 1.0 specifically."""
            tls10 = getattr(ssl.TLSVersion, "TLSv1", None)
            if tls10 is None:
                return None  # Python build doesn't support TLS 1.0
            result = _connect(host, p,
                ciphers="AES128-SHA:AES256-SHA:DES-CBC3-SHA:RC4-SHA:RC4-MD5:DEFAULT:@SECLEVEL=0",
                min_ver=tls10, max_ver=tls10)
            return result  # (cipher, "TLSv1") or None

        for raw in targets:
            host = hostname_from(raw)
            tgt  = f"{host}:{port}"

            # ── Step 1: Basic connectivity check ──────────────────────
            baseline = _connect(host, port)
            if baseline is None:
                # Try with lower security level
                baseline = _connect(host, port, ciphers="DEFAULT:@SECLEVEL=0")
            if baseline is None:
                self._e(tgt, "Cannot connect — TLS handshake failed (port closed or not TLS)"); continue

            neg_cipher, neg_ver = baseline
            self._i(tgt, f"Connected: {neg_ver} / {neg_cipher}")

            vulns   = []
            warns   = []
            safes   = []

            # ── BEAST (CVE-2011-3389): TLS 1.0 + CBC ──────────────────
            beast_result = _try_tls10_cbc(host, port)
            if beast_result:
                bc, bv = beast_result
                if bv == "TLSv1" and "CBC" in bc.upper() or re.search(r"AES|DES|RC4", bc, re.I):
                    vulns.append(f"BEAST (CVE-2011-3389): TLS 1.0 accepted with cipher {bc}")
                else:
                    safes.append(f"BEAST: TLS 1.0 responded but cipher={bc} (check manually)")
            else:
                safes.append("BEAST: No TLS 1.0 CBC negotiation possible")

            # ── BREACH (CVE-2013-3587): HTTP gzip on HTTPS ─────────────
            breach_status, breach_msg = _check_breach(host, port)
            if breach_status == "VULNERABLE":
                vulns.append(f"BREACH (CVE-2013-3587): {breach_msg}")
            elif breach_status == "WARNING":
                warns.append(f"BREACH: {breach_msg}")
            elif breach_status == "SAFE":
                safes.append(f"BREACH: {breach_msg}")
            else:
                warns.append(f"BREACH check error: {breach_msg}")

            # ── CRIME (CVE-2012-4929): TLS compression ─────────────────
            crime_status, crime_msg = _check_crime(host, port)
            if crime_status == "VULNERABLE":
                vulns.append(crime_msg)
            else:
                safes.append(f"CRIME: {crime_msg}")

            # ── LUCKY13 (CVE-2013-0169): CBC cipher over any TLS ───────
            # Any CBC cipher suite in use = potentially vulnerable to Lucky13
            cbc_result = _connect(host, port,
                ciphers="AES128-SHA:AES256-SHA:AES128-SHA256:AES256-SHA256:DES-CBC3-SHA:DEFAULT:@SECLEVEL=0")
            if cbc_result:
                cc, cv = cbc_result
                if "SHA" in cc and not "GCM" in cc and not "CCM" in cc:
                    warns.append(f"LUCKY13 (CVE-2013-0169): CBC cipher accepted — {cc} over {cv} (uses obsolete CBC block chaining)")
                else:
                    safes.append(f"LUCKY13: Negotiated {cc} (non-CBC or GCM — OK)")
            else:
                safes.append("LUCKY13: No CBC ciphers accepted")

            # ── POODLE SSL (CVE-2014-3566): SSLv3 support ──────────────
            sslv3_const = getattr(ssl.TLSVersion, "SSLv3", None)
            poodle_found = False
            if sslv3_const:
                r3 = _connect(host, port, min_ver=sslv3_const, max_ver=sslv3_const,
                              ciphers="DEFAULT:@SECLEVEL=0")
                if r3:
                    vulns.append(f"POODLE/SSLv3 (CVE-2014-3566): SSLv3 accepted — {r3[0]}")
                    poodle_found = True
            if not poodle_found:
                safes.append("POODLE: No SSLv3 support")

            # ── SWEET32 / 3DES (CVE-2016-2183) ────────────────────────
            des3_result = _connect(host, port,
                ciphers="DES-CBC3-SHA:DES-CBC3-MD5:EDH-RSA-DES-CBC3-SHA:DEFAULT:@SECLEVEL=0")
            if des3_result:
                vulns.append(f"SWEET32/3DES (CVE-2016-2183): 3DES cipher accepted — {des3_result[0]}")
            else:
                safes.append("SWEET32: No 3DES ciphers accepted")

            # ── RC4 (CVE-2013-2566 / CVE-2015-2808) ───────────────────
            rc4_result = _connect(host, port,
                ciphers="RC4-SHA:RC4-MD5:RC4:@SECLEVEL=0")
            if rc4_result:
                vulns.append(f"RC4 (CVE-2013-2566): RC4 cipher accepted — {rc4_result[0]}")
            else:
                safes.append("RC4: No RC4 ciphers accepted")

            # ── FREAK (CVE-2015-0204): EXPORT ciphers ─────────────────
            freak_result = _connect(host, port,
                ciphers="EXP-RC4-MD5:EXP-RC2-CBC-MD5:EXP-DES-CBC-SHA:EXPORT:@SECLEVEL=0")
            if freak_result:
                vulns.append(f"FREAK (CVE-2015-0204): EXPORT cipher accepted — {freak_result[0]}")
            else:
                safes.append("FREAK: No EXPORT ciphers accepted")

            # ── LOGJAM (CVE-2015-4000): DHE EXPORT / weak DH ──────────
            logjam_result = _connect(host, port,
                ciphers="EXP-EDH-RSA-DES-CBC-SHA:EXP-EDH-DSS-DES-CBC-SHA:DHE-RSA-EXPORT:@SECLEVEL=0")
            if logjam_result:
                vulns.append(f"LOGJAM (CVE-2015-4000): DHE EXPORT cipher — {logjam_result[0]}")
            else:
                safes.append("LOGJAM: No DHE EXPORT ciphers")

            # ── NULL / ANON ciphers ────────────────────────────────────
            null_result = _connect(host, port, ciphers="NULL:aNULL:eNULL:@SECLEVEL=0")
            if null_result:
                vulns.append(f"NULL/ANON cipher accepted — {null_result[0]} (no encryption/auth)")
            else:
                safes.append("NULL/ANON: Not accepted")

            # ── TLS 1.0 / 1.1 (weak protocols) ────────────────────────
            for vname, vconst in [("TLS 1.0", getattr(ssl.TLSVersion,"TLSv1",None)),
                                   ("TLS 1.1", getattr(ssl.TLSVersion,"TLSv1_1",None))]:
                if vconst is None: continue
                r = _connect(host, port, min_ver=vconst, max_ver=vconst,
                             ciphers="DEFAULT:@SECLEVEL=0")
                if r:
                    vulns.append(f"{vname} supported (deprecated protocol — CVE-2011-3389 attack surface)")

            # ── Emit results ───────────────────────────────────────────
            for v in vulns:
                self._v(tgt, v)
            for w in warns:
                self._w(tgt, w)
            for s in safes:
                self._s(tgt, s)

            # Summary line
            if vulns:
                self._v(tgt, f"SUMMARY: {len(vulns)} VULNERABLE, {len(warns)} WARNING, {len(safes)} SAFE checks")
            else:
                self._s(tgt, f"SUMMARY: 0 vulnerabilities found — {len(safes)} checks passed")

    # ── 3. SWEET32 ───────────────────────────────────────────────────────
    def sweet32(self, targets, port):
        for raw in targets:
            host = hostname_from(raw)
            try:
                r = subprocess.run(["nmap","--script","ssl-enum-ciphers","-p",str(port),host,"-Pn"],
                    capture_output=True,text=True,timeout=60)
                out = r.stdout.upper()
            except Exception as e:
                self._e(f"{host}:{port}", str(e)); continue
            tgt = f"{host}:{port}"
            if "3DES" in out or "DES-CBC" in out:
                self._v(tgt, "3DES/SWEET32 cipher detected (CVE-2016-2183)")
            else:
                self._s(tgt, "No 3DES ciphers found")

    # ── 4. Missing Headers ───────────────────────────────────────────────
    def missing_headers(self, targets, port):
        for raw in targets:
            resp, used = self._get(raw, "https" if port==443 else "http")
            if resp is None:
                self._e(raw, "Could not connect"); continue
            present = {k.lower() for k in resp.headers}
            missing = [h for h in SECURITY_HEADERS if h.lower() not in present]
            if missing: self._v(used, f"Missing ({len(missing)}): {', '.join(missing)}")
            else:       self._s(used, f"All {len(SECURITY_HEADERS)} security headers present")

    # ── 5. HSTS ─────────────────────────────────────────────────────────
    def hsts(self, targets, port):
        MIN = 31536000
        for raw in targets:
            host = hostname_from(raw)
            url = f"https://{host}" + (f":{port}" if port!=443 else "")
            try:
                resp = requests.get(url,timeout=10,verify=False,allow_redirects=True)
                hsts = resp.headers.get("Strict-Transport-Security","")
                if not hsts:
                    self._v(host, "HSTS header MISSING"); continue
                m = re.search(r"max-age\s*=\s*(\d+)",hsts,re.I)
                age = int(m.group(1)) if m else 0
                sub = "includesubdomains" in hsts.lower()
                if age < MIN:    self._v(host, f"HSTS max-age too low: {age}s (need ≥ {MIN})")
                elif not sub:    self._w(host, f"HSTS present (max-age={age}) but includeSubDomains missing")
                else:            self._s(host, f"HSTS OK (max-age={age}, includeSubDomains)")
            except Exception as e:
                self._e(host, str(e))

    # ── 6. Clickjacking ──────────────────────────────────────────────────
    def clickjacking(self, targets, port):
        for raw in targets:
            resp, used = self._get(raw, "https")
            if resp is None:
                self._e(raw, "Could not connect"); continue
            xfo = resp.headers.get("X-Frame-Options","").upper().strip()
            csp = resp.headers.get("Content-Security-Policy","")
            xfo_ok = xfo in ("DENY","SAMEORIGIN")
            csp_ok = "frame-ancestors" in csp.lower()
            if xfo_ok or csp_ok:
                parts = []
                if xfo_ok: parts.append(f"X-Frame-Options: {xfo}")
                if csp_ok: parts.append("CSP frame-ancestors present")
                self._s(used, "; ".join(parts))
            else:
                miss = []
                if not xfo_ok: miss.append("X-Frame-Options MISSING" if not xfo else f"X-Frame-Options invalid ({xfo})")
                if not csp_ok: miss.append("CSP frame-ancestors MISSING")
                self._v(used, "; ".join(miss))

    # ── 7/8. Header Analyser ─────────────────────────────────────────────
    def header_analyser(self, targets, port, verify_ssl=True):
        for raw in targets:
            url = normalise_url(raw, "https" if port==443 else "http")
            try:
                resp = requests.get(url,timeout=8,verify=verify_ssl,allow_redirects=True)
                findings = []
                for h in ("Server","X-Powered-By","X-AspNet-Version","X-AspNetMvc-Version"):
                    v = resp.headers.get(h,"")
                    if v and _VERSION_RX.search(v): findings.append(f"{h}: {v} [VERSION]")
                    elif v and _PRODUCT_RX.search(v): findings.append(f"{h}: {v} [product]")
                if any("[VERSION]" in f for f in findings): self._v(url, " | ".join(findings))
                elif findings: self._w(url, " | ".join(findings))
                else:          self._s(url, "No version info disclosed")
            except Exception as e:
                self._e(url, str(e))

    def header_analyser_ssl(self, targets, port):
        self.header_analyser(targets, port, verify_ssl=False)

    # ── 9. Basic Auth ─────────────────────────────────────────────────────
    def basic_auth(self, targets, port):
        PATHS = ["/","/login","/admin","/wp-admin","/api","/secure","/dashboard","/management"]
        for raw in targets:
            host = hostname_from(raw)
            found = []
            for scheme in ("https","http"):
                base = f"{scheme}://{host}"
                ok = False
                for path in PATHS:
                    try:
                        r = requests.get(base+path,timeout=6,verify=False,allow_redirects=False)
                        ok = True
                        auth = r.headers.get("WWW-Authenticate","")
                        if r.status_code==401 and "basic" in auth.lower():
                            m = re.search(r'realm=["\']?([^"\',]+)',auth,re.I)
                            found.append(f"{path} (realm: {m.group(1) if m else '?'})")
                    except: pass
                if ok: break
            if found: self._v(host, f"Basic Auth on {len(found)} path(s): {', '.join(found)}")
            else:     self._s(host, "Basic Authentication not detected")

    # ── 10. HTTP OPTIONS ──────────────────────────────────────────────────
    def options_method(self, targets, port):
        for raw in targets:
            url = normalise_url(raw, "https" if port==443 else "http")
            try:
                resp = requests.options(url,timeout=8,verify=False,allow_redirects=False)
                allow = resp.headers.get("Allow","") or resp.headers.get("Public","")
                methods = {m.strip().upper() for m in allow.split(",")} if allow else set()
                try:
                    tr = requests.request("TRACE",url,timeout=6,verify=False)
                    if tr.status_code==200: methods.add("TRACE")
                except: pass
                bad = methods & DANGEROUS_METHODS
                if bad:    self._v(url, f"Dangerous methods: {', '.join(sorted(bad))} | Allow: {allow or 'N/A'}")
                elif methods: self._s(url, f"No dangerous methods; allowed: {allow}")
                else:      self._i(url, f"No Allow header (status {resp.status_code})")
            except Exception as e:
                self._e(url, str(e))

    # ── 11. ASP.NET Debug ─────────────────────────────────────────────────
    def asp_debug(self, targets, port):
        INDICATORS = ["Stack Trace","Server Error","Compilation Error","System.Web","Source Error"]
        for raw in targets:
            url = normalise_url(raw, "http")
            try:
                r = subprocess.run(["curl","-sivk","-X","DEBUG",url,"-H","Command: run-debug","--max-time","10"],
                    capture_output=True,text=True,timeout=15)
                out = r.stdout+r.stderr
                if any(i in out for i in INDICATORS):
                    self._v(url, "ASP.NET debugging ENABLED")
                else:
                    self._s(url, "ASP.NET debugging not detected")
            except FileNotFoundError:
                self._e(url, "curl not found")
            except Exception as e:
                self._e(url, str(e))

    # ── 12/13. XML Policies ───────────────────────────────────────────────
    def _xml_policy(self, raw, filename):
        try:
            parsed = urlparse(raw if "://" in raw else "http://"+raw)
            url = f"{parsed.scheme}://{parsed.netloc}/{filename}"
            r = requests.get(url,timeout=10,verify=False)
            if r.status_code==200:
                if 'domain="*"' in r.text or "allow-access-from" in r.text.lower():
                    self._v(url, f"Found with permissive wildcard policy")
                else:
                    self._w(url, "Found — review content")
            elif r.status_code==404:
                self._s(url, "Not found (404)")
            else:
                self._i(url, f"HTTP {r.status_code}")
        except Exception as e:
            self._e(raw, str(e))

    def crossdomain(self, targets, port):
        for raw in targets: self._xml_policy(raw, "crossdomain.xml")

    def clientaccess(self, targets, port):
        for raw in targets: self._xml_policy(raw, "clientaccesspolicy.xml")

    # ── 14. Directory Listing ─────────────────────────────────────────────
    def dir_listing(self, targets, port):
        PATHS = ["/","/uploads","/upload","/backup","/backups","/logs","/log",
                 "/files","/data","/images","/assets","/static","/temp","/tmp",
                 "/old","/archive","/config","/configs"]
        SIGS = ["Index of /","Parent Directory","Directory listing for","[PARENTDIR]","<title>Index of"]
        for raw in targets:
            parsed = urlparse(normalise_url(raw,"http"))
            base = f"{parsed.scheme}://{parsed.netloc}"
            vuln_paths = []
            for path in PATHS:
                try:
                    r = requests.get(base+path,timeout=8,verify=False,allow_redirects=False)
                    if r.status_code==200 and any(s in r.text for s in SIGS):
                        vuln_paths.append(path)
                except: pass
            if vuln_paths: self._v(base, f"Directory listing on: {', '.join(vuln_paths)}")
            else:          self._s(base, f"No directory listing detected ({len(PATHS)} paths tested)")

    # ── 15/16. jQuery ─────────────────────────────────────────────────────
    def _jquery(self, raw, verify_ssl):
        url = normalise_url(raw, "https" if not verify_ssl else "http")
        try:
            r = requests.get(url,timeout=10,verify=verify_ssl)
            soup = BeautifulSoup(r.text,"html.parser")
            for tag in soup.find_all("script",src=True):
                src = tag["src"]
                if "jquery" in src.lower():
                    m = re.search(r"jquery[.-](\d+\.\d+\.\d+)",src,re.I)
                    if m:
                        ver = m.group(1)
                        parts = tuple(int(x) for x in ver.split("."))
                        if parts < (1,12,0): self._v(url, f"jQuery {ver} — outdated, known CVEs")
                        elif parts < (3,0,0): self._w(url, f"jQuery {ver} — check for CVEs")
                        else:                 self._s(url, f"jQuery {ver} — no known critical CVEs")
                        return
            self._i(url, "jQuery not detected in page HTML")
        except Exception as e:
            self._e(url, str(e))

    def jquery(self, targets, port):
        for raw in targets: self._jquery(raw, verify_ssl=True)

    def jquery_ssl(self, targets, port):
        for raw in targets: self._jquery(raw, verify_ssl=False)

    # ── 17. Server Version ────────────────────────────────────────────────
    def server_version(self, targets, port):
        HDRS = ["Server","X-Powered-By","X-AspNet-Version","X-AspNetMvc-Version","X-Generator"]
        for raw in targets:
            url = normalise_url(raw, "https" if port==443 else "http")
            try:
                resp = requests.get(url,timeout=8,verify=False,allow_redirects=True)
                findings = []
                for h in HDRS:
                    v = resp.headers.get(h,"")
                    if not v: continue
                    if _VERSION_RX.search(v): findings.append(f"{h}: {v} [VERSION]")
                    elif _PRODUCT_RX.search(v): findings.append(f"{h}: {v} [product]")
                if any("[VERSION]" in f for f in findings): self._v(url, " | ".join(findings))
                elif findings: self._w(url, " | ".join(findings))
                else:          self._s(url, "No server version disclosed")
            except Exception as e:
                self._e(url, str(e))

    # ── 18. Unencrypted ───────────────────────────────────────────────────
    def unencrypted(self, targets, port):
        for raw in targets:
            host = hostname_from(raw)
            try:
                r = requests.get(f"http://{host}",timeout=8,verify=False,allow_redirects=False)
                if r.status_code in (301,302,307,308):
                    loc = r.headers.get("Location","")
                    if loc.startswith("https://"):
                        self._s(host, f"HTTP→HTTPS redirect ({r.status_code})")
                    else:
                        self._v(host, f"HTTP redirects to non-HTTPS: {loc}")
                elif r.status_code < 400:
                    self._v(host, f"HTTP accessible without redirect (status {r.status_code})")
                else:
                    self._i(host, f"HTTP returned {r.status_code}")
            except requests.ConnectionError:
                try:
                    requests.get(f"https://{host}",timeout=8,verify=True)
                    self._s(host, "HTTP closed; HTTPS available with valid cert")
                except Exception:
                    self._i(host, "HTTP port closed; HTTPS also unreachable")
            except Exception as e:
                self._e(host, str(e))

    # ── 19. SSH Weak ──────────────────────────────────────────────────────
    def ssh_weak(self, targets, port):
        for raw in targets:
            host = hostname_from(raw)
            try:
                r = subprocess.run(["nmap","-p",str(port),"--script","ssh2-enum-algos",host],
                    capture_output=True,text=True,timeout=60)
                found = [a for a in WEAK_SSH_ALGOS if a in r.stdout.lower()]
                tgt = f"{host}:{port}"
                if found: self._v(tgt, f"Weak SSH algorithms: {', '.join(found)}")
                else:     self._s(tgt, "No weak SSH algorithms detected")
            except FileNotFoundError:
                self._e(f"{host}:{port}", "nmap not installed")
            except Exception as e:
                self._e(f"{host}:{port}", str(e))

    # ── 20. SMB Signing ───────────────────────────────────────────────────
    def smb_signing(self, targets, port):
        for raw in targets:
            host = hostname_from(raw)
            try:
                r = subprocess.run(["nmap","--script","smb2-security-mode","-p",str(port),"-Pn",host],
                    capture_output=True,text=True,timeout=60)
                out = r.stdout
                tgt = f"{host}:{port}"
                if "Message signing enabled but not required" in out:
                    self._v(tgt, "SMB signing enabled but NOT REQUIRED (relay attack possible)")
                elif "Message signing enabled and required" in out:
                    self._s(tgt, "SMB signing required")
                elif "Message signing disabled" in out:
                    self._v(tgt, "SMB signing DISABLED")
                else:
                    self._i(tgt, "Could not determine SMB signing status")
            except FileNotFoundError:
                self._e(f"{host}:{port}", "nmap not installed")
            except Exception as e:
                self._e(f"{host}:{port}", str(e))

    # ── 21a. PHP Version Disclosure ──────────────────────────────────────
    def php_version(self, targets, port):
        """Detect PHP version disclosed in HTTP response headers."""
        import re as _re
        PHP_HEADERS = ["X-Powered-By", "X-PHP-Version", "Server"]
        PHP_RE = _re.compile(r'PHP[/ ]([\d.]+)', _re.IGNORECASE)
        for raw in targets:
            if self._stopped(): return
            host = hostname_from(raw)
            tgt = f"{host}:{port}"
            found = False
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}:{port}/"
                try:
                    r = requests.get(url, timeout=8, verify=False, allow_redirects=True)
                    all_headers = dict(r.headers)
                    for hdr in PHP_HEADERS:
                        val = all_headers.get(hdr, "") or all_headers.get(hdr.lower(), "")
                        m = PHP_RE.search(val)
                        if m:
                            ver = m.group(1)
                            self._v(tgt, f"PHP version disclosed in '{hdr}': PHP/{ver} — update and suppress version in php.ini")
                            found = True
                            break
                    if not found:
                        # Also scan body for common phpinfo() disclosure
                        body = r.text[:4000]
                        m2 = PHP_RE.search(body)
                        if m2:
                            self._w(tgt, f"PHP version found in page body: PHP/{m2.group(1)} — possible phpinfo() exposure")
                            found = True
                    break
                except Exception:
                    continue
            if not found:
                self._s(tgt, "No PHP version disclosed in headers or body")

    # ── 21b. Apache Server Version Disclosure ────────────────────────────
    def apache_version(self, targets, port):
        """Detect Apache version and OS detail in Server header (ServerTokens Full/OS)."""
        import re as _re
        APACHE_RE = _re.compile(r'Apache(?:/(\S+))?', _re.IGNORECASE)
        for raw in targets:
            if self._stopped(): return
            host = hostname_from(raw)
            tgt = f"{host}:{port}"
            found = False
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}:{port}/"
                try:
                    r = requests.get(url, timeout=8, verify=False, allow_redirects=True)
                    server = r.headers.get("Server", "") or r.headers.get("server", "")
                    m = APACHE_RE.search(server)
                    if m:
                        ver = m.group(1) or "(version hidden)"
                        full_banner = server.strip()
                        # Check for detailed disclosure (OS, modules)
                        detail_level = "minimal"
                        os_patterns = ["Ubuntu", "Debian", "CentOS", "Red Hat", "Win32", "Win64", "Fedora", "openSUSE"]
                        if any(os in full_banner for os in os_patterns):
                            detail_level = "FULL (OS + modules)"
                        elif "(" in full_banner:
                            detail_level = "detailed (modules listed)"
                        if detail_level != "minimal":
                            self._v(tgt, f"Apache version/OS disclosed: '{full_banner}' — set ServerTokens Prod in httpd.conf")
                        else:
                            self._w(tgt, f"Apache version disclosed: '{full_banner}' — set ServerTokens Prod to suppress version")
                        found = True
                    elif server:
                        self._i(tgt, f"Non-Apache server: '{server}'")
                        found = True
                    break
                except Exception:
                    continue
            if not found:
                self._i(tgt, "Could not reach target or no Server header returned")

    # ── 21c. SMB Null Session ─────────────────────────────────────────────
    def smb_null_session(self, targets, port):
        """Check if SMB null session (anonymous bind) is allowed — CVE classic / MS legacy."""
        import struct as _struct, socket as _sock
        def _smb_null_check(host, port):
            # Build SMB negotiate + Session Setup Andx with null user/pass
            # Netbios session request
            nb_hdr = b'\x00\x00\x00\x2f'  # type 0, length 0x2f
            nb_called = b'\x20' + b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'[:30] + b'\x00'
            nb_calling = b'\x20' + b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'[:30] + b'\x00'
            nb_msg = nb_hdr + nb_called[:32] + nb_calling[:32]

            # Minimal SMBv1 Negotiate
            smb_neg = (b'\xff\x53\x4d\x42' + b'\x72' + b'\x00\x00\x00\x00' +
                       b'\x08' + b'\x01\xc8' + b'\x00' * 12 +
                       b'\x00' + b'\x0c\x00' + b'\x02NTLM 0.12\x00')
            netbios_len = len(smb_neg)
            pkt = b'\x00' + netbios_len.to_bytes(3, 'big') + smb_neg

            with _sock.create_connection((host, port), timeout=8) as s:
                s.sendall(pkt)
                data = s.recv(1024)
                if len(data) < 8:
                    return None, "Short response"
                # SMBv1 response magic check
                if data[4:8] != b'\xff\x53\x4d\x42':
                    return None, "Not SMB response"

                # Session Setup AnDX — null credentials
                ss_null = (b'\xff\x53\x4d\x42' + b'\x73' + b'\x00\x00\x00\x00' +
                           b'\x08\x01\xc8\x00' + b'\x00' * 12 + b'\x0d' +
                           b'\xff\x00\x00\x00' + b'\xff\x03' + b'\x01\x00' +
                           b'\x00\x00' + b'\x00\x00\x00\x00' + b'\x00\x00' +
                           b'\x00\x00' + b'\x00\x00\x00\x00' + b'\x40\x00\x00\x00' +
                           b'\x1a\x00' + b'\x00' + b'\x00' + b'\x00\x00' + b'\x00\x00' +
                           b'W\x00i\x00n\x00d\x00o\x00w\x00s\x002\x000\x000\x000\x00\x00\x00' +
                           b'\x00\x00')
                sslen = len(ss_null)
                ss_pkt = b'\x00' + sslen.to_bytes(3, 'big') + ss_null
                s.sendall(ss_pkt)
                resp = s.recv(1024)
                if len(resp) < 9:
                    return False, "No session setup response"
                # NT_STATUS at offset 5-8 in SMB header (after 4-byte NetBIOS)
                nt_status = int.from_bytes(resp[9:13], 'little')
                if nt_status == 0x00000000:
                    return True, "Null session accepted (NT_STATUS_SUCCESS)"
                elif nt_status == 0xC000006D:
                    return False, "Null session rejected (STATUS_LOGON_FAILURE)"
                elif nt_status == 0xC0000022:
                    return False, "Null session rejected (ACCESS_DENIED)"
                else:
                    return False, f"NT_STATUS: 0x{nt_status:08X}"

        for raw in targets:
            if self._stopped(): return
            host = hostname_from(raw)
            tgt = f"{host}:{port}"
            try:
                allowed, detail = _smb_null_check(host, port)
                if allowed is True:
                    self._v(tgt, f"SMB Null Session ALLOWED — {detail}. Restrict anonymous access in Local Security Policy")
                elif allowed is False:
                    self._s(tgt, f"SMB Null Session blocked — {detail}")
                else:
                    self._i(tgt, f"SMB Null Session check inconclusive — {detail}")
            except ConnectionRefusedError:
                self._i(tgt, "Port 445 closed or filtered")
            except Exception as e:
                self._e(tgt, f"SMB null session check failed: {e}")

    # ── 21. Tomcat ────────────────────────────────────────────────────────
    def tomcat(self, targets, port):
        def is_tomcat(text): return any(rx.search(text) for rx in TOMCAT_PATTERNS)
        for raw in targets:
            host = hostname_from(raw)
            indicators = []
            try:
                r = subprocess.run(["nmap","-sV","-p","80,8080,8443,8009,8005","--script=http-server-header","-Pn",host],
                    capture_output=True,text=True,timeout=90)
                if is_tomcat(r.stdout): indicators.append("nmap service detection")
            except: pass
            for chk_port in (80,8080,8443):
                for scheme in ("https","http"):
                    url = f"{scheme}://{host}:{chk_port}"
                    try:
                        resp = requests.get(url+"/",timeout=5,verify=False)
                        if is_tomcat(resp.headers.get("Server","")) or is_tomcat(resp.text[:2000]):
                            indicators.append(f"Tomcat in {scheme}:{chk_port} response")
                        mgr = requests.get(url+"/manager/html",timeout=5,verify=False,allow_redirects=False)
                        if mgr.status_code in (200,401):
                            indicators.append(f"/manager/html reachable ({scheme}:{chk_port}, {mgr.status_code})")
                        break
                    except: continue
            if indicators: self._v(host, f"Tomcat: {'; '.join(indicators)}")
            else:          self._s(host, "No Tomcat indicators found")

    # ── 22. TLS URL (threaded) ────────────────────────────────────────────
    def tls_url(self, targets, port):
        WEAK = {"TLSv1.0","TLSv1.1","SSLv3"}
        def check_url(url):
            url = url.strip()
            if "://" not in url: url = "https://"+url
            parsed = urlparse(url)
            host = parsed.hostname
            p = parsed.port or 443
            row = {"URL":url}
            for vname, vc in _TLS_VERSIONS.items():
                if vc is None: row[vname]="N/A"; continue
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
                    ctx.minimum_version=vc; ctx.maximum_version=vc
                    if vname in ("TLSv1.0","TLSv1.1"):
                        try: ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
                        except: pass
                    with socket.create_connection((host,p),timeout=5) as sock:
                        with ctx.wrap_socket(sock,server_hostname=host): row[vname]="SUPPORTED"
                except: row[vname]="NOT SUPPORTED"
            return row

        self._i("tls_url", f"Scanning {len(targets)} URL(s) with 10 threads…")
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_path = os.path.join(OUTPUT_DIR, f"tls_url_{ts}.csv")
        rows = []
        with ThreadPoolExecutor(max_workers=10) as exe:
            futs = {exe.submit(check_url,t):t for t in targets}
            for fut in as_completed(futs):
                try:
                    row = fut.result(); rows.append(row)
                    url = row["URL"]
                    weak_sup = [v for v in WEAK if row.get(v)=="SUPPORTED"]
                    if weak_sup: self._v(url, f"Supports weak TLS: {', '.join(weak_sup)}")
                    else:
                        sup = [v for v in _TLS_VERSIONS if row.get(v)=="SUPPORTED"]
                        self._s(url, f"Supported: {', '.join(sup) if sup else 'none detected'}")
                except Exception as e:
                    self._e(futs[fut], str(e))
        # Save CSV
        if rows:
            with open(csv_path,"w",newline="",encoding="utf-8-sig") as f:
                w = csv.DictWriter(f,fieldnames=list(rows[0].keys()),extrasaction="ignore")
                w.writeheader(); w.writerows(rows)
            self._i("tls_url", f"CSV saved → {csv_path}")

    # ════════════════════════════════════════════════════════════════════
    #  FastVulnVerify-inspired modules (pure Python / nmap)
    # ════════════════════════════════════════════════════════════════════

    # ── FV-01: MS17-010 EternalBlue ──────────────────────────────────────
    def ms17_010(self, targets, port):
        for raw in targets:
            host = hostname_from(raw)
            tgt  = f"{host}:{port}"
            try:
                r = subprocess.run(
                    ["nmap","-p",str(port),"--script","smb-vuln-ms17-010","-Pn","--open",host],
                    capture_output=True, text=True, timeout=90)
                out = r.stdout + r.stderr
                if "VULNERABLE" in out:
                    self._v(tgt, "MS17-010 EternalBlue SMB RCE VULNERABLE (CVE-2017-0143)")
                elif "Host is up" in out or "open" in out:
                    self._s(tgt, "MS17-010: SMB port open but NOT vulnerable")
                else:
                    self._i(tgt, "MS17-010: Port closed or filtered")
            except FileNotFoundError:
                self._e(tgt, "nmap not installed")
            except Exception as e:
                self._e(tgt, str(e))

    # ── FV-02: BlueKeep RDP CVE-2019-0708 ────────────────────────────────
    def bluekeep(self, targets, port):
        for raw in targets:
            host = hostname_from(raw)
            tgt  = f"{host}:{port}"
            try:
                r = subprocess.run(
                    ["nmap","-p",str(port),"--script","rdp-vuln-ms12-020","-Pn",host],
                    capture_output=True, text=True, timeout=60)
                out = r.stdout
                # Try the bluekeep script if available
                r2 = subprocess.run(
                    ["nmap","-p",str(port),"--script","rdp-enum-encryption","-Pn",host],
                    capture_output=True, text=True, timeout=60)
                rdp_open = "3389/tcp open" in r.stdout or "3389/tcp open" in r2.stdout
                if rdp_open:
                    self._w(tgt, "RDP port open — BlueKeep (CVE-2019-0708) requires manual verification or Metasploit auxiliary/scanner/rdp/cve_2019_0708_bluekeep")
                else:
                    self._s(tgt, "RDP port not open — BlueKeep not applicable")
            except FileNotFoundError:
                # Fallback: raw socket check
                try:
                    with socket.create_connection((host, port), timeout=5):
                        self._w(tgt, f"Port {port} open — BlueKeep (CVE-2019-0708) requires manual check (nmap not available)")
                except:
                    self._s(tgt, f"Port {port} closed — BlueKeep not applicable")
            except Exception as e:
                self._e(tgt, str(e))

    # ── FV-03: RDP NLA Check (Terminal Services without NLA) ─────────────
    def rdp_nla(self, targets, port):
        for raw in targets:
            host = hostname_from(raw)
            tgt  = f"{host}:{port}"
            try:
                r = subprocess.run(
                    ["nmap","-p",str(port),"--script","rdp-enum-encryption","-Pn",host],
                    capture_output=True, text=True, timeout=60)
                out = r.stdout
                if "NLA" in out and "supported" in out.lower():
                    self._s(tgt, "RDP: Network Level Authentication (NLA) supported")
                elif f"{port}/tcp open" in out or "rdp" in out.lower():
                    self._v(tgt, "RDP: NLA not enforced — authentication without NLA possible")
                else:
                    self._i(tgt, f"RDP port {port} not open or no response")
            except FileNotFoundError:
                try:
                    with socket.create_connection((host, port), timeout=5):
                        self._w(tgt, f"Port {port} open — RDP NLA check requires nmap rdp-enum-encryption script")
                except:
                    self._i(tgt, f"Port {port} closed")
            except Exception as e:
                self._e(tgt, str(e))

    # ── FV-04: SNMP Default Community String ─────────────────────────────
    def snmp_default(self, targets, port):
        COMMUNITIES = ["public","private","community","admin","default","cisco","snmp"]
        for raw in targets:
            host = hostname_from(raw)
            tgt  = f"{host}:{port}"
            found = []
            # Try nmap snmp-brute / snmp-info
            try:
                r = subprocess.run(
                    ["nmap","-sU","-p",str(port),"--script","snmp-info,snmp-sysdescr","-Pn",host],
                    capture_output=True, text=True, timeout=60)
                if "SNMPv1" in r.stdout or "sysDescr" in r.stdout:
                    found.append(f"SNMP responding (nmap): {r.stdout[:200].strip()}")
            except FileNotFoundError:
                pass
            # Python fallback using snmp via UDP raw (community string probe)
            try:
                import struct
                for comm in COMMUNITIES:
                    # SNMPv1 GetRequest for sysDescr OID (1.3.6.1.2.1.1.1.0)
                    comm_b = comm.encode()
                    oid = b"\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00"
                    pdu  = b"\xa0" + bytes([len(oid)+6]) + b"\x02\x01\x00\x02\x01\x00\x30\x00" + oid
                    msg  = (b"\x30" + bytes([len(comm_b)+len(pdu)+4]) +
                            b"\x02\x01\x00\x04" + bytes([len(comm_b)]) + comm_b + pdu)
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.settimeout(3)
                        s.sendto(msg, (host, port))
                        resp, _ = s.recvfrom(1024)
                        if resp:
                            found.append(f"SNMP community '{comm}' accepted")
                            break
            except Exception:
                pass
            if found:
                self._v(tgt, "SNMP default community: " + "; ".join(found))
            else:
                self._s(tgt, "SNMP: No default community strings accepted (or port closed)")

    # ── FV-05: SSL Certificate Expiry ────────────────────────────────────
    def ssl_cert_expiry(self, targets, port):
        import datetime as dt
        for raw in targets:
            host = hostname_from(raw)
            tgt  = f"{host}:{port}"
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=8) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ss:
                        cert = ss.getpeercert()
                        if not cert:
                            # Retry with verified context to get cert info
                            self._w(tgt, "No certificate data returned"); continue
                        exp_str = cert.get("notAfter","")
                        exp_dt  = dt.datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                        now     = dt.datetime.utcnow()
                        days    = (exp_dt - now).days
                        issued  = cert.get("notBefore","")
                        subj    = dict(x[0] for x in cert.get("subject",()))
                        cn      = subj.get("commonName","?")
                        if days < 0:
                            self._v(tgt, f"SSL certificate EXPIRED {abs(days)} days ago (CN={cn}, expired {exp_str})")
                        elif days < 30:
                            self._v(tgt, f"SSL certificate expires in {days} days — CRITICAL (CN={cn}, expires {exp_str})")
                        elif days < 90:
                            self._w(tgt, f"SSL certificate expires in {days} days — WARNING (CN={cn}, expires {exp_str})")
                        else:
                            self._s(tgt, f"SSL certificate valid for {days} more days (CN={cn}, expires {exp_str})")
            except Exception as e:
                self._e(tgt, str(e))

    # ── FV-06: SSL Weak Cert Hash (MD5/SHA1) ─────────────────────────────
    def ssl_weak_hash(self, targets, port):
        for raw in targets:
            host = hostname_from(raw)
            tgt  = f"{host}:{port}"
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=8) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ss:
                        der = ss.getpeercert(binary_form=True)
                        if not der:
                            self._i(tgt, "No cert returned"); continue
                        import hashlib
                        # Check signature algorithm via raw DER scan
                        # md5WithRSA OID: 1.2.840.113549.1.1.4
                        # sha1WithRSA OID: 1.2.840.113549.1.1.5
                        md5_oid  = bytes([0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x04])
                        sha1_oid = bytes([0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x05])
                        if md5_oid in der:
                            self._v(tgt, "SSL certificate signed with MD5 (CVE-2004-2761) — VULNERABLE")
                        elif sha1_oid in der:
                            self._w(tgt, "SSL certificate signed with SHA-1 — deprecated, browsers reject it")
                        else:
                            self._s(tgt, "SSL certificate uses strong signature algorithm (SHA-256 or better)")
            except Exception as e:
                self._e(tgt, str(e))

    # ── FV-07: SSL Certificate Cannot Be Trusted ─────────────────────────
    def ssl_untrusted(self, targets, port):
        for raw in targets:
            host = hostname_from(raw)
            tgt  = f"{host}:{port}"
            try:
                # First connect with verification ON
                ctx = ssl.create_default_context()
                try:
                    with socket.create_connection((host, port), timeout=8) as sock:
                        with ctx.wrap_socket(sock, server_hostname=host):
                            self._s(tgt, "SSL certificate trusted by system CA store")
                except ssl.SSLCertVerificationError as e:
                    self._v(tgt, f"SSL certificate NOT trusted: {e.verify_message}")
                except ssl.CertificateError as e:
                    self._v(tgt, f"SSL certificate error: {e}")
            except Exception as e:
                self._e(tgt, str(e))

    # ── FV-08: Heartbleed (CVE-2014-0160) ────────────────────────────────
    def heartbleed(self, targets, port):
        for raw in targets:
            host = hostname_from(raw)
            tgt  = f"{host}:{port}"
            try:
                r = subprocess.run(
                    ["nmap","-p",str(port),"--script","ssl-heartbleed","-Pn",host],
                    capture_output=True, text=True, timeout=60)
                if "VULNERABLE" in r.stdout:
                    self._v(tgt, "Heartbleed (CVE-2014-0160) VULNERABLE — OpenSSL memory disclosure")
                elif "not vulnerable" in r.stdout.lower():
                    self._s(tgt, "Heartbleed: Not vulnerable")
                elif str(port)+"/tcp open" in r.stdout:
                    self._s(tgt, "Heartbleed: Port open, not vulnerable")
                else:
                    self._i(tgt, "Heartbleed: Could not determine (port closed or no TLS)")
            except FileNotFoundError:
                self._e(tgt, "nmap not installed (required for Heartbleed check)")
            except Exception as e:
                self._e(tgt, str(e))

    # ── FV-09: HTTP Trace/Track Methods ──────────────────────────────────
    def http_trace(self, targets, port):
        for raw in targets:
            url = normalise_url(raw, "https" if port==443 else "http")
            found = []
            for method in ("TRACE","TRACK"):
                try:
                    r = requests.request(method, url, timeout=8, verify=False, allow_redirects=False)
                    if r.status_code == 200:
                        found.append(f"{method} (200 OK)")
                    elif r.status_code in (405, 403, 501):
                        pass  # properly disabled
                    else:
                        found.append(f"{method} ({r.status_code})")
                except Exception:
                    pass
            if found:
                self._v(url, f"HTTP TRACE/TRACK enabled: {', '.join(found)} — XST attack possible")
            else:
                self._s(url, "TRACE/TRACK methods disabled")

    # ── FV-10: ASP.NET trace.axd Disclosure ──────────────────────────────
    def aspnet_trace(self, targets, port):
        PATHS = ["/trace.axd", "/Trace.axd", "/elmah.axd", "/elmah/detail.axd"]
        for raw in targets:
            parsed = urlparse(normalise_url(raw, "https" if port==443 else "http"))
            base   = f"{parsed.scheme}://{parsed.netloc}"
            found  = []
            for path in PATHS:
                try:
                    r = requests.get(base+path, timeout=8, verify=False, allow_redirects=False)
                    if r.status_code == 200 and any(x in r.text for x in
                            ["Application Trace","Request Details","ASP.NET","trace.axd"]):
                        found.append(f"{path} (200 — trace page exposed)")
                    elif r.status_code == 200:
                        found.append(f"{path} (200 — review manually)")
                except Exception:
                    pass
            if found:
                self._v(base, "ASP.NET trace.axd/elmah exposed: " + "; ".join(found))
            else:
                self._s(base, "ASP.NET trace.axd not exposed")

    # ── FV-11: Internal IP Disclosure in HTTP Headers ─────────────────────
    def internal_ip_disclosure(self, targets, port):
        RFC1918 = re.compile(
            r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
            r'172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'
            r'192\.168\.\d{1,3}\.\d{1,3})\b')
        HDRS_TO_CHECK = ["Server","Location","X-Forwarded-For","Via","X-Real-IP",
                         "X-Originating-IP","X-Remote-IP","X-Client-IP",
                         "X-Forwarded-Host","X-Backend-Server","X-Server"]
        for raw in targets:
            url = normalise_url(raw, "https" if port==443 else "http")
            try:
                r = requests.get(url, timeout=10, verify=False,
                                 allow_redirects=True,
                                 headers={"Connection":"close"})
                found = []
                for h in HDRS_TO_CHECK:
                    v = r.headers.get(h,"")
                    m = RFC1918.search(v)
                    if m:
                        found.append(f"{h}: {v} (IP: {m.group()})")
                # Also check body briefly
                body_m = RFC1918.search(r.text[:5000])
                if body_m:
                    found.append(f"Response body contains RFC1918 IP: {body_m.group()}")
                if found:
                    self._v(url, "Internal IP disclosed: " + " | ".join(found))
                else:
                    self._s(url, "No internal IP addresses found in response headers/body")
            except Exception as e:
                self._e(url, str(e))

    # ── FV-12: WEB-INF Directory Disclosure ──────────────────────────────
    def webinf_disclosure(self, targets, port):
        PATHS = ["/WEB-INF/web.xml","/WEB-INF/classes/","/WEB-INF/lib/",
                 "/META-INF/MANIFEST.MF","/WEB-INF/","/web.xml"]
        for raw in targets:
            parsed = urlparse(normalise_url(raw, "https" if port==443 else "http"))
            base   = f"{parsed.scheme}://{parsed.netloc}"
            found  = []
            for path in PATHS:
                try:
                    r = requests.get(base+path, timeout=8, verify=False, allow_redirects=False)
                    if r.status_code == 200 and len(r.text) > 50:
                        found.append(f"{path} (200 — {len(r.text)} bytes)")
                except Exception:
                    pass
            if found:
                self._v(base, "WEB-INF/META-INF accessible: " + "; ".join(found))
            else:
                self._s(base, "WEB-INF/META-INF not accessible")

    # ── FV-13: MongoDB Unauthenticated ───────────────────────────────────
    def mongodb_unauth(self, targets, port):
        for raw in targets:
            host = hostname_from(raw)
            tgt  = f"{host}:{port}"
            try:
                # MongoDB wire protocol: isMaster command
                msg = (b"\x41\x00\x00\x00"  # messageLength
                       b"\x01\x00\x00\x00"  # requestID
                       b"\x00\x00\x00\x00"  # responseTo
                       b"\xd4\x07\x00\x00"  # opCode OP_QUERY=2004
                       b"\x00\x00\x00\x00"  # flags
                       b"admin.$cmd\x00"     # fullCollectionName
                       b"\x00\x00\x00\x00"  # numberToSkip
                       b"\x01\x00\x00\x00"  # numberToReturn
                       b"\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00")
                with socket.create_connection((host, port), timeout=6) as s:
                    s.sendall(msg)
                    resp = s.recv(1024)
                    if resp and len(resp) > 20:
                        self._v(tgt, "MongoDB responding WITHOUT authentication — unauthenticated access possible")
                    else:
                        self._s(tgt, "MongoDB: No unauthenticated response")
            except ConnectionRefusedError:
                self._s(tgt, "MongoDB: Port closed")
            except Exception as e:
                self._i(tgt, f"MongoDB check: {e}")

    # ── FV-14: Telnet Detection ───────────────────────────────────────────
    def telnet_detect(self, targets, port):
        for raw in targets:
            host = hostname_from(raw)
            tgt  = f"{host}:{port}"
            try:
                with socket.create_connection((host, port), timeout=6) as s:
                    s.settimeout(3)
                    banner = b""
                    try: banner = s.recv(256)
                    except: pass
                    if banner:
                        # Telnet IAC sequence starts with 0xFF
                        if b"\xff" in banner or b"login:" in banner.lower() or b"telnet" in banner.lower():
                            self._v(tgt, f"Telnet service OPEN — unencrypted remote access (banner: {banner[:60]})")
                        else:
                            self._w(tgt, f"Port {port} open with banner: {banner[:60]} — verify if Telnet")
                    else:
                        self._w(tgt, f"Port {port} open but no banner — may be Telnet")
            except ConnectionRefusedError:
                self._s(tgt, f"Telnet: Port {port} closed")
            except Exception as e:
                self._i(tgt, f"Telnet check: {e}")

    # ── FV-15: NTP monlist DoS Amplification ─────────────────────────────
    def ntp_monlist(self, targets, port):
        for raw in targets:
            host = hostname_from(raw)
            tgt  = f"{host}:{port}"
            try:
                # NTP monlist request (mode 7, REQ_MON_GETLIST)
                pkt = bytes([0x17,0x00,0x03,0x2a]) + b"\x00"*4
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(5)
                    s.sendto(pkt, (host, port))
                    resp, _ = s.recvfrom(4096)
                    if len(resp) > 100:
                        self._v(tgt, f"NTP monlist ENABLED — amplification DDoS possible (got {len(resp)} bytes response)")
                    else:
                        self._i(tgt, "NTP responded but monlist data minimal")
            except socket.timeout:
                self._s(tgt, "NTP monlist: No response (likely disabled)")
            except Exception as e:
                self._i(tgt, f"NTP check: {e}")

    # ── FV-16: ProxyLogon Exchange CVE-2021-26855 ────────────────────────
    def proxylogon(self, targets, port):
        for raw in targets:
            parsed = urlparse(normalise_url(raw,"https"))
            host   = parsed.hostname
            base   = f"https://{host}" + (f":{port}" if port not in (443,80) else "")
            tgt    = f"{host}:{port}"
            try:
                # ProxyLogon SSRF probe — CVE-2021-26855
                ssrf_path = "/owa/auth/x.js"
                cookie = "X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3; X-BEResource=localhost/owa/auth/logon.aspx?~3;"
                r = requests.get(base + ssrf_path, timeout=8, verify=False,
                                 headers={"Cookie": cookie}, allow_redirects=False)
                is_exchange = any(x in r.headers.get("Server","").lower() for x in
                                  ("microsoft-iis","exchange")) or \
                              r.status_code in (200, 302, 401)
                # Check OWA presence
                owa = requests.get(base + "/owa/", timeout=8, verify=False, allow_redirects=True)
                has_owa = "Outlook Web" in owa.text or "owa" in owa.url.lower()
                if has_owa and r.status_code not in (404,):
                    self._w(tgt, f"Exchange/OWA detected — verify ProxyLogon (CVE-2021-26855) with authenticated scanner or PoC")
                elif is_exchange:
                    self._w(tgt, "Possible Exchange endpoint — ProxyLogon requires manual verification")
                else:
                    self._s(tgt, "No Exchange/OWA indicators found")
            except Exception as e:
                self._e(tgt, str(e))

    # ── FV-17: F5 BIG-IP Cookie Info Disclosure ───────────────────────────
    def bigip_cookie(self, targets, port):
        # BIG-IP persistence cookies encode backend server IP in base10
        BIGIP_RX = re.compile(r'BIGipServer[^=]+=(\d+)\.(\d+)\.(\d+)', re.I)
        for raw in targets:
            url = normalise_url(raw, "https" if port==443 else "http")
            try:
                r = requests.get(url, timeout=10, verify=False, allow_redirects=True)
                cookies_raw = r.headers.get("Set-Cookie","")
                m = BIGIP_RX.search(cookies_raw)
                if m:
                    # Decode: BIG-IP stores IP as little-endian base10
                    encoded = int(m.group(1))
                    port_enc= int(m.group(2))
                    b1 = (encoded)       & 0xFF
                    b2 = (encoded >> 8)  & 0xFF
                    b3 = (encoded >> 16) & 0xFF
                    b4 = (encoded >> 24) & 0xFF
                    real_ip   = f"{b1}.{b2}.{b3}.{b4}"
                    real_port = ((port_enc & 0xFF) << 8) | ((port_enc >> 8) & 0xFF)
                    self._v(url, f"F5 BIG-IP cookie discloses backend IP: {real_ip}:{real_port} (cookie: {m.group()})")
                else:
                    self._s(url, "No F5 BIG-IP persistence cookies found")
            except Exception as e:
                self._e(url, str(e))

    # ── FV-18: DNS Recursive Query / Cache Snooping ───────────────────────
    def dns_recursive(self, targets, port):
        import struct
        def build_dns_query(domain):
            tid = 0x1337
            flags = 0x0100  # standard query, recursion desired
            hdr = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)
            qname = b""
            for part in domain.split("."):
                qname += bytes([len(part)]) + part.encode()
            qname += b"\x00"
            question = qname + struct.pack(">HH", 1, 1)  # type A, class IN
            return hdr + question

        for raw in targets:
            host = hostname_from(raw)
            tgt  = f"{host}:{port}"
            try:
                pkt = build_dns_query("google.com")
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(5)
                    s.sendto(pkt, (host, port))
                    resp, _ = s.recvfrom(512)
                    if len(resp) > 12:
                        flags_resp = struct.unpack(">H", resp[2:4])[0]
                        rcode = flags_resp & 0x000F
                        ancount = struct.unpack(">H", resp[6:8])[0]
                        ra = (flags_resp >> 7) & 1  # Recursion Available
                        if ra and ancount > 0:
                            self._v(tgt, "DNS recursive queries ENABLED — cache poisoning / amplification risk")
                        elif rcode == 0:
                            self._w(tgt, "DNS responded but recursion availability unclear — verify manually")
                        else:
                            self._s(tgt, "DNS recursive queries disabled (RCODE: refused/not available)")
                    else:
                        self._i(tgt, "DNS: Short response received")
            except socket.timeout:
                self._s(tgt, "DNS: No response (port closed or recursion blocked)")
            except Exception as e:
                self._i(tgt, f"DNS check: {e}")

    # ── FV-19: SMBv1 Detection ─────────────────────────────────────────────
    def smbv1(self, targets, port):
        for raw in targets:
            host = hostname_from(raw)
            tgt  = f"{host}:{port}"
            try:
                r = subprocess.run(
                    ["nmap","-p",str(port),"--script","smb-protocols","-Pn",host],
                    capture_output=True, text=True, timeout=60)
                out = r.stdout
                if "SMBv1" in out or "NT LM 0.12" in out:
                    self._v(tgt, "SMBv1 ENABLED (CVE-2017-0143 / EternalBlue attack surface)")
                elif "SMBv2" in out or "SMBv3" in out:
                    self._s(tgt, "SMBv1 disabled; SMBv2/v3 only")
                elif str(port)+"/tcp open" in out:
                    self._w(tgt, "SMB port open — protocol version detection inconclusive")
                else:
                    self._i(tgt, "SMB port not open or filtered")
            except FileNotFoundError:
                self._e(tgt, "nmap not installed")
            except Exception as e:
                self._e(tgt, str(e))

    # ── FV-20: SSL/TLS Renegotiation ──────────────────────────────────────
    def ssl_renegotiation(self, targets, port):
        for raw in targets:
            host = hostname_from(raw)
            tgt  = f"{host}:{port}"
            try:
                r = subprocess.run(
                    ["nmap","-p",str(port),"--script","ssl-renegotiation","-Pn",host],
                    capture_output=True, text=True, timeout=60)
                out = r.stdout
                if "VULNERABLE" in out or "insecure" in out.lower():
                    self._v(tgt, "SSL/TLS insecure renegotiation (CVE-2009-3555) — MitM injection possible")
                elif "secure renegotiation" in out.lower() or "TLS_EMPTY_RENEGOTIATION" in out:
                    self._s(tgt, "SSL renegotiation: Secure (RFC 5746 extension present)")
                elif str(port)+"/tcp open" in out:
                    self._s(tgt, "SSL renegotiation: No vulnerability detected")
                else:
                    self._i(tgt, "Port closed or no TLS")
            except FileNotFoundError:
                # Fallback: check via Python
                try:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((host, port), timeout=6) as sock:
                        with ctx.wrap_socket(sock, server_hostname=host) as ss:
                            self._i(tgt, "SSL connected — renegotiation check requires nmap ssl-renegotiation script")
                except Exception as e2:
                    self._e(tgt, str(e2))
            except Exception as e:
                self._e(tgt, str(e))

    # ════════════════════════════════════════════════════════════════════
    #  NEW-01: Open Port Scanner with Service/Version Detection
    # ════════════════════════════════════════════════════════════════════
    def port_scan(self, targets, port):
        """
        Scan a wide range of common ports on each target.
        Grab banners / TLS certs to identify service + version.
        'port' param is ignored — we scan our own PORT_LIST.
        """
        # Common ports: web, DB, remote access, mail, infrastructure
        PORT_LIST = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
            389, 443, 445, 465, 587, 631, 993, 995, 1433, 1521,
            3306, 3389, 4444, 5432, 5900, 5985, 5986, 6379, 7001,
            8080, 8443, 8888, 9200, 9300, 11211, 27017, 27018,
        ]
        SERVICE_MAP = {
            21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
            80:"HTTP", 110:"POP3", 111:"RPC", 135:"MSRPC", 139:"NetBIOS",
            143:"IMAP", 389:"LDAP", 443:"HTTPS", 445:"SMB", 465:"SMTPS",
            587:"SMTP/TLS", 631:"IPP", 993:"IMAPS", 995:"POP3S",
            1433:"MSSQL", 1521:"Oracle DB", 3306:"MySQL", 3389:"RDP",
            4444:"Metasploit?", 5432:"PostgreSQL", 5900:"VNC",
            5985:"WinRM-HTTP", 5986:"WinRM-HTTPS", 6379:"Redis",
            7001:"WebLogic", 8080:"HTTP-Alt", 8443:"HTTPS-Alt",
            8888:"HTTP-Alt", 9200:"Elasticsearch", 9300:"Elasticsearch",
            11211:"Memcached", 27017:"MongoDB", 27018:"MongoDB",
        }
        RISKY_PORTS = {
            23:"Telnet (unencrypted)", 135:"MSRPC (worm vector)",
            139:"NetBIOS", 445:"SMB (EternalBlue/ransomware)",
            4444:"Metasploit default listener", 5900:"VNC (often unauth)",
            6379:"Redis (often unauthenticated)", 9200:"Elasticsearch (often unauth)",
            11211:"Memcached (DDoS amplification)", 27017:"MongoDB (often unauth)",
            1433:"MSSQL exposed", 1521:"Oracle DB exposed",
            3306:"MySQL exposed", 5432:"PostgreSQL exposed",
        }

        def grab_banner(h, p, use_tls=False, timeout=4):
            """Try to grab a service banner."""
            try:
                if use_tls:
                    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with socket.create_connection((h, p), timeout=timeout) as raw:
                        with ctx.wrap_socket(raw, server_hostname=h) as s:
                            # For HTTPS grab Server header
                            try:
                                s.sendall(f"HEAD / HTTP/1.0\r\nHost: {h}\r\n\r\n".encode())
                                resp = s.recv(1024).decode(errors="replace")
                                for line in resp.splitlines():
                                    if line.lower().startswith("server:"):
                                        return line.split(":",1)[1].strip()
                            except: pass
                            # Try cert CN
                            cert = s.getpeercert()
                            if cert:
                                subj = dict(x[0] for x in cert.get("subject",()))
                                return f"TLS CN={subj.get('commonName','?')}"
                            return "TLS (no banner)"
                else:
                    with socket.create_connection((h, p), timeout=timeout) as s:
                        s.settimeout(timeout)
                        # Send HTTP probe for web ports
                        if p in (80, 8080, 8888):
                            s.sendall(f"HEAD / HTTP/1.0\r\nHost: {h}\r\n\r\n".encode())
                        try:
                            banner = s.recv(512).decode(errors="replace").strip()
                            # Only first line of banner
                            first = banner.splitlines()[0][:120] if banner else ""
                            # For HTTP responses extract Server header
                            if "HTTP/" in first:
                                for line in banner.splitlines():
                                    if line.lower().startswith("server:"):
                                        return line.split(":",1)[1].strip()
                                return first[:80]
                            return first if first else "(connected, no banner)"
                        except socket.timeout:
                            return "(connected, no banner)"
            except (ConnectionRefusedError, socket.timeout, OSError):
                return None
            except Exception as e:
                return None

        for raw in targets:
            host = hostname_from(raw)
            self._i(host, f"Starting port scan on {host} — checking {len(PORT_LIST)} ports…")
            open_ports = []

            # Threaded connect scan
            def check_port(p):
                if self._stopped(): return None, None
                # Try plain first
                banner = grab_banner(host, p, use_tls=False)
                if banner is None and p in (443, 8443, 5986, 993, 995, 465):
                    banner = grab_banner(host, p, use_tls=True)
                return p, banner

            with ThreadPoolExecutor(max_workers=50) as ex:
                futures = {ex.submit(check_port, p): p for p in PORT_LIST}
                for fut in as_completed(futures):
                    if self._stopped(): break
                    p, banner = fut.result()
                    if banner is not None:
                        open_ports.append((p, banner))

            if not open_ports:
                self._s(host, "No common ports open (all filtered or closed)")
                continue

            open_ports.sort(key=lambda x: x[0])
            for p, banner in open_ports:
                svc  = SERVICE_MAP.get(p, "Unknown")
                tgt  = f"{host}:{p}"
                info = f"{svc} — {banner}" if banner and banner != "(connected, no banner)" else svc
                if p in RISKY_PORTS:
                    self._v(tgt, f"⚠ RISKY PORT OPEN: {RISKY_PORTS[p]} | Banner: {banner or 'n/a'}")
                else:
                    self._i(tgt, f"Open: {info}")

            # Summary
            risky = [p for p,_ in open_ports if p in RISKY_PORTS]
            self._i(host,
                f"Scan complete — {len(open_ports)} open port(s) found"
                + (f" | {len(risky)} RISKY: {risky}" if risky else ""))

    # ════════════════════════════════════════════════════════════════════
    #  NEW-02: Database Ports Exposed to the Internet
    # ════════════════════════════════════════════════════════════════════
    def db_exposed(self, targets, port):
        """
        Check whether common database ports are reachable from the scanner
        (i.e. exposed to the internet / network). Also attempts auth-less
        banner grab to confirm the service and detect unauthenticated access.
        """
        DB_PORTS = {
            1433:  ("MSSQL",       "Microsoft SQL Server"),
            1521:  ("Oracle",      "Oracle Database"),
            3306:  ("MySQL",       "MySQL / MariaDB"),
            5432:  ("PostgreSQL",  "PostgreSQL"),
            5984:  ("CouchDB",     "Apache CouchDB"),
            6379:  ("Redis",       "Redis (often unauthenticated)"),
            7474:  ("Neo4j",       "Neo4j Graph DB (HTTP API)"),
            9042:  ("Cassandra",   "Apache Cassandra"),
            9200:  ("Elastic",     "Elasticsearch (HTTP API)"),
            9300:  ("Elastic",     "Elasticsearch (transport)"),
            11211: ("Memcached",   "Memcached"),
            27017: ("MongoDB",     "MongoDB"),
            27018: ("MongoDB",     "MongoDB (shard)"),
            28015: ("RethinkDB",   "RethinkDB"),
            50000: ("DB2",         "IBM DB2"),
            6432:  ("PgBouncer",   "PgBouncer (PostgreSQL proxy)"),
        }

        # Payloads that may elicit an identifying response without auth
        AUTH_PROBES = {
            6379:  b"PING\r\n",                              # Redis PING → +PONG
            9200:  b"GET / HTTP/1.0\r\n\r\n",               # Elastic info
            7474:  b"GET / HTTP/1.0\r\n\r\n",               # Neo4j HTTP
            5984:  b"GET / HTTP/1.0\r\n\r\n",               # CouchDB
            11211: b"stats\r\n",                             # Memcached
            27017: (b"\x41\x00\x00\x00\x01\x00\x00\x00"    # MongoDB isMaster
                    b"\x00\x00\x00\x00\xd4\x07\x00\x00"
                    b"\x00\x00\x00\x00admin.$cmd\x00"
                    b"\x00\x00\x00\x00\x01\x00\x00\x00"
                    b"\x13\x00\x00\x00\x10isMaster\x00"
                    b"\x01\x00\x00\x00\x00"),
        }

        # Indicators of unauthenticated access in response
        UNAUTH_INDICATORS = {
            6379:  ["+PONG", "+OK"],
            9200:  ['"cluster_name"', '"version"', '"tagline"'],
            7474:  ["neo4j", "Neo4j", "bolt"],
            5984:  ['"couchdb"', '"version"'],
            11211: ["STAT ", "VERSION "],
            27017: [b"\x01\x00\x00\x00"],   # MongoDB OP_REPLY opcode
        }

        for raw in targets:
            host = hostname_from(raw)
            any_found = False

            for db_port, (short, full_name) in DB_PORTS.items():
                if self._stopped(): break
                tgt = f"{host}:{db_port}"
                try:
                    with socket.create_connection((host, db_port), timeout=5) as s:
                        s.settimeout(4)
                        any_found = True
                        # Send probe if we have one
                        probe   = AUTH_PROBES.get(db_port)
                        resp    = b""
                        resp_s  = ""
                        if probe:
                            try:
                                s.sendall(probe)
                                resp   = s.recv(2048)
                                resp_s = resp.decode(errors="replace")
                            except: pass
                        else:
                            try: resp = s.recv(512); resp_s = resp.decode(errors="replace")
                            except: pass

                        # Check for unauthenticated access
                        unauth = False
                        indicators = UNAUTH_INDICATORS.get(db_port, [])
                        for ind in indicators:
                            if isinstance(ind, bytes):
                                if ind in resp: unauth = True; break
                            else:
                                if ind in resp_s: unauth = True; break

                        # Banner — first meaningful line
                        banner = ""
                        if resp_s:
                            for line in resp_s.splitlines():
                                line = line.strip()
                                if line and len(line) > 2:
                                    banner = line[:120]; break

                        if unauth:
                            self._v(tgt,
                                f"🗄 {full_name} EXPOSED + UNAUTHENTICATED ACCESS — "
                                f"no credentials required! Banner: {banner or 'n/a'}")
                        else:
                            self._v(tgt,
                                f"🗄 {full_name} PORT EXPOSED to network"
                                + (f" — Banner: {banner}" if banner else " (no banner / auth required)"))

                except ConnectionRefusedError:
                    self._s(tgt, f"{full_name}: Port closed")
                except socket.timeout:
                    self._s(tgt, f"{full_name}: Filtered / no response")
                except Exception as e:
                    self._i(tgt, f"{full_name}: {e}")

            if not any_found:
                self._s(host, "No database ports reachable from this scanner — good!")

    # ════════════════════════════════════════════════════════════════════
    #  SHORTSCAN — IIS Short Filename (8.3) Enumeration (CVE-2010-2730)
    # ════════════════════════════════════════════════════════════════════
    def shortscan(self, targets, port):
        """
        Pure-Python IIS tilde (~) short filename enumeration.
        Replicates the core technique of Shortscan / IIS-ShortName-Scanner.

        Method: Send HEAD requests with tilde wildcard paths.
        IIS returns 404 (or 400) for valid short names vs 400 for invalid ones.
        This reveals the first 6 chars of filenames and extensions.

        CVE-2010-2730  /  OWASP: IIS Short Filename Disclosure
        """
        CHARSET   = "abcdefghijklmnopqrstuvwxyz0123456789_-"
        MAX_DEPTH = 6   # max filename chars to brute

        def _probe(session, base_url, path_tilde):
            """Return True if IIS indicates the short name exists."""
            try:
                r = session.head(base_url + path_tilde, timeout=6,
                                 verify=False, allow_redirects=False)
                # IIS leaks: 404 (exists), 400 (invalid), 200 (hit)
                # Non-IIS returns consistent 400/404 for both → not vulnerable
                return r.status_code in (200, 301, 302, 404)
            except Exception:
                return False

        def _is_vulnerable(session, base_url):
            """
            Check if the server leaks short names by comparing responses:
            valid tilde path vs definitely-invalid tilde path.
            """
            # Path that IIS WOULD respond to if vulnerable
            test_valid   = "/*~1*/.aspx"
            # Path that is always invalid
            test_invalid = "/AAAAAAAAAAAAAAAAAAAA~1/.aspx"
            try:
                r1 = session.head(base_url + test_valid,   timeout=6, verify=False, allow_redirects=False)
                r2 = session.head(base_url + test_invalid, timeout=6, verify=False, allow_redirects=False)
                # Vulnerable: different status codes
                return r1.status_code != r2.status_code
            except Exception:
                return False

        def _enumerate(session, base_url, is_dir=False):
            """Brute-force short file/dir names up to MAX_DEPTH chars."""
            found = []
            prefix_queue = [""]
            while prefix_queue:
                if self._stopped(): break
                prefix = prefix_queue.pop(0)
                if len(prefix) >= MAX_DEPTH:
                    found.append(prefix + "~1" + ("/" if is_dir else ""))
                    continue
                any_child = False
                for c in CHARSET:
                    if self._stopped(): break
                    candidate = prefix + c
                    # Wildcard probe: candidate* exists?
                    tilde_path = f"/{candidate}*~1{'/' if is_dir else '.*'}"
                    if _probe(session, base_url, tilde_path):
                        prefix_queue.append(candidate)
                        any_child = True
                if not any_child and prefix:
                    found.append(prefix + "~1" + ("/" if is_dir else ""))
            return found

        for raw in targets:
            scheme   = "https" if port in (443, 8443) else "http"
            host     = hostname_from(raw)
            base_url = f"{scheme}://{host}" + (f":{port}" if port not in (80,443) else "")
            tgt      = f"{host}:{port}"

            self._i(tgt, f"Shortscan: Testing IIS short filename disclosure on {base_url}…")

            session = requests.Session()
            session.headers.update({
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Accept":     "*/*",
            })

            # 1. Vulnerability check
            try:
                vulnerable = _is_vulnerable(session, base_url)
            except Exception as e:
                self._e(tgt, f"Shortscan: Connection failed — {e}"); continue

            if not vulnerable:
                self._s(tgt, "Shortscan: Server does NOT appear vulnerable to IIS short filename disclosure")
                continue

            self._v(tgt, "Shortscan: SERVER IS VULNERABLE to IIS short filename (8.3) disclosure (CVE-2010-2730)!")

            # 2. Enumerate files
            self._i(tgt, "Shortscan: Enumerating short filenames (this may take a moment)…")
            files = _enumerate(session, base_url, is_dir=False)
            dirs  = _enumerate(session, base_url, is_dir=True)

            if files:
                for fn in files[:30]:   # cap output
                    self._v(tgt, f"Shortscan FILE: {fn}* (short name disclosed — reconstruct full name manually)")
            else:
                self._i(tgt, "Shortscan: No files enumerated (server may rate-limit or require specific paths)")

            if dirs:
                for dn in dirs[:20]:
                    self._w(tgt, f"Shortscan DIR:  {dn}* (directory short name disclosed)")

            total = len(files) + len(dirs)
            self._v(tgt,
                f"Shortscan complete — {len(files)} file(s), {len(dirs)} dir(s) disclosed. "
                f"Use shortscan CLI or IIS-ShortName-Scanner for full enumeration.")

    # ── dispatcher ────────────────────────────────────────────────────────
    # ── Retire.js — Vulnerable JavaScript Library Detection ──────────────
    def retirejs(self, targets, port):
        """Detect outdated/vulnerable JS libraries (jQuery, Bootstrap, Angular, etc.)
        by fetching page HTML and checking script src versions against known CVEs."""
        import re as _re
        # Known vulnerable version ranges: {lib: [(max_safe_ver, cve, severity), ...]}
        VULN_DB = {
            "jquery": [
                ("1.12.4", "CVE-2019-11358 (prototype pollution)", "HIGH"),
                ("3.4.0",  "CVE-2019-11358 (prototype pollution)", "HIGH"),
                ("3.5.0",  "CVE-2020-11022/11023 (XSS via HTML)", "HIGH"),
            ],
            "bootstrap": [
                ("3.4.0",  "CVE-2018-14041/14042 (XSS)", "MEDIUM"),
                ("4.3.0",  "CVE-2019-8331 (XSS tooltip)", "MEDIUM"),
            ],
            "angular": [
                ("1.6.0",  "CVE-2019-14863 (XSS)", "HIGH"),
                ("1.7.9",  "CVE-2020-7676 (XSS)", "HIGH"),
            ],
            "angularjs": [
                ("1.6.0",  "CVE-2019-14863 (XSS)", "HIGH"),
                ("1.7.9",  "CVE-2020-7676 (XSS)", "HIGH"),
            ],
            "react": [
                ("16.0.0", "CVE-2018-6341 (XSS dangerouslySetInnerHTML)", "MEDIUM"),
            ],
            "lodash": [
                ("4.17.11","CVE-2019-10744 (prototype pollution)", "HIGH"),
                ("4.17.20","CVE-2020-28500 (ReDoS)", "MEDIUM"),
            ],
            "moment": [
                ("2.29.1", "CVE-2022-24785 (path traversal)", "HIGH"),
            ],
            "vue": [
                ("2.6.10", "CVE-2021-22931 (XSS)", "MEDIUM"),
            ],
        }
        # Regex to find <script src="...lib-version...">
        SCRIPT_RE = _re.compile(
            r'<script[^>]+src=["\']([^"\']*?'
            r'(jquery|bootstrap|angular(?:js)?|react|lodash|moment|vue)'
            r'[^"\']*?)["\']',
            _re.IGNORECASE)
        VER_RE = _re.compile(r'[-./](\d+\.\d+\.?\d*)', _re.IGNORECASE)

        def _parse_ver(v):
            try:
                parts = [int(x) for x in v.split(".")[:3]]
                while len(parts) < 3: parts.append(0)
                return tuple(parts)
            except: return (0, 0, 0)

        def _is_vulnerable(lib, ver_str):
            issues = []
            vt = _parse_ver(ver_str)
            for max_safe, cve, sev in VULN_DB.get(lib.lower(), []):
                if vt <= _parse_ver(max_safe):
                    issues.append(f"{cve} [{sev}]")
            return issues

        for raw in targets:
            if self._stopped(): return
            host = hostname_from(raw)
            tgt = f"{host}:{port}"
            found_any = False
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}:{port}/"
                try:
                    r = requests.get(url, timeout=10, verify=False, allow_redirects=True)
                    scripts = SCRIPT_RE.findall(r.text)
                    if not scripts:
                        self._i(tgt, "No known JS libraries found in page source")
                        found_any = True
                        break
                    seen = set()
                    for src_full, lib in scripts:
                        if lib.lower() in seen: continue
                        seen.add(lib.lower())
                        # Extract version from filename
                        m = VER_RE.search(src_full)
                        ver = m.group(1) if m else None
                        if not ver:
                            self._i(tgt, f"{lib}: found (version undetectable) — {src_full[:80]}")
                            continue
                        issues = _is_vulnerable(lib, ver)
                        if issues:
                            self._v(tgt, f"{lib} v{ver} VULNERABLE — " + ", ".join(issues) + f" | src: {src_full[:80]}")
                        else:
                            self._s(tgt, f"{lib} v{ver} — no known CVEs in Retire.js DB")
                    found_any = True
                    break
                except Exception:
                    continue
            if not found_any:
                self._e(tgt, "Could not reach target for Retire.js scan")

    # ── Tech Fingerprint (Wappalyzer-style) ───────────────────────────────
    def tech_fingerprint(self, targets, port):
        """Detect tech stack from HTTP headers + HTML patterns:
        web server, framework, CMS, JS libraries, OS."""
        import re as _re
        SIGNATURES = {
            # (category, name, [header_patterns], [body_patterns])
            "Web Server": [
                ("Apache",       [("Server", r"Apache(?:/[\d.]+)?")],  []),
                ("Nginx",        [("Server", r"nginx(?:/[\d.]+)?")],   []),
                ("IIS",          [("Server", r"Microsoft-IIS(?:/[\d.]+)?")], []),
                ("LiteSpeed",    [("Server", r"LiteSpeed")],           []),
                ("Cloudflare",   [("Server", r"cloudflare"), ("CF-RAY", r".")], []),
                ("Caddy",        [("Server", r"Caddy")],               []),
            ],
            "Framework": [
                ("ASP.NET",      [("X-Powered-By", r"ASP\.NET"), ("X-AspNet-Version", r".")], [r'__VIEWSTATE', r'asp\.net']),
                ("PHP",          [("X-Powered-By", r"PHP/[\d.]+")],   [r'\.php']),
                ("Django",       [("X-Frame-Options", r"SAMEORIGIN")], [r'csrfmiddlewaretoken', r'django']),
                ("Laravel",      [("Set-Cookie", r"laravel_session")], [r'laravel']),
                ("Ruby on Rails",[("X-Powered-By", r"Phusion Passenger")], [r'csrf-token.*rails']),
                ("Express/Node", [("X-Powered-By", r"Express")],      []),
                ("Spring",       [("X-Application-Context", r".")],   [r'spring', r'Whitelabel Error']),
            ],
            "CMS": [
                ("WordPress",    [],  [r'/wp-content/', r'/wp-includes/', r'wp-json']),
                ("Joomla",       [],  [r'/components/com_', r'Joomla!']),
                ("Drupal",       [("X-Generator", r"Drupal")], [r'Drupal\.settings', r'/sites/default/']),
                ("Magento",      [],  [r'Mage\.Cookies', r'/skin/frontend/']),
                ("Shopify",      [],  [r'cdn\.shopify\.com', r'Shopify\.theme']),
                ("Squarespace",  [],  [r'squarespace\.com', r'static\.squarespace']),
            ],
            "JS Library": [
                ("jQuery",       [],  [r'jquery(?:\.min)?\.js', r"jQuery v?([\d.]+)"]),
                ("React",        [],  [r'react(?:\.min)?\.js', r'react-dom', r'__reactFiber']),
                ("Angular",      [],  [r'angular(?:\.min)?\.js', r'ng-version=']),
                ("Vue.js",       [],  [r'vue(?:\.min)?\.js', r'__vue__']),
                ("Bootstrap",    [],  [r'bootstrap(?:\.min)?\.(?:js|css)']),
            ],
            "CDN / WAF": [
                ("Cloudflare WAF",[("CF-RAY", r".")], []),
                ("Akamai",       [("X-Check-Cacheable", r".")], []),
                ("Imperva",      [("X-Iinfo", r".")], []),
                ("AWS CloudFront",[("X-Cache", r"CloudFront"), ("Via", r"CloudFront")], []),
                ("Fastly",       [("X-Served-By", r"cache-")], []),
            ],
            "Operating System": [
                ("Windows Server",[("Server", r"Win(?:32|64|dows)")], []),
                ("Ubuntu",       [("Server", r"Ubuntu")],  []),
                ("Debian",       [("Server", r"Debian")],  []),
                ("CentOS",       [("Server", r"CentOS")],  []),
            ],
        }

        for raw in targets:
            if self._stopped(): return
            host = hostname_from(raw)
            tgt = f"{host}:{port}"
            detected = []
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}:{port}/"
                try:
                    r = requests.get(url, timeout=10, verify=False, allow_redirects=True)
                    hdrs = {k.lower(): v for k, v in r.headers.items()}
                    body = r.text[:8000]
                    for category, sigs in SIGNATURES.items():
                        for name, hdr_pats, body_pats in sigs:
                            matched = False
                            for hdr, pat in hdr_pats:
                                val = hdrs.get(hdr.lower(), "")
                                if val and _re.search(pat, val, _re.IGNORECASE):
                                    matched = True; break
                            if not matched:
                                for pat in body_pats:
                                    if _re.search(pat, body, _re.IGNORECASE):
                                        matched = True; break
                            if matched:
                                detected.append(f"[{category}] {name}")
                    break
                except Exception:
                    continue
            if detected:
                summary = " | ".join(detected)
                self._i(tgt, f"Tech Stack: {summary}")
                # Flag outdated/risky items
                risky = [d for d in detected if any(x in d for x in
                    ["IIS", "ASP.NET", "WordPress", "Joomla", "Magento", "jQuery"])]
                if risky:
                    self._w(tgt, f"Review these for known CVEs: {', '.join(risky)}")
            else:
                self._i(tgt, "No technology signatures detected")

    DISPATCH = {
        "tls_version": tls_version, "ssl_complete": ssl_complete,
        "ssl_vuln_ciphers": ssl_vuln_ciphers, "sweet32": sweet32,
        "missing_headers": missing_headers, "hsts": hsts, "clickjacking": clickjacking,
        "header_analyser": header_analyser, "header_analyser_ssl": header_analyser_ssl,
        "basic_auth": basic_auth, "options_method": options_method, "asp_debug": asp_debug,
        "crossdomain": crossdomain, "clientaccess": clientaccess,
        "dir_listing": dir_listing, "jquery": jquery, "jquery_ssl": jquery_ssl,
        "server_version": server_version, "unencrypted": unencrypted,
        "ssh_weak": ssh_weak, "smb_signing": smb_signing,
        "tomcat": tomcat, "tls_url": tls_url,
        # FastVulnVerify modules
        "ms17_010": ms17_010, "bluekeep": bluekeep, "rdp_nla": rdp_nla,
        "snmp_default": snmp_default, "ssl_cert_expiry": ssl_cert_expiry,
        "ssl_weak_hash": ssl_weak_hash, "ssl_untrusted": ssl_untrusted,
        "heartbleed": heartbleed, "http_trace": http_trace,
        "aspnet_trace": aspnet_trace, "internal_ip_disclosure": internal_ip_disclosure,
        "webinf_disclosure": webinf_disclosure, "mongodb_unauth": mongodb_unauth,
        "telnet_detect": telnet_detect, "ntp_monlist": ntp_monlist,
        "proxylogon": proxylogon, "bigip_cookie": bigip_cookie,
        "dns_recursive": dns_recursive, "smbv1": smbv1,
        "ssl_renegotiation": ssl_renegotiation,
        # New modules
        "port_scan": port_scan,
        "db_exposed": db_exposed,
        "shortscan": shortscan,
        "php_version": php_version,
        "apache_version": apache_version,
        "smb_null_session": smb_null_session,
        "retirejs": retirejs,
        "tech_fingerprint": tech_fingerprint,
    }

    def run(self, tool_key, targets, port):
        fn = self.DISPATCH.get(tool_key)
        if fn:
            # Filter targets through stop_flag for per-target cancellation
            def filtered_targets():
                for t in targets:
                    if self._stopped():
                        self._i("—", "⏹ Scan stopped by user")
                        return
                    yield t
            fn(self, list(filtered_targets()), port)
        else:
            self._e("—", f"Unknown tool: {tool_key}")


# ══════════════════════════════════════════════════════════════════════════
#  TOOLS METADATA
# ══════════════════════════════════════════════════════════════════════════
TOOLS = [
    # (key, display_name, default_port, group)
    ("tls_version",         "TLS Version Checker",              443,  "SSL/TLS"),
    ("ssl_complete",        "SSL Complete Audit (all ciphers)", 443,  "SSL/TLS"),
    ("ssl_vuln_ciphers",    "Vuln Ciphers: BEAST/BREACH/RC4",   443,  "SSL/TLS"),
    ("sweet32",             "SWEET32 / 3DES Check",             443,  "SSL/TLS"),
    ("tls_url",             "TLS v1.0–1.3 per-URL (threaded)",  443,  "SSL/TLS"),
    ("missing_headers",     "Missing Security Headers",         443,  "HTTP Headers"),
    ("hsts",                "HSTS Check",                       443,  "HTTP Headers"),
    ("clickjacking",        "Clickjacking Protection",          80,   "HTTP Headers"),
    ("header_analyser",     "Server Version Disclosure",        443,  "HTTP Headers"),
    ("header_analyser_ssl", "Server Version (SSL bypass)",      443,  "HTTP Headers"),
    ("basic_auth",          "Basic Authentication Detection",   80,   "Auth/Methods"),
    ("options_method",      "HTTP Dangerous Methods (OPTIONS)", 443,  "Auth/Methods"),
    ("asp_debug",           "ASP.NET Debug Mode",               80,   "Auth/Methods"),
    ("crossdomain",         "crossdomain.xml Policy",           443,  "Web App"),
    ("clientaccess",        "clientaccesspolicy.xml",           443,  "Web App"),
    ("dir_listing",         "Directory Listing Detection",      80,   "Web App"),
    ("jquery",              "jQuery Version Detection",         80,   "Web App"),
    ("jquery_ssl",          "jQuery (SSL bypass)",              443,  "Web App"),
    ("server_version",      "Server / X-Powered-By Header",    80,   "Web App"),
    ("unencrypted",         "HTTP vs HTTPS (Unencrypted)",      80,   "Web App"),
    ("ssh_weak",            "SSH Weak Algorithms",              22,   "Network/Host"),
    ("smb_signing",         "SMB Signing Check",                445,  "Network/Host"),
    ("tomcat",              "Apache Tomcat Detection",          8080, "Network/Host"),
    # FastVulnVerify — SSL/TLS Certificate
    ("ssl_cert_expiry",     "SSL Cert Expiry Check",            443,  "SSL/TLS Certs"),
    ("ssl_weak_hash",       "SSL Weak Hash (MD5/SHA1)",         443,  "SSL/TLS Certs"),
    ("ssl_untrusted",       "SSL Untrusted Certificate",        443,  "SSL/TLS Certs"),
    ("ssl_renegotiation",   "SSL Insecure Renegotiation",       443,  "SSL/TLS Certs"),
    ("heartbleed",          "Heartbleed CVE-2014-0160",         443,  "SSL/TLS Certs"),
    # FastVulnVerify — HTTP Exploits
    ("http_trace",          "HTTP TRACE/TRACK (XST)",           80,   "HTTP Exploits"),
    ("aspnet_trace",        "ASP.NET trace.axd Disclosure",     80,   "HTTP Exploits"),
    ("internal_ip_disclosure","Internal IP in Headers",         80,   "HTTP Exploits"),
    ("webinf_disclosure",   "WEB-INF / META-INF Exposure",      80,   "HTTP Exploits"),
    ("bigip_cookie",        "F5 BIG-IP Cookie Disclosure",      80,   "HTTP Exploits"),
    ("proxylogon",          "ProxyLogon CVE-2021-26855",        443,  "HTTP Exploits"),
    # FastVulnVerify — Network / Host
    ("ms17_010",            "EternalBlue MS17-010 (SMB)",       445,  "Network Exploits"),
    ("smbv1",               "SMBv1 Detection",                  445,  "Network Exploits"),
    ("bluekeep",            "BlueKeep CVE-2019-0708 (RDP)",     3389, "Network Exploits"),
    ("rdp_nla",             "RDP NLA Check",                    3389, "Network Exploits"),
    ("snmp_default",        "SNMP Default Community String",    161,  "Network Exploits"),
    ("mongodb_unauth",      "MongoDB Unauthenticated Access",   27017,"Network Exploits"),
    ("telnet_detect",       "Telnet Service Detection",         23,   "Network Exploits"),
    ("ntp_monlist",         "NTP monlist Amplification",        123,  "Network Exploits"),
    ("dns_recursive",       "DNS Recursive Query",              53,   "Network Exploits"),
    # New tools
    ("port_scan",           "Open Port Scanner + Versions",     0,    "Recon"),
    ("db_exposed",          "Database Ports Exposed",           0,    "Recon"),
    ("shortscan",           "IIS Short Filename (Shortscan)",   80,   "Recon"),
    ("php_version",         "PHP Version Disclosure",           80,   "Web App"),
    ("apache_version",      "Apache Server Version Disclosure", 80,   "Web App"),
    ("smb_null_session",    "SMB Null Session Check",           445,  "Network/Host"),
    ("retirejs",            "Retire.js Vuln JS Libraries",      80,   "Web App"),
    ("tech_fingerprint",    "Tech Fingerprint (Wappalyzer)",    80,   "Recon"),
]
TOOL_BY_KEY = {t[0]: t for t in TOOLS}


# ══════════════════════════════════════════════════════════════════════════
#  GUI
# ══════════════════════════════════════════════════════════════════════════
class RevalPackApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("RevalPack v4.0 — Security Revalidation Scanner  |  Author: Suprit Mangde")
        self.geometry("1180x740")
        self.minsize(900, 600)
        self.configure(bg=DARK)
        self._q = queue.Queue()
        self._running = False
        self._stop_flag = False
        self._results = []
        self._build_ui()
        self._poll()

    # ── UI BUILD ──────────────────────────────────────────────────────────
    def _build_ui(self):
        # Sidebar
        sb = tk.Frame(self, bg=SIDEBAR, width=210)
        sb.pack(side=tk.LEFT, fill=tk.Y); sb.pack_propagate(False)

        # Brand
        brand = tk.Frame(sb, bg=SIDEBAR)
        brand.pack(fill=tk.X, padx=14, pady=(22,0))
        mark = tk.Label(brand, text="R", bg=GREEN, fg=WHITE,
                        font=("Segoe UI",14,"bold"), width=2, relief="flat")
        mark.pack(side=tk.LEFT, padx=(0,8))
        tk.Label(brand, text="RevalPack", bg=SIDEBAR, fg=WHITE,
                 font=("Segoe UI",13,"bold")).pack(side=tk.LEFT, anchor="w")

        tk.Label(sb, text="Suprit Mangde · Offensive Security", bg=SIDEBAR,
                 fg=MUTED, font=("Segoe UI",9)).pack(padx=14, anchor="w", pady=(2,0))
        tk.Label(sb, text="Author: Suprit Mangde", bg=SIDEBAR,
                 fg=GREEN_L, font=("Segoe UI",8)).pack(padx=14, anchor="w", pady=(0,4))

        # ── Search box ────────────────────────────────────────────────────
        search_frame = tk.Frame(sb, bg=SIDEBAR)
        search_frame.pack(fill=tk.X, padx=10, pady=(12,0))

        # magnifier icon label
        tk.Label(search_frame, text="🔍", bg=SIDEBAR, fg=MUTED,
                 font=("Segoe UI",10)).pack(side=tk.LEFT, padx=(4,2))

        self._search_var = tk.StringVar()
        search_entry = tk.Entry(search_frame, textvariable=self._search_var,
                                bg=CARD, fg=TEXT, insertbackground=GREEN_L,
                                font=("Segoe UI",9), relief="flat",
                                highlightthickness=1, highlightbackground=LINE,
                                highlightcolor=GREEN)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5, padx=(0,4))
        search_entry.insert(0, "Search tools…")
        search_entry.configure(fg=MUTED)

        def _search_focus_in(e):
            if search_entry.get() == "Search tools…":
                search_entry.delete(0, tk.END)
                search_entry.configure(fg=TEXT)
        def _search_focus_out(e):
            if not search_entry.get().strip():
                search_entry.insert(0, "Search tools…")
                search_entry.configure(fg=MUTED)

        search_entry.bind("<FocusIn>",  _search_focus_in)
        search_entry.bind("<FocusOut>", _search_focus_out)

        # Clear button
        def _clear_search():
            search_entry.delete(0, tk.END)
            search_entry.insert(0, "Search tools…")
            search_entry.configure(fg=MUTED)
            self._search_var.set("")
            self._filter_tools("")

        clear_btn = tk.Label(search_frame, text="✕", bg=SIDEBAR, fg=MUTED,
                             font=("Segoe UI",10), cursor="hand2", padx=4)
        clear_btn.pack(side=tk.LEFT)
        clear_btn.bind("<Button-1>", lambda e: _clear_search())

        tk.Label(sb, text="TOOLS", bg=SIDEBAR, fg=MUTED,
                 font=("Segoe UI",8,"bold")).pack(padx=14, pady=(10,2), anchor="w")

        # ── Scrollable sidebar canvas ──────────────────────────────────────
        sb_canvas = tk.Canvas(sb, bg=SIDEBAR, highlightthickness=0, bd=0)
        sb_scroll = tk.Scrollbar(sb, orient="vertical", command=sb_canvas.yview)
        sb_canvas.configure(yscrollcommand=sb_scroll.set)
        sb_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        sb_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        tool_frame = tk.Frame(sb_canvas, bg=SIDEBAR)
        sb_win = sb_canvas.create_window((0,0), window=tool_frame, anchor="nw")

        def _on_tf_resize(e):
            sb_canvas.configure(scrollregion=sb_canvas.bbox("all"))
            sb_canvas.itemconfig(sb_win, width=sb_canvas.winfo_width())
        tool_frame.bind("<Configure>", _on_tf_resize)
        sb_canvas.bind("<Configure>", lambda e: sb_canvas.itemconfig(sb_win, width=e.width))

        def _on_mousewheel(e):
            sb_canvas.yview_scroll(int(-1*(e.delta/120)), "units")
        sb_canvas.bind_all("<MouseWheel>", _on_mousewheel)

        # Build collapsible groups
        self._tool_btns    = {}
        self._group_frames = {}   # group -> (header_frame, items_frame, collapsed_var)
        self._tool_names   = {}   # key -> display name (for search filtering)
        self._sb_canvas    = sb_canvas
        self._tool_frame   = tool_frame

        groups_ordered = []
        seen_groups    = {}
        for key, name, port, group in TOOLS:
            if group not in seen_groups:
                seen_groups[group] = []
                groups_ordered.append(group)
            seen_groups[group].append((key, name, port))
            self._tool_names[key] = name.lower()

        for group in groups_ordered:
            # Group header — click to collapse/expand
            collapsed = tk.BooleanVar(value=False)
            grp_hdr = tk.Frame(tool_frame, bg=SIDEBAR, cursor="hand2")
            grp_hdr.pack(fill=tk.X, padx=4, pady=(10,0))

            arrow_lbl = tk.Label(grp_hdr, text="▾", bg=SIDEBAR, fg=GREEN_L,
                                 font=("Segoe UI",8,"bold"))
            arrow_lbl.pack(side=tk.LEFT, padx=(4,2))
            tk.Label(grp_hdr, text=group.upper(), bg=SIDEBAR, fg=MUTED,
                     font=("Segoe UI",7,"bold")).pack(side=tk.LEFT, padx=(0,4))

            items_frame = tk.Frame(tool_frame, bg=SIDEBAR)
            items_frame.pack(fill=tk.X, padx=2)

            def _toggle(cf=items_frame, av=arrow_lbl, cv=collapsed):
                cv.set(not cv.get())
                if cv.get():
                    cf.pack_forget()
                    av.configure(text="▸")
                else:
                    cf.pack(fill=tk.X, padx=2)
                    av.configure(text="▾")
                tool_frame.update_idletasks()
                sb_canvas.configure(scrollregion=sb_canvas.bbox("all"))

            grp_hdr.bind("<Button-1>", lambda e, t=_toggle: t())
            arrow_lbl.bind("<Button-1>", lambda e, t=_toggle: t())
            for child in grp_hdr.winfo_children():
                child.bind("<Button-1>", lambda e, t=_toggle: t())

            self._group_frames[group] = (grp_hdr, items_frame, collapsed)

            # Tool buttons inside group
            for key, name, port in seen_groups[group]:
                btn = tk.Label(items_frame, text=f"  {name}", bg=SIDEBAR, fg=TEXT,
                               font=("Segoe UI",9), anchor="w", cursor="hand2",
                               padx=4, pady=4, wraplength=180, justify="left")
                btn.pack(fill=tk.X, padx=2, pady=1)
                btn.bind("<Button-1>", lambda e, k=key: self._select_tool(k))
                btn.bind("<Enter>",    lambda e, b=btn: b.configure(bg=DARK2))
                btn.bind("<Leave>",    lambda e, b=btn, k=key: b.configure(
                    bg=GREEN if self._current_tool==k else SIDEBAR))
                self._tool_btns[key] = btn

        # Footer
        tk.Label(sb, text=f"v4.0 · {len(TOOLS)} tools", bg=SIDEBAR, fg=MUTED,
                 font=("Segoe UI",8)).pack(side=tk.BOTTOM, padx=14, pady=(0,4), anchor="w")
        tk.Label(sb, text="● Offline · standalone", bg=SIDEBAR, fg=GREEN_L,
                 font=("Segoe UI",8)).pack(side=tk.BOTTOM, padx=14, pady=(0,2), anchor="w")

        # Main area
        main = tk.Frame(self, bg=DARK)
        main.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Header bar
        hdr = tk.Frame(main, bg=DARK2, height=52)
        hdr.pack(fill=tk.X); hdr.pack_propagate(False)
        self._hdr_title = tk.Label(hdr, text="Select a tool from the left panel",
                                   bg=DARK2, fg=WHITE, font=("Segoe UI",12,"bold"))
        self._hdr_title.pack(side=tk.LEFT, padx=20, pady=14)
        self._hdr_chip = tk.Label(hdr, text="0 results", bg=DARK, fg=MUTED,
                                  font=("Segoe UI",9), padx=10, pady=4)
        self._hdr_chip.pack(side=tk.RIGHT, padx=20, pady=12)

        # Top config panel
        top = tk.Frame(main, bg=DARK, pady=12)
        top.pack(fill=tk.X, padx=18)

        # Targets
        tgt_lbl = tk.Label(top, text="TARGETS  (one IP / hostname / URL per line)",
                           bg=DARK, fg=MUTED, font=("Segoe UI",8,"bold"))
        tgt_lbl.grid(row=0, column=0, sticky="w", pady=(0,4))

        self._targets_box = tk.Text(top, height=6, bg=CARD, fg=TEXT,
                                    insertbackground=GREEN_L, font=MONO,
                                    relief="flat", bd=0, padx=8, pady=6,
                                    highlightthickness=1,
                                    highlightbackground=LINE,
                                    highlightcolor=GREEN)
        self._targets_box.grid(row=1, column=0, sticky="ew", padx=(0,12))
        self._targets_box.bind("<KeyRelease>", self._update_count)

        # Right config
        cfg = tk.Frame(top, bg=DARK)
        cfg.grid(row=1, column=1, sticky="ns")

        tk.Label(cfg, text="PORT", bg=DARK, fg=MUTED,
                 font=("Segoe UI",8,"bold")).pack(anchor="w")
        self._port_var = tk.StringVar(value="443")
        self._port_entry = tk.Entry(cfg, textvariable=self._port_var,
                                    width=10, bg=CARD, fg=TEXT,
                                    insertbackground=GREEN_L, font=MONO,
                                    relief="flat", highlightthickness=1,
                                    highlightbackground=LINE, highlightcolor=GREEN)
        self._port_entry.pack(fill=tk.X, pady=(2,12), ipady=5)

        tk.Label(cfg, text="TARGETS", bg=DARK, fg=MUTED,
                 font=("Segoe UI",8,"bold")).pack(anchor="w")
        self._count_lbl = tk.Label(cfg, text="0", bg=DARK, fg=GREEN_L,
                                   font=("Segoe UI",18,"bold"))
        self._count_lbl.pack()

        btn_frame = tk.Frame(cfg, bg=DARK)
        btn_frame.pack(fill=tk.X, pady=(10,0))
        self._run_btn = tk.Button(btn_frame, text="▶  RUN SCAN",
                                  bg=GREEN, fg=WHITE, font=("Segoe UI",10,"bold"),
                                  relief="flat", cursor="hand2", padx=12, pady=8,
                                  command=self._run_scan, state=tk.DISABLED)
        self._run_btn.pack(fill=tk.X, pady=(0,4))
        self._stop_btn = tk.Button(btn_frame, text="⏹  STOP",
                                   bg="#8b1a1a", fg=WHITE, font=("Segoe UI",10,"bold"),
                                   relief="flat", cursor="hand2", padx=12, pady=8,
                                   command=self._stop_scan, state=tk.DISABLED)
        self._stop_btn.pack(fill=tk.X, pady=(0,6))
        tk.Button(btn_frame, text="✕  Clear", bg=DARK2, fg=MUTED,
                  font=("Segoe UI",9), relief="flat", cursor="hand2", padx=8, pady=5,
                  command=self._clear_all).pack(fill=tk.X)

        top.columnconfigure(0, weight=1)

        # Progress
        prog_frame = tk.Frame(main, bg=DARK, pady=0, padx=18)
        prog_frame.pack(fill=tk.X)
        self._progress = ttk.Progressbar(prog_frame, mode="indeterminate", length=200)
        self._status_lbl = tk.Label(prog_frame, text="", bg=DARK, fg=MUTED,
                                    font=("Segoe UI",9))
        self._status_lbl.pack(side=tk.LEFT)

        # KPI bar
        kpi_bar = tk.Frame(main, bg=DARK, padx=18, pady=8)
        kpi_bar.pack(fill=tk.X)
        self._kpis = {}
        for label, color, key in [
            ("VULNERABLE", RED, "VULNERABLE"),
            ("WARNING",    AMBER, "WARNING"),
            ("SAFE",       GREEN_L, "SAFE"),
            ("INFO",       BLUE, "INFO"),
            ("TOTAL",      WHITE, "TOTAL"),
        ]:
            kf = tk.Frame(kpi_bar, bg=CARD, padx=14, pady=8)
            kf.pack(side=tk.LEFT, padx=(0,8))
            n = tk.Label(kf, text="0", bg=CARD, fg=color, font=("Segoe UI",18,"bold"))
            n.pack()
            tk.Label(kf, text=label, bg=CARD, fg=MUTED, font=("Segoe UI",8,"bold")).pack()
            self._kpis[key] = n

        # Results area
        res_hdr = tk.Frame(main, bg="#0a0a0a", padx=18, pady=6)
        res_hdr.pack(fill=tk.X)
        tk.Label(res_hdr, text="RESULTS", bg="#0a0a0a", fg=GREEN_L,
                 font=("Segoe UI",8,"bold")).pack(side=tk.LEFT)

        btn_r = tk.Frame(res_hdr, bg="#0a0a0a")
        btn_r.pack(side=tk.RIGHT)
        tk.Button(btn_r, text="↓ Export TXT", bg=DARK2, fg=GREEN_L,
                  font=("Segoe UI",9), relief="flat", cursor="hand2",
                  padx=10, pady=4, command=self._export_txt).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_r, text="↓ Export CSV", bg=DARK2, fg=GREEN_L,
                  font=("Segoe UI",9), relief="flat", cursor="hand2",
                  padx=10, pady=4, command=self._export_csv).pack(side=tk.LEFT, padx=4)
        tk.Button(btn_r, text="✕ Clear results", bg=DARK2, fg=RED,
                  font=("Segoe UI",9), relief="flat", cursor="hand2",
                  padx=10, pady=4, command=self._clear_results).pack(side=tk.LEFT, padx=4)

        # Results table with scrollbar
        tbl_frame = tk.Frame(main, bg="#0a0a0a", padx=18, pady=12)
        tbl_frame.pack(fill=tk.BOTH, expand=True)

        style = ttk.Style()
        style.theme_use("default")
        style.configure("Dark.Treeview",
                         background="#0a0a0a", foreground=TEXT,
                         fieldbackground="#0a0a0a", rowheight=28,
                         font=("Segoe UI",10))
        style.configure("Dark.Treeview.Heading",
                         background="#111111", foreground=GREEN_L,
                         font=("Segoe UI",9,"bold"), relief="flat")
        style.map("Dark.Treeview", background=[("selected","#1a3a6e")])

        cols = ("status","target","port","detail","tool","time")
        self._tree = ttk.Treeview(tbl_frame, columns=cols, show="headings",
                                   style="Dark.Treeview")
        self._sort_state = {}   # col -> ascending bool

        col_defs = [
            ("status","Status ▲▼",90), ("target","Target ▲▼",200),
            ("port","Port ▲▼",55), ("detail","Detail ▲▼",480),
            ("tool","Tool ▲▼",140), ("time","Time ▲▼",90),
        ]
        for col, hdr, w in col_defs:
            self._tree.heading(col, text=hdr,
                               command=lambda c=col: self._sort_column(c))
            self._tree.column(col, width=w, minwidth=40)

        self._tree.tag_configure("VULNERABLE", foreground=RED)
        self._tree.tag_configure("WARNING",    foreground=AMBER)
        self._tree.tag_configure("SAFE",       foreground=GREEN_L)
        self._tree.tag_configure("INFO",       foreground=BLUE)
        self._tree.tag_configure("ERROR",      foreground=MUTED)

        vsb = ttk.Scrollbar(tbl_frame, orient="vertical",   command=self._tree.yview)
        hsb = ttk.Scrollbar(tbl_frame, orient="horizontal",  command=self._tree.xview)
        self._tree.configure(yscroll=vsb.set, xscroll=hsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tbl_frame.rowconfigure(0, weight=1)
        tbl_frame.columnconfigure(0, weight=1)

        self._current_tool = None

        # Wire search box live filtering
        def _on_search(*_):
            val = self._search_var.get()
            if val == "Search tools…": val = ""
            self._filter_tools(val)
        self._search_var.trace_add("write", _on_search)

    # ── SEARCH FILTER ─────────────────────────────────────────────────────
    def _filter_tools(self, query):
        q = query.strip().lower()
        is_searching = bool(q) and q != "search tools…"

        for group, (grp_hdr, items_frame, collapsed) in self._group_frames.items():
            group_has_match = False
            for key, btn in self._tool_btns.items():
                # Only check buttons in this group's items_frame
                if str(btn.master) != str(items_frame):
                    continue
                name = self._tool_names.get(key, "")
                match = (not is_searching) or (q in name) or (q in group.lower())
                if match:
                    btn.pack(fill=tk.X, padx=2, pady=1)
                    group_has_match = True
                else:
                    btn.pack_forget()

            if is_searching:
                if group_has_match:
                    grp_hdr.pack(fill=tk.X, padx=4, pady=(10,0))
                    items_frame.pack(fill=tk.X, padx=2)
                    collapsed.set(False)
                else:
                    grp_hdr.pack_forget()
                    items_frame.pack_forget()
            else:
                # Restore normal layout — show all groups, respect collapsed state
                grp_hdr.pack(fill=tk.X, padx=4, pady=(10,0))
                if not collapsed.get():
                    items_frame.pack(fill=tk.X, padx=2)

        self._tool_frame.update_idletasks()
        self._sb_canvas.configure(scrollregion=self._sb_canvas.bbox("all"))
        self._sb_canvas.yview_moveto(0)

    # ── SORT COLUMN ───────────────────────────────────────────────────────
    def _sort_column(self, col):
        asc = not self._sort_state.get(col, False)
        self._sort_state[col] = asc

        # Pull all rows out
        rows = [(self._tree.set(iid, col), iid) for iid in self._tree.get_children("")]

        # Sort — port column numeric, others string
        STATUS_ORDER = {"VULNERABLE":0,"WARNING":1,"INFO":2,"SAFE":3,"ERROR":4}
        if col == "port":
            rows.sort(key=lambda x: int(x[0]) if x[0].isdigit() else 0, reverse=not asc)
        elif col == "status":
            rows.sort(key=lambda x: STATUS_ORDER.get(x[0], 9), reverse=not asc)
        else:
            rows.sort(key=lambda x: x[0].lower(), reverse=not asc)

        for idx, (_, iid) in enumerate(rows):
            self._tree.move(iid, "", idx)

        # Update heading arrows
        col_labels = {
            "status":"Status","target":"Target","port":"Port",
            "detail":"Detail","tool":"Tool","time":"Time"
        }
        for c in ("status","target","port","detail","tool","time"):
            arrow = (" ↑" if asc else " ↓") if c == col else " ▲▼"
            self._tree.heading(c, text=col_labels[c]+arrow)

    # ── TOOL SELECTION ────────────────────────────────────────────────────
    def _select_tool(self, key):
        # Reset previous
        if self._current_tool and self._current_tool in self._tool_btns:
            self._tool_btns[self._current_tool].configure(bg=SIDEBAR)
        self._current_tool = key
        self._tool_btns[key].configure(bg=GREEN)
        _, name, port, _ = TOOL_BY_KEY[key]
        self._hdr_title.configure(text=name)
        self._port_var.set(str(port))
        self._run_btn.configure(state=tk.NORMAL)
        self._status_lbl.configure(text=f"Ready — {name}")

    # ── SCAN ──────────────────────────────────────────────────────────────
    def _run_scan(self):
        if self._running: return
        if not self._current_tool:
            messagebox.showwarning("No tool", "Please select a tool from the left panel.")
            return
        raw_targets = self._targets_box.get("1.0", tk.END).strip()
        targets = [l.strip() for l in raw_targets.splitlines()
                   if l.strip() and not l.strip().startswith("#")]
        if not targets:
            messagebox.showwarning("No targets", "Enter at least one IP/hostname/URL.")
            return
        # Parse multiport: "80,443,8080" or single "443"
        raw_port = self._port_var.get().strip()
        ports = []
        for p in raw_port.split(","):
            p = p.strip()
            if p:
                try:
                    ports.append(int(p))
                except ValueError:
                    messagebox.showerror("Invalid port", f"'{p}' is not a valid port number.")
                    return
        if not ports:
            messagebox.showerror("Invalid port", "Enter at least one port number.")
            return

        self._running = True
        self._stop_flag = False
        self._run_btn.configure(state=tk.DISABLED, text="⏳  Running…")
        self._stop_btn.configure(state=tk.NORMAL)
        self._progress.pack(side=tk.LEFT, pady=4)
        self._progress.start(12)
        multi = f"{len(ports)} ports" if len(ports) > 1 else f"port {ports[0]}"
        self._status_lbl.configure(text=f"Scanning {len(targets)} target(s) on {multi}…")

        tool_key = self._current_tool

        def worker():
            def emit(status, target, detail, port_used=ports[0]):
                if self._stop_flag:
                    return
                ts = datetime.datetime.now().strftime("%H:%M:%S")
                self._q.put(("row", status, target, str(port_used), detail, tool_key, ts))
            try:
                engine = ScanEngine(emit)
                engine.stop_flag = lambda: self._stop_flag
                for port in ports:
                    if self._stop_flag: break
                    # Patch emit to carry correct port for each run
                    def make_emit(p):
                        def _emit(status, target, detail):
                            if self._stop_flag: return
                            ts = datetime.datetime.now().strftime("%H:%M:%S")
                            self._q.put(("row", status, target, str(p), detail, tool_key, ts))
                        return _emit
                    engine.emit = make_emit(port)
                    engine.run(tool_key, targets, port)
            except Exception as e:
                self._q.put(("row","ERROR","engine",raw_port,str(e),tool_key,
                              datetime.datetime.now().strftime("%H:%M:%S")))
            finally:
                self._q.put(("done",))

        threading.Thread(target=worker, daemon=True).start()

    # ── STOP SCAN ─────────────────────────────────────────────────────────
    def _stop_scan(self):
        if self._running:
            self._stop_flag = True
            self._stop_btn.configure(state=tk.DISABLED, text="Stopping…")
            self._status_lbl.configure(text="⏹ Stop requested — finishing current target…")

    # ── POLL QUEUE ────────────────────────────────────────────────────────
    def _poll(self):
        try:
            while True:
                msg = self._q.get_nowait()
                if msg[0] == "done":
                    self._running = False
                    self._stop_flag = False
                    self._run_btn.configure(state=tk.NORMAL, text="▶  RUN SCAN")
                    self._stop_btn.configure(state=tk.DISABLED, text="⏹  STOP")
                    self._progress.stop()
                    self._progress.pack_forget()
                    self._status_lbl.configure(
                        text=f"Scan complete — {len(self._results)} result(s)")
                    self._save_output()
                elif msg[0] == "row":
                    _, status, target, port, detail, tool, ts = msg
                    row = {"status":status,"target":target,"port":port,
                           "detail":detail,"tool":tool,"time":ts}
                    self._results.append(row)
                    iid = self._tree.insert("", tk.END,
                        values=(status, target, port, detail, tool, ts),
                        tags=(status,))
                    self._tree.see(iid)
                    self._update_kpis()
        except queue.Empty:
            pass
        self.after(80, self._poll)

    # ── HELPERS ───────────────────────────────────────────────────────────
    def _update_count(self, _=None):
        lines = [l for l in self._targets_box.get("1.0",tk.END).splitlines()
                 if l.strip() and not l.strip().startswith("#")]
        self._count_lbl.configure(text=str(len(lines)))

    def _update_kpis(self):
        counts = {"VULNERABLE":0,"WARNING":0,"SAFE":0,"INFO":0,"TOTAL":len(self._results),"ERROR":0}
        for r in self._results:
            if r["status"] in counts: counts[r["status"]] += 1
        for k, lbl in self._kpis.items():
            lbl.configure(text=str(counts.get(k,0)))
        self._hdr_chip.configure(text=f"{len(self._results)} results")

    def _save_output(self):
        if not self._results: return
        tool = self._current_tool or "scan"
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(OUTPUT_DIR, f"{tool}_{ts}.txt")
        try:
            with open(path,"w",encoding="utf-8") as f:
                f.write(f"RevalPack — {TOOL_BY_KEY.get(tool,('',tool,'',''))[1]}\n")
                f.write(f"Generated: {datetime.datetime.now()}\n{'='*60}\n\n")
                for r in self._results:
                    f.write(f"[{r['status']}] {r['target']}:{r['port']} — {r['detail']} ({r['tool']})\n")
            self._status_lbl.configure(text=f"Scan complete — saved to revalpack_output/{os.path.basename(path)}")
        except Exception as e:
            self._status_lbl.configure(text=f"Save failed: {e}")

    def _export_txt(self):
        if not self._results:
            messagebox.showinfo("No results","Run a scan first."); return
        path = filedialog.asksaveasfilename(defaultextension=".txt",
            filetypes=[("Text","*.txt")],
            initialfile=f"revalpack_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        if not path: return
        with open(path,"w",encoding="utf-8") as f:
            f.write("RevalPack — Security Scan Report\n")
            f.write(f"Suprit Mangde · Offensive Security\n")
            f.write(f"Generated: {datetime.datetime.now()}\n{'='*60}\n\n")
            counts = {s:sum(1 for r in self._results if r['status']==s) for s in ["VULNERABLE","WARNING","SAFE","INFO"]}
            f.write(f"Total: {len(self._results)}  Vulnerable: {counts['VULNERABLE']}  Warning: {counts['WARNING']}  Safe: {counts['SAFE']}\n\n")
            for status in ("VULNERABLE","WARNING","SAFE","INFO"):
                grp = [r for r in self._results if r["status"]==status]
                if not grp: continue
                f.write(f"── {status} ({len(grp)}) {'─'*40}\n\n")
                for r in grp:
                    f.write(f"[{r['status']}] {r['target']} — {r['detail']} [{r['tool']}:{r['port']}] @ {r['time']}\n")
                f.write("\n")
        messagebox.showinfo("Exported", f"Report saved:\n{path}")

    def _export_csv(self):
        if not self._results:
            messagebox.showinfo("No results","Run a scan first."); return
        path = filedialog.asksaveasfilename(defaultextension=".csv",
            filetypes=[("CSV","*.csv")],
            initialfile=f"revalpack_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        if not path: return
        with open(path,"w",newline="",encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=["status","target","port","detail","tool","time"])
            w.writeheader(); w.writerows(self._results)
        messagebox.showinfo("Exported", f"CSV saved:\n{path}")

    def _clear_all(self):
        self._targets_box.delete("1.0",tk.END)
        self._count_lbl.configure(text="0")

    def _clear_results(self):
        if messagebox.askyesno("Clear","Clear all results from this session?"):
            self._results.clear()
            for item in self._tree.get_children(): self._tree.delete(item)
            self._update_kpis()

if __name__ == "__main__":
    app = RevalPackApp()
    app.mainloop()
