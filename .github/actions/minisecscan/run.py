#!/usr/bin/env python3
import argparse, json, re, sys
from enum import Enum
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup

# ---------- models ----------
class Severity(str, Enum):
    HIGH="HIGH"; MEDIUM="MEDIUM"; LOW="LOW"; INFO="INFO"

def finding(title, severity, description, remediation, evidence=""):
    return {
        "title": title,
        "severity": severity,
        "description": description,
        "remediation": remediation,
        "evidence": evidence
    }

# ---------- scoring ----------
def score_findings(findings):
    s = 100
    for f in findings:
        if f["severity"] == "HIGH": s -= 15
        elif f["severity"] == "MEDIUM": s -= 7
        elif f["severity"] == "LOW": s -= 2
    s = max(0, s)
    if s >= 90: grade = "A"
    elif s >= 75: grade = "B"
    elif s >= 60: grade = "C"
    else: grade = "D"
    return s, grade

# ---------- header analysis ----------
def analyze_headers(headers):
    h = {k.lower(): v for k,v in headers.items()}
    findings = []

    csp = h.get("content-security-policy")
    if not csp:
        findings.append(finding("Content-Security-Policy missing","HIGH",
                                "Define a strict CSP to reduce XSS risk.",
                                "Add CSP with nonces or hashes; avoid 'unsafe-inline'."))
    elif re.search(r"\bunsafe-inline\b", csp, re.I):
        findings.append(finding("CSP allows unsafe-inline","MEDIUM",
                                "Inline scripts permitted by CSP weaken protections.",
                                "Use nonces or hashes; remove 'unsafe-inline'.",
                                csp))

    hsts = h.get("strict-transport-security")
    if not hsts:
        findings.append(finding("HSTS missing","HIGH",
                                "HSTS forces HTTPS to prevent downgrade/mitm.",
                                "Set Strict-Transport-Security with long max-age; includeSubDomains; consider preload."))
    elif "max-age=" not in hsts:
        findings.append(finding("HSTS incomplete","MEDIUM",
                                "HSTS present but missing max-age.",
                                "Set max-age=31536000; includeSubDomains; preload.",
                                hsts))

    xcto = h.get("x-content-type-options","").lower()
    if xcto != "nosniff":
        findings.append(finding("X-Content-Type-Options missing","MEDIUM",
                                "Prevents MIME-type sniffing.",
                                "Set X-Content-Type-Options: nosniff."))

    xfo = h.get("x-frame-options")
    if not xfo and not (csp and re.search(r"\bframe-ancestors\b", csp, re.I)):
        findings.append(finding("Clickjacking protection missing","MEDIUM",
                                "No X-Frame-Options or CSP frame-ancestors found.",
                                "Use X-Frame-Options: DENY or SAMEORIGIN, or CSP frame-ancestors."))

    refp = h.get("referrer-policy")
    if not refp:
        findings.append(finding("Referrer-Policy missing","LOW",
                                "Controls sensitive referrer leakage.",
                                "Use strict-origin-when-cross-origin or no-referrer."))

    perm = h.get("permissions-policy") or h.get("feature-policy")
    if not perm:
        findings.append(finding("Permissions-Policy missing","LOW",
                                "Disable unneeded browser features.",
                                "Set Permissions-Policy to restrict camera, mic, geolocation, etc."))

    # cookies
    sc = h.get("set-cookie", "")
    if sc:
        # naive cookie split
        parts = re.split(r",\s*(?=[^;,\s]+=)", sc)
        for c in parts:
            if re.search(r"\bsamesite\s*=\s*none\b", c, re.I) and not re.search(r"\bsecure\b", c, re.I):
                findings.append(finding("Cookie SameSite=None without Secure","HIGH",
                                        "Modern browsers reject SameSite=None unless Secure is set.",
                                        "Add Secure to cookies with SameSite=None.",
                                        c.strip()))
            if not re.search(r"\bhttponly\b", c, re.I):
                findings.append(finding("Cookie missing HttpOnly","MEDIUM",
                                        "Without HttpOnly, JS can read cookies if XSS occurs.",
                                        "Add HttpOnly to session cookies.",
                                        c.strip()))
    return findings

# ---------- DOM/content analysis ----------
def analyze_dom(html, base_url=None):
    findings = []
    soup = BeautifulSoup(html or "", "html.parser")

    # mixed content heuristic (if base scheme is https)
    if base_url and urlparse(base_url).scheme == "https":
        for el in soup.find_all(src=True):
            if str(el["src"]).startswith("http://"):
                findings.append(finding("Mixed content (src)","HIGH",
                                        "HTTPS page loads asset over HTTP.",
                                        "Serve assets via HTTPS.",
                                        el["src"]))
                break
        for el in soup.find_all(href=True):
            if str(el["href"]).startswith("http://"):
                findings.append(finding("Mixed content (href)","HIGH",
                                        "HTTPS page links critical asset over HTTP.",
                                        "Serve assets via HTTPS.",
                                        el["href"]))
                break

    # inline scripts + CSP meta
    inline_scripts = len([s for s in soup.find_all("script") if not s.get("src")])
    csp_meta = soup.find("meta", attrs={"http-equiv": "Content-Security-Policy"})
    if inline_scripts > 0 and csp_meta:
        if re.search(r"\bunsafe-inline\b", csp_meta.get("content",""), re.I):
            findings.append(finding("CSP allows unsafe-inline (meta)","MEDIUM",
                                    "Inline scripts allowed by CSP meta tag.",
                                    "Use nonces or hashes; remove 'unsafe-inline'.",
                                    f"inline_scripts={inline_scripts}"))

    # forms: password + GET or insecure action; CSRF token heuristic
    for form in soup.find_all("form"):
        method = (form.get("method") or "get").lower()
        action = (form.get("action") or "").strip()
        has_pwd = form.find("input", attrs={"type": "password"}) is not None
        if has_pwd and method == "get":
            findings.append(finding("Password form uses GET","HIGH",
                                    "Credentials should not be sent in query string.",
                                    "Use POST for authentication forms."))
        if has_pwd and action.startswith("http://"):
            findings.append(finding("Password form posts to HTTP","HIGH",
                                    "Credentials posted to insecure endpoint.",
                                    "Post to HTTPS only.", action))
        if method == "post":
            has_csrf = any(("csrf" in ((i.get("name") or "") + (i.get("id") or "")).lower()) for i in form.find_all("input"))
            if not has_csrf:
                findings.append(finding("Possible missing CSRF token","MEDIUM",
                                        "No obvious CSRF token in POST form.",
                                        "Implement CSRF tokens for state-changing requests."))

    # un-sandboxed iframes
    for ifr in soup.find_all("iframe"):
        if not ifr.get("sandbox"):
            findings.append(finding("Iframe without sandbox","LOW",
                                    "Unrestricted iframes can enable clickjacking or privilege issues.",
                                    "Add sandbox and allow only required capabilities.",
                                    ifr.get("src","")))

    # third-party scripts list
    third = set()
    try:
        base_host = urlparse(base_url).hostname if base_url else None
        for s in soup.find_all("script", src=True):
            host = urlparse(s["src"]).hostname
            if host and base_host and host != base_host:
                third.add(host)
    except Exception:
        pass
    if third:
        findings.append(finding("Third-party script hosts detected","INFO",
                                "External scripts increase supply-chain risk.",
                                "Limit third-party scripts or pin versions; consider SRI.",
                                ", ".join(sorted(third))))
    return findings

# ---------- fetch ----------
def fetch_url(url):
    try:
        resp = requests.get(url, timeout=12, allow_redirects=True, headers={"User-Agent":"MiniSecScan/CI"})
        return resp
    except Exception as e:
        return e

# ---------- main ----------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default=None)
    ap.add_argument("--file", default=None)
    ap.add_argument("--min-score", type=int, default=75)
    ap.add_argument("--fail-on", choices=["NONE","LOW","MEDIUM","HIGH"], default="HIGH")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    if not args.url and not args.file:
        print("Provide --url or --file", file=sys.stderr)
        sys.exit(3)

    base_url = None
    headers = {}
    html = ""

    if args.url:
        base_url = args.url if args.url.startswith(("http://","https://")) else "https://" + args.url
        got = fetch_url(base_url)
        if isinstance(got, Exception):
            # network failure counts as findings but keeps the job deterministic
            findings = [finding("Fetch failed","HIGH","Target URL could not be fetched.","Ensure the URL is reachable from CI.", str(got))]
            score, grade = score_findings(findings)
            report = {"url": base_url, "mode":"url", "score": score, "grade": grade, "findings": findings}
            with open(args.out,"w") as f: json.dump(report, f, indent=2)
            return exit_with_policy(report, args)
        headers = got.headers
        html = got.text
    else:
        base_url = None
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            html = f.read()

    findings = []
    findings += analyze_dom(html, base_url)
    findings += analyze_headers(headers) if headers else []

    score, grade = score_findings(findings)
    report = {
        "url": base_url or args.file,
        "mode": "url" if args.url else "file",
        "score": score,
        "grade": grade,
        "findings": findings
    }
    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)

    exit_with_policy(report, args)

def exit_with_policy(report, args):
    # write summary table for job log
    print("MiniSecScan Score:", report["score"], report["grade"])
    print("Findings:", len(report["findings"]))
    # policy checks
    sev_order = {"NONE":0,"LOW":1,"MEDIUM":2,"HIGH":3}
    worst = "NONE"
    for f in report["findings"]:
        if sev_order[f["severity"]] > sev_order[worst]:
            worst = f["severity"]
    fail = False
    if report["score"] < args.min_score:
        fail = True
        print(f"::error title=Score below threshold::{report['score']} < {args.min_score}")
    if sev_order[worst] >= sev_order[args.fail_on] and args.fail_on != "NONE":
        fail = True
        print(f"::error title=Severity threshold tripped::Worst={worst} (fail_on={args.fail_on})")
    sys.exit(1 if fail else 0)

if __name__ == "__main__":
    main()
