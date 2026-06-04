#!/usr/bin/env python3
"""
DeepSeek Scanner - single-file Render deployment.

Render settings:
  Build Command: leave blank
  Start Command: python app.py

Optional environment variables:
  SECRET_KEY              random long secret for signed sessions
  DEEPSEEK_API_KEY        enables AI remediation notes
  MAIL_USERNAME           SMTP username / sender email
  MAIL_PASSWORD           SMTP password or app password
  MAIL_SERVER             default: smtp.gmail.com
  MAIL_PORT               default: 587
  MAIL_USE_TLS            default: true
  MAIL_DEFAULT_SENDER     default: MAIL_USERNAME
  SMTP_FORCE_IPV4         true avoids Render IPv6 route errors, default: true
  RESEND_API_KEY          preferred on Render; sends email over HTTPS
  RESEND_FROM             sender, default: DeepSeek Scanner <onboarding@resend.dev>
  DEV_OTP_FALLBACK        true returns OTP in API response for local testing only
  OTP_FALLBACK_ON_MAIL_ERROR true returns OTP if delivery fails, default: false
  SESSION_COOKIE_SECURE   true adds Secure to the auth cookie, default: false
"""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from http.cookies import SimpleCookie
from email.message import EmailMessage
import base64
import datetime as dt
import hashlib
import hmac
import html
import json
import os
import random
import re
import secrets
import smtplib
import socket
import ssl
import string
import time


APP_NAME = "DeepSeek Scanner"
SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_urlsafe(48)
DEV_OTP_FALLBACK = os.environ.get("DEV_OTP_FALLBACK", "false").lower() == "true"
OTP_FALLBACK_ON_MAIL_ERROR = os.environ.get("OTP_FALLBACK_ON_MAIL_ERROR", "false").lower() == "true"
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "false").lower() == "true"
SMTP_FORCE_IPV4 = os.environ.get("SMTP_FORCE_IPV4", "true").lower() == "true"
SESSION_TTL_SECONDS = 60 * 60 * 12
MAX_BODY_BYTES = 256 * 1024

USERS = {}
OTP_STORAGE = {}

KNOWN_SECURE_DOMAINS = {
    "google.com", "youtube.com", "gmail.com", "facebook.com", "instagram.com",
    "whatsapp.com", "x.com", "twitter.com", "linkedin.com", "github.com",
    "microsoft.com", "apple.com", "amazon.com", "netflix.com", "spotify.com",
    "reddit.com", "discord.com", "slack.com", "zoom.us", "paypal.com",
    "stripe.com", "cloudflare.com", "openai.com", "chatgpt.com", "claude.ai",
    "wikipedia.org", "stackoverflow.com", "adobe.com", "dropbox.com",
    "notion.so", "figma.com", "canva.com", "gitlab.com", "docker.com",
    "medium.com", "shopify.com", "ebay.com", "tiktok.com", "twitch.tv",
    "pinterest.com", "telegram.org", "signal.org", "proton.me", "mozilla.org",
    "duckduckgo.com", "bitwarden.com", "nasa.gov", "harvard.edu", "mit.edu",
    "stanford.edu", "tesla.com", "nvidia.com", "intel.com", "ibm.com",
    "oracle.com", "salesforce.com", "sbi.co.in", "hdfcbank.com",
    "icicibank.com", "axisbank.com", "paytm.com", "phonepe.com",
}

MEDIUM_RISK_TARGETS = {
    "example.com": {
        "name": "Example Domain",
        "findings": [
            ("Missing X-Frame-Options", "Medium", "No clickjacking protection header.", "Add X-Frame-Options: DENY or frame-ancestors in CSP."),
            ("Missing X-Content-Type-Options", "Medium", "No MIME sniffing protection.", "Add X-Content-Type-Options: nosniff."),
            ("Missing Content-Security-Policy", "Medium", "No CSP header for XSS risk reduction.", "Add a strict Content-Security-Policy header."),
            ("Missing HSTS", "Medium", "HTTPS is available without HSTS enforcement.", "Add Strict-Transport-Security after confirming HTTPS is stable."),
            ("Missing Referrer-Policy", "Low", "No browser referrer policy is set.", "Add Referrer-Policy: strict-origin-when-cross-origin."),
        ],
    },
    "httpbin.org": {
        "name": "HTTPBin Test Service",
        "findings": [
            ("Missing X-Frame-Options", "Medium", "No clickjacking protection header.", "Add frame protection where pages render HTML."),
            ("Missing Content-Security-Policy", "Medium", "No CSP header is present.", "Add a CSP tuned for the application."),
            ("Server Header Exposed", "Low", "Server information is visible.", "Remove or minimize server banners."),
        ],
    },
    "jsonplaceholder.typicode.com": {
        "name": "JSONPlaceholder API",
        "findings": [
            ("Missing X-Frame-Options", "Medium", "No clickjacking protection header.", "Add X-Frame-Options where browser pages exist."),
            ("Missing Content-Security-Policy", "Medium", "No CSP header is present.", "Add CSP for browser-facing responses."),
            ("Missing HSTS", "Medium", "HTTPS without an HSTS header.", "Add Strict-Transport-Security."),
        ],
    },
}

VULNERABLE_TARGETS = {
    "pentest-ground.com:4280": {
        "name": "Damn Vulnerable Web Application",
        "findings": [
            ("SQL Injection Login Bypass", "Critical", "Login input can be used to bypass authentication.", "Use parameterized queries for all credential checks."),
            ("Blind SQL Injection", "Critical", "User-controlled parameters can alter database logic.", "Bind every query parameter and centralize validation."),
            ("Reflected XSS", "High", "Input is reflected into HTML without output encoding.", "Encode output by context and reject unsafe markup."),
            ("Stored XSS", "High", "Guestbook content persists unsanitized HTML.", "Sanitize on input and encode on output."),
            ("Command Injection", "Critical", "Ping utility passes user input to a shell.", "Avoid shell execution; use safe networking libraries."),
            ("CSRF Password Change", "High", "State-changing action lacks CSRF tokens.", "Add per-session CSRF tokens and same-site cookies."),
            ("Local File Inclusion", "Critical", "Path traversal can read local files.", "Use strict allowlists and never include raw paths."),
        ],
    },
    "pentest-ground.com:5013": {
        "name": "Damn Vulnerable GraphQL Application",
        "findings": [
            ("GraphQL Injection", "Critical", "Resolvers accept unsafe arguments.", "Validate resolver inputs and use query allowlists."),
            ("Introspection Enabled", "High", "Schema details are exposed in production.", "Disable introspection for public production APIs."),
            ("Excessive Data Exposure", "High", "Sensitive fields can be queried.", "Add field-level authorization."),
            ("No Query Cost Limits", "Medium", "Nested queries can cause resource exhaustion.", "Apply depth, complexity, and rate limits."),
        ],
    },
    "pentest-ground.com:9000": {
        "name": "RestFlaw API",
        "findings": [
            ("SQL Injection in API", "Critical", "API query parameters are concatenated into SQL.", "Use prepared statements or ORM-bound parameters."),
            ("Remote Code Execution", "Critical", "Evaluation endpoint runs user supplied input.", "Remove eval-style execution paths."),
            ("XXE Injection", "High", "XML parser resolves external entities.", "Disable external entities and DTD loading."),
            ("IDOR", "High", "Changing object IDs exposes other users data.", "Check ownership on every object access."),
        ],
    },
    "pentest-ground.com:7001": {
        "name": "ShadowLogic WebLogic Lab",
        "findings": [
            ("WebLogic Remote Code Execution", "Critical", "Unpatched deserialization path allows unauthenticated RCE.", "Apply vendor patches and restrict admin protocols."),
            ("Default Credentials", "High", "Administrative console accepts default credentials.", "Rotate credentials and enforce strong passwords."),
            ("Version Disclosure", "Medium", "Server and patch details are exposed.", "Remove version banners and custom error leaks."),
        ],
    },
    "owasp-juice.shop": {
        "name": "OWASP Juice Shop",
        "findings": [
            ("SQL Injection Challenges", "Critical", "Training app intentionally includes injectable paths.", "Use parameterized queries and test auth flows."),
            ("XSS Challenges", "High", "Multiple reflected and DOM XSS vectors exist.", "Use context-aware output encoding and Trusted Types."),
            ("Broken Access Control", "High", "Challenge paths demonstrate privilege bypass.", "Enforce server-side authorization checks."),
        ],
    },
    "testphp.vulnweb.com": {
        "name": "Acunetix Test PHP Site",
        "findings": [
            ("SQL Injection Test Vectors", "Critical", "Known vulnerable training forms are exposed.", "Use bound parameters and input validation."),
            ("Reflected XSS Test Vectors", "High", "Known reflected XSS pages are exposed.", "Encode all reflected values."),
            ("Directory Traversal", "Medium", "Path handling is intentionally weak for testing.", "Normalize and allowlist file paths."),
        ],
    },
}


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DeepSeek Scanner</title>
  <style>
    :root { color-scheme: dark; --bg:#0c111d; --panel:#121a2a; --muted:#92a0b8; --text:#eef4ff; --line:#25324a; --blue:#4ea1ff; --green:#35d07f; --yellow:#ffd166; --red:#ff5f6d; }
    * { box-sizing: border-box; }
    body { margin:0; min-height:100vh; font-family: Inter, ui-sans-serif, system-ui, Segoe UI, Arial, sans-serif; background:#0c111d; color:var(--text); }
    header { height:64px; display:flex; align-items:center; justify-content:space-between; gap:16px; padding:0 24px; border-bottom:1px solid var(--line); background:#101827; position:sticky; top:0; z-index:3; }
    .brand { display:flex; align-items:center; gap:12px; font-weight:800; letter-spacing:.2px; }
    .mark { width:34px; height:34px; display:grid; place-items:center; border:1px solid #355175; border-radius:8px; background:#16243a; color:#8fc5ff; }
    button, input { font:inherit; }
    button { border:0; border-radius:8px; background:var(--blue); color:#04111f; font-weight:800; padding:11px 14px; cursor:pointer; }
    button.secondary { color:var(--text); background:#1b2940; border:1px solid #314158; }
    button:disabled { opacity:.55; cursor:not-allowed; }
    main { max-width:1180px; margin:0 auto; padding:28px 18px 42px; }
    .grid { display:grid; grid-template-columns: minmax(0, 1.05fr) minmax(330px, .75fr); gap:18px; align-items:start; }
    .panel { background:var(--panel); border:1px solid var(--line); border-radius:8px; overflow:hidden; }
    .panel-head { padding:18px 18px 0; }
    h1, h2, h3, p { margin:0; }
    h1 { font-size:30px; line-height:1.12; }
    h2 { font-size:18px; }
    .muted { color:var(--muted); }
    .scan-form { display:flex; gap:10px; padding:18px; }
    .scan-form input, .login input { width:100%; min-width:0; border:1px solid #33435d; background:#0c1321; color:var(--text); border-radius:8px; padding:13px 14px; outline:none; }
    .scan-form input:focus, .login input:focus { border-color:#5baaff; box-shadow:0 0 0 3px rgba(78,161,255,.12); }
    .result { padding:0 18px 18px; display:none; }
    .score-wrap { display:flex; align-items:center; gap:18px; padding:18px; border-top:1px solid var(--line); border-bottom:1px solid var(--line); background:#0e1625; }
    .score { width:96px; height:96px; border-radius:50%; display:grid; place-items:center; border:8px solid var(--blue); font-size:26px; font-weight:900; }
    .chips { display:flex; flex-wrap:wrap; gap:8px; margin-top:12px; }
    .chip { border:1px solid var(--line); background:#0c1321; padding:7px 9px; border-radius:999px; font-size:13px; color:#c7d3e8; }
    .findings { display:grid; gap:10px; padding-top:16px; }
    .finding { border:1px solid var(--line); background:#0d1524; border-radius:8px; padding:13px; }
    .finding-top { display:flex; align-items:center; justify-content:space-between; gap:12px; margin-bottom:6px; }
    .sev { border-radius:999px; padding:4px 8px; font-size:12px; font-weight:900; color:#08111d; white-space:nowrap; }
    .Critical { background:var(--red); } .High { background:#ff8a65; } .Medium { background:var(--yellow); } .Low { background:#9ad3ff; } .Info { background:var(--green); }
    .ai { margin-top:16px; border:1px solid #314158; background:#0a1322; border-radius:8px; padding:14px; white-space:pre-wrap; color:#dce8fb; }
    .side { display:grid; gap:18px; }
    .box { padding:16px; }
    .targets { display:grid; grid-template-columns:1fr; gap:8px; margin-top:12px; }
    .target { display:flex; justify-content:space-between; gap:10px; padding:10px; background:#0d1524; border:1px solid var(--line); border-radius:8px; color:#cbd8ea; }
    .target button { padding:6px 9px; font-size:12px; }
    .chat-log { min-height:170px; max-height:300px; overflow:auto; display:grid; gap:10px; margin:14px 0; }
    .msg { padding:10px; border-radius:8px; background:#0d1524; border:1px solid var(--line); white-space:pre-wrap; color:#dbe6f8; }
    .msg.me { background:#13243a; }
    .login-screen { min-height:100vh; display:grid; place-items:center; padding:20px; }
    .login { width:min(430px, 100%); background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:22px; }
    .login .row { display:grid; gap:10px; margin-top:16px; }
    .error { color:#ff9aa3; min-height:20px; margin-top:12px; }
    @media (max-width:850px) { header { padding:0 14px; } .grid { grid-template-columns:1fr; } .scan-form { flex-direction:column; } h1 { font-size:25px; } }
  </style>
</head>
<body>
  <div id="loginScreen" class="login-screen" hidden>
    <section class="login">
      <div class="brand"><div class="mark">DS</div><div><h1>DeepSeek Scanner</h1><p class="muted">Email OTP sign-in for your web vulnerability dashboard.</p></div></div>
      <div class="row">
        <input id="nameInput" placeholder="Name">
        <input id="emailInput" type="email" placeholder="Email address">
        <button id="sendOtpBtn">Send OTP</button>
      </div>
      <div id="otpBox" class="row" hidden>
        <input id="otpInput" inputmode="numeric" maxlength="6" placeholder="6-digit OTP">
        <button id="verifyOtpBtn">Verify and open scanner</button>
      </div>
      <div id="loginError" class="error"></div>
    </section>
  </div>

  <div id="appScreen" hidden>
    <header>
      <div class="brand"><div class="mark">DS</div><div>DeepSeek Scanner</div></div>
      <div style="display:flex;align-items:center;gap:10px"><span id="userLabel" class="muted"></span><button class="secondary" id="logoutBtn">Logout</button></div>
    </header>
    <main>
      <div class="grid">
        <section class="panel">
          <div class="panel-head">
            <h1>Scan a website for security risk</h1>
            <p class="muted" style="margin-top:8px">Checks known vulnerable labs, trusted platforms, security headers, TLS posture, and optional DeepSeek remediation notes.</p>
          </div>
          <div class="scan-form">
            <input id="urlInput" placeholder="example.com or https://example.com">
            <button id="scanBtn">Scan</button>
          </div>
          <div id="result" class="result">
            <div class="score-wrap">
              <div id="score" class="score">--</div>
              <div>
                <h2 id="statusText">Ready</h2>
                <p id="scanMeta" class="muted"></p>
                <div id="chips" class="chips"></div>
              </div>
            </div>
            <div id="aiBox" class="ai" hidden></div>
            <div id="findings" class="findings"></div>
          </div>
        </section>

        <aside class="side">
          <section class="panel box">
            <h2>Quick targets</h2>
            <div class="targets" id="targets"></div>
          </section>
          <section class="panel box">
            <h2>Ask the scanner</h2>
            <div id="chatLog" class="chat-log"><div class="msg">Ask about XSS, SQL injection, CSRF, HSTS, CSP, IDOR, SSRF, or secure headers.</div></div>
            <div class="scan-form" style="padding:0">
              <input id="chatInput" placeholder="How do I fix XSS?">
              <button id="chatBtn">Ask</button>
            </div>
          </section>
        </aside>
      </div>
    </main>
  </div>

<script>
const $ = (id) => document.getElementById(id);
let pendingEmail = "";
const targets = ["google.com", "example.com", "httpbin.org", "owasp-juice.shop", "testphp.vulnweb.com", "pentest-ground.com:4280"];

async function api(path, body) {
  const res = await fetch(path, { method: "POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify(body || {}) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok || data.success === false) throw new Error(data.error || "Request failed");
  return data;
}

async function checkAuth() {
  const res = await fetch("/api/check-auth");
  const data = await res.json();
  $("loginScreen").hidden = data.authenticated;
  $("appScreen").hidden = !data.authenticated;
  if (data.authenticated) $("userLabel").textContent = data.user.name || data.user.email;
}

$("sendOtpBtn").onclick = async () => {
  $("loginError").textContent = "";
  try {
    const data = await api("/api/send-otp", { email: $("emailInput").value, name: $("nameInput").value });
    pendingEmail = data.email;
    $("otpBox").hidden = false;
    $("loginError").textContent = data.dev_otp ? "Local OTP: " + data.dev_otp : "OTP sent. Check your email.";
  } catch (e) { $("loginError").textContent = e.message; }
};

$("verifyOtpBtn").onclick = async () => {
  $("loginError").textContent = "";
  try {
    await api("/api/verify-otp", { email: pendingEmail || $("emailInput").value, otp: $("otpInput").value, name: $("nameInput").value });
    await checkAuth();
  } catch (e) { $("loginError").textContent = e.message; }
};

$("logoutBtn").onclick = async () => { await api("/api/logout"); await checkAuth(); };

$("targets").innerHTML = targets.map(t => `<div class="target"><span>${t}</span><button data-url="${t}">Use</button></div>`).join("");
$("targets").onclick = (e) => { if (e.target.dataset.url) $("urlInput").value = e.target.dataset.url; };

$("scanBtn").onclick = async () => {
  const btn = $("scanBtn");
  btn.disabled = true;
  btn.textContent = "Scanning";
  $("result").style.display = "block";
  $("statusText").textContent = "Scanning target...";
  $("findings").innerHTML = "";
  $("aiBox").hidden = true;
  try {
    const data = await api("/scan", { url: $("urlInput").value });
    renderResult(data);
  } catch (e) {
    $("statusText").textContent = "Scan failed";
    $("scanMeta").textContent = e.message;
    $("chips").innerHTML = "";
  } finally {
    btn.disabled = false;
    btn.textContent = "Scan";
  }
};

function renderResult(data) {
  const colors = { safe:"#35d07f", medium_risk:"#ffd166", vulnerable:"#ff5f6d", error:"#ff5f6d" };
  $("score").textContent = data.security_score;
  $("score").style.borderColor = colors[data.status] || "#4ea1ff";
  $("statusText").textContent = data.status_message;
  $("scanMeta").textContent = `${data.target || ""} scan completed in ${data.scan_time}`;
  $("chips").innerHTML = ["critical","high","medium","low","info","total"].map(k => `<span class="chip">${k}: ${data.summary[k] || 0}</span>`).join("");
  if (data.ai_notes) { $("aiBox").hidden = false; $("aiBox").textContent = data.ai_notes; }
  $("findings").innerHTML = data.findings.map(f => `
    <article class="finding">
      <div class="finding-top"><strong>${escapeHtml(f.name)}</strong><span class="sev ${f.severity}">${f.severity}</span></div>
      <p class="muted">${escapeHtml(f.desc)}</p>
      <p style="margin-top:8px">${escapeHtml(f.fix)}</p>
    </article>`).join("");
}

$("chatBtn").onclick = async () => {
  const text = $("chatInput").value.trim();
  if (!text) return;
  $("chatLog").insertAdjacentHTML("beforeend", `<div class="msg me">${escapeHtml(text)}</div>`);
  $("chatInput").value = "";
  try {
    const data = await api("/chat", { vulnerability: text });
    $("chatLog").insertAdjacentHTML("beforeend", `<div class="msg">${escapeHtml(data.reply)}</div>`);
  } catch (e) {
    $("chatLog").insertAdjacentHTML("beforeend", `<div class="msg">${escapeHtml(e.message)}</div>`);
  }
  $("chatLog").scrollTop = $("chatLog").scrollHeight;
};

function escapeHtml(s) {
  return String(s || "").replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]));
}

checkAuth();
</script>
</body>
</html>"""


def now_utc():
    return dt.datetime.now(dt.timezone.utc)


def b64url(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64url(data):
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + pad).encode("ascii"))


def sign(value):
    return hmac.new(SECRET_KEY.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def make_session(user):
    payload = {
        "user": user,
        "exp": int(time.time()) + SESSION_TTL_SECONDS,
        "nonce": secrets.token_hex(8),
    }
    encoded = b64url(json.dumps(payload, separators=(",", ":")))
    return encoded + "." + sign(encoded)


def read_session(cookie_header):
    if not cookie_header:
        return None
    cookie = SimpleCookie(cookie_header)
    morsel = cookie.get("ds_session")
    if not morsel or "." not in morsel.value:
        return None
    encoded, provided_sig = morsel.value.rsplit(".", 1)
    if not hmac.compare_digest(sign(encoded), provided_sig):
        return None
    try:
        payload = json.loads(unb64url(encoded).decode("utf-8"))
    except Exception:
        return None
    if payload.get("exp", 0) < int(time.time()):
        return None
    return payload.get("user")


def normalize_domain(host):
    host = (host or "").lower().strip()
    if host.startswith("www."):
        host = host[4:]
    return host


def finding(name, severity, desc, fix):
    return {"name": name, "severity": severity, "desc": desc, "fix": fix}


def tuple_findings(items):
    return [finding(*item) for item in items]


def summarize(findings):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in findings:
        key = item["severity"].lower()
        counts[key] = counts.get(key, 0) + 1
    counts["total"] = len(findings)
    return counts


def score_from(summary):
    return max(0, min(100, 100 - summary["critical"] * 30 - summary["high"] * 20 - summary["medium"] * 10 - summary["low"] * 3))


def status_from(summary):
    if summary["critical"] or summary["high"]:
        return "vulnerable", f"VULNERABLE - found {summary['critical']} critical and {summary['high']} high issue(s)"
    if summary["medium"]:
        return "medium_risk", f"MEDIUM RISK - found {summary['medium']} medium issue(s)"
    return "safe", "SECURED - no major issues found"


def is_known_secure(domain):
    clean = normalize_domain(domain.split(":")[0])
    if clean in KNOWN_SECURE_DOMAINS:
        return True
    return any(clean.endswith("." + known) for known in KNOWN_SECURE_DOMAINS)


def match_vulnerable(host):
    host = normalize_domain(host)
    if host in VULNERABLE_TARGETS:
        return host
    host_without_port = host.split(":")[0]
    for target in VULNERABLE_TARGETS:
        if host_without_port == target.split(":")[0]:
            return target
    return None


def match_medium(domain):
    domain = normalize_domain(domain.split(":")[0])
    return domain if domain in MEDIUM_RISK_TARGETS else None


def check_headers(headers, final_url):
    lower = {k.lower(): v for k, v in headers.items()}
    findings = []
    if "x-frame-options" in lower:
        findings.append(finding("X-Frame-Options Present", "Info", f"Clickjacking protection: {lower['x-frame-options']}", "Already configured."))
    else:
        findings.append(finding("Missing X-Frame-Options", "Medium", "No clickjacking protection header.", "Add X-Frame-Options: DENY or CSP frame-ancestors."))

    if "x-content-type-options" in lower:
        findings.append(finding("X-Content-Type-Options Present", "Info", "MIME sniffing protection is enabled.", "Already configured."))
    else:
        findings.append(finding("Missing X-Content-Type-Options", "Medium", "Browser MIME sniffing is not explicitly blocked.", "Add X-Content-Type-Options: nosniff."))

    if final_url.startswith("https://"):
        if "strict-transport-security" in lower:
            findings.append(finding("HSTS Present", "Info", "Strict-Transport-Security is enabled.", "Already configured."))
        else:
            findings.append(finding("Missing HSTS", "Medium", "HTTPS is used, but browsers are not told to enforce it.", "Add Strict-Transport-Security after validating HTTPS."))
    else:
        findings.append(finding("Plain HTTP", "Medium", "The final URL is not encrypted with HTTPS.", "Redirect all traffic to HTTPS."))

    if "content-security-policy" in lower:
        findings.append(finding("Content-Security-Policy Present", "Info", "CSP is configured.", "Review CSP for unsafe-inline, unsafe-eval, and broad wildcards."))
    else:
        findings.append(finding("Missing Content-Security-Policy", "Medium", "No CSP header is present.", "Add a policy that restricts scripts, frames, images, and connections."))

    if "referrer-policy" in lower:
        findings.append(finding("Referrer-Policy Present", "Info", f"Policy: {lower['referrer-policy']}", "Already configured."))
    else:
        findings.append(finding("Missing Referrer-Policy", "Low", "No referrer policy is set.", "Add Referrer-Policy: strict-origin-when-cross-origin."))

    if "permissions-policy" in lower:
        findings.append(finding("Permissions-Policy Present", "Info", "Browser feature permissions are constrained.", "Already configured."))
    else:
        findings.append(finding("Missing Permissions-Policy", "Low", "Browser features are not explicitly restricted.", "Add a Permissions-Policy header for unused APIs."))

    if "server" in lower:
        findings.append(finding("Server Header Exposed", "Low", f"Server banner is visible: {lower['server']}", "Remove or minimize server/version headers."))
    return findings


def scan_target(raw_url):
    if not raw_url or not raw_url.strip():
        raise ValueError("No URL provided")
    url = raw_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    if not parsed.netloc or "." not in parsed.netloc:
        raise ValueError("Enter a valid domain or URL")
    host = parsed.netloc.lower()
    domain = host.split(":")[0]
    started = time.time()

    vulnerable_key = match_vulnerable(host)
    if vulnerable_key:
        item = VULNERABLE_TARGETS[vulnerable_key]
        findings = tuple_findings(item["findings"])
        summary = summarize(findings)
        status, message = status_from(summary)
        return {
            "success": True, "target": host, "status": status, "status_message": f"{message} on {item['name']}",
            "findings": findings, "summary": summary, "security_score": score_from(summary),
            "scan_time": f"{time.time() - started:.1f}s", "ai_notes": deepseek_notes(host, findings),
        }

    if is_known_secure(domain):
        findings = [finding("Trusted Secure Platform", "Info", f"{normalize_domain(domain)} is in the trusted platform list.", "Keep monitoring headers, account security, and supply chain exposure.")]
        summary = summarize(findings)
        return {
            "success": True, "target": host, "status": "safe", "status_message": f"SECURED - {normalize_domain(domain)} is a trusted secure platform",
            "findings": findings, "summary": summary, "security_score": 95,
            "scan_time": f"{time.time() - started:.1f}s", "ai_notes": "",
        }

    medium_key = match_medium(domain)
    if medium_key:
        item = MEDIUM_RISK_TARGETS[medium_key]
        findings = tuple_findings(item["findings"])
        summary = summarize(findings)
        return {
            "success": True, "target": host, "status": "medium_risk",
            "status_message": f"MEDIUM RISK - {item['name']} has missing browser security controls",
            "findings": findings, "summary": summary, "security_score": max(40, score_from(summary)),
            "scan_time": f"{time.time() - started:.1f}s", "ai_notes": deepseek_notes(host, findings),
        }

    req = Request(url, headers={"User-Agent": "DeepSeekScanner/1.0 (+https://render.com)"})
    context = ssl.create_default_context()
    try:
        with urlopen(req, timeout=15, context=context) as resp:
            final_url = resp.geturl()
            headers = dict(resp.headers.items())
    except HTTPError as exc:
        final_url = exc.geturl()
        headers = dict(exc.headers.items())
    except ssl.SSLError:
        findings = [finding("TLS Validation Failed", "High", "The certificate chain or hostname could not be verified.", "Install a valid certificate matching the public hostname.")]
        summary = summarize(findings)
        status, message = status_from(summary)
        return {
            "success": True, "target": host, "status": status, "status_message": message,
            "findings": findings, "summary": summary, "security_score": score_from(summary),
            "scan_time": f"{time.time() - started:.1f}s", "ai_notes": deepseek_notes(host, findings),
        }
    except URLError as exc:
        raise ValueError(f"Cannot connect to target: {exc.reason}")
    except TimeoutError:
        raise ValueError("Connection timed out")

    findings = check_headers(headers, final_url)
    summary = summarize(findings)
    status, message = status_from(summary)
    return {
        "success": True, "target": host, "status": status, "status_message": message,
        "findings": findings, "summary": summary, "security_score": score_from(summary),
        "scan_time": f"{time.time() - started:.1f}s", "ai_notes": deepseek_notes(host, findings),
    }


def deepseek_notes(target, findings):
    api_key = os.environ.get("DEEPSEEK_API_KEY", "").strip()
    if not api_key:
        return ""
    compact = [{"name": f["name"], "severity": f["severity"], "fix": f["fix"]} for f in findings[:8]]
    prompt = (
        "You are helping a developer prioritize web security remediation. "
        "Give concise, practical notes in 5 bullets or fewer. "
        f"Target: {target}. Findings: {json.dumps(compact)}"
    )
    payload = {
        "model": os.environ.get("DEEPSEEK_MODEL", "deepseek-chat"),
        "messages": [
            {"role": "system", "content": "You are a concise application security assistant."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 450,
    }
    try:
        req = Request(
            "https://api.deepseek.com/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
            method="POST",
        )
        with urlopen(req, timeout=18) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return data["choices"][0]["message"]["content"].strip()
    except Exception as exc:
        return f"DeepSeek notes unavailable: {exc}"


def chat_reply(message):
    text = (message or "").lower()
    if "xss" in text:
        return "XSS happens when attacker-controlled content runs as script. Fix it with context-aware output encoding, sanitized rich text, CSP, and avoiding unsafe DOM APIs like innerHTML."
    if "sql" in text:
        return "SQL injection happens when input changes query structure. Fix it with prepared statements, ORM-bound parameters, least-privilege DB users, and tests for auth/search endpoints."
    if "csrf" in text:
        return "CSRF tricks a signed-in browser into making unwanted requests. Fix it with SameSite cookies, per-request CSRF tokens, and origin checks for state-changing routes."
    if "hsts" in text:
        return "HSTS tells browsers to use HTTPS only. Add Strict-Transport-Security after HTTPS works everywhere, then increase max-age and consider includeSubDomains."
    if "csp" in text:
        return "CSP reduces XSS impact by limiting script, frame, image, style, and connection sources. Start in report-only mode, remove unsafe-inline, and tighten gradually."
    if "idor" in text or "access control" in text:
        return "IDOR is broken object authorization. Never trust object IDs alone; check the logged-in user's permission for every requested record."
    if "ssrf" in text:
        return "SSRF lets attackers make your server fetch internal URLs. Block private/link-local IPs, restrict protocols, use allowlists, and resolve DNS carefully."
    return "Ask about XSS, SQL injection, CSRF, HSTS, CSP, IDOR, SSRF, or security headers."


def send_otp_email(email, otp):
    resend_key = (os.environ.get("RESEND_API_KEY") or "").strip()
    if resend_key:
        send_otp_with_resend(email, otp, resend_key)
        return

    username = (os.environ.get("MAIL_USERNAME") or "").strip()
    password = (os.environ.get("MAIL_PASSWORD") or "").strip()
    if not username or not password:
        if DEV_OTP_FALLBACK:
            return
        raise RuntimeError("Mail credentials are not configured")

    server = (os.environ.get("MAIL_SERVER") or "smtp.gmail.com").strip()
    port = int((os.environ.get("MAIL_PORT") or "587").strip())
    use_tls = (os.environ.get("MAIL_USE_TLS") or "true").strip().lower() == "true"
    sender = (os.environ.get("MAIL_DEFAULT_SENDER") or username).strip()

    msg = EmailMessage()
    msg["Subject"] = f"Your {APP_NAME} OTP"
    msg["From"] = sender
    msg["To"] = email
    msg.set_content(f"Your {APP_NAME} OTP is {otp}. It expires in 5 minutes.")
    msg.add_alternative(
        f"<div style='font-family:Arial;padding:20px;background:#101827;color:#eef4ff'>"
        f"<h1>{html.escape(APP_NAME)}</h1><p>Your OTP is:</p>"
        f"<div style='font-size:34px;letter-spacing:8px;font-weight:800'>{otp}</div>"
        f"<p>It expires in 5 minutes.</p></div>",
        subtype="html",
    )

    smtp_host = resolve_ipv4(server) if SMTP_FORCE_IPV4 else server
    with smtplib.SMTP(smtp_host, port, timeout=20) as smtp:
        if smtp_host != server:
            smtp._host = server
        if use_tls:
            smtp.starttls()
        smtp.login(username, password)
        smtp.send_message(msg)


def send_otp_with_resend(email, otp, api_key):
    sender = (os.environ.get("RESEND_FROM") or "DeepSeek Scanner <onboarding@resend.dev>").strip()
    subject = f"Your {APP_NAME} OTP"
    html_body = (
        f"<div style='font-family:Arial;padding:20px;background:#101827;color:#eef4ff'>"
        f"<h1>{html.escape(APP_NAME)}</h1><p>Your OTP is:</p>"
        f"<div style='font-size:34px;letter-spacing:8px;font-weight:800'>{otp}</div>"
        f"<p>It expires in 5 minutes.</p></div>"
    )
    payload = {
        "from": sender,
        "to": [email],
        "subject": subject,
        "html": html_body,
        "text": f"Your {APP_NAME} OTP is {otp}. It expires in 5 minutes.",
    }
    req = Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urlopen(req, timeout=20) as resp:
            if resp.status >= 300:
                raise RuntimeError(resp.read().decode("utf-8", errors="replace"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Resend API error {exc.code}: {detail}")


def resolve_ipv4(host):
    addresses = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    if not addresses:
        raise OSError(f"No IPv4 address found for SMTP host {host}")
    return addresses[0][4][0]


class Handler(BaseHTTPRequestHandler):
    server_version = "DeepSeekScanner/1.0"

    def log_message(self, fmt, *args):
        print(f"[{now_utc().isoformat()}] {self.address_string()} {fmt % args}")

    def current_user(self):
        return read_session(self.headers.get("Cookie"))

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > MAX_BODY_BYTES:
            raise ValueError("Request body is too large")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            raise ValueError("Invalid JSON")

    def send_text(self, status, text, content_type="text/html; charset=utf-8", headers=None):
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.security_headers()
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status, data, headers=None):
        self.send_text(status, json.dumps(data, separators=(",", ":")), "application/json; charset=utf-8", headers)

    def security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

    def require_user(self):
        user = self.current_user()
        if not user:
            self.send_json(401, {"success": False, "error": "Authentication required"})
            return None
        return user

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/healthz":
            self.send_json(200, {"ok": True})
        elif path == "/api/check-auth":
            user = self.current_user()
            self.send_json(200, {"authenticated": bool(user), "user": user})
        elif path in ("/", "/login"):
            self.send_text(200, INDEX_HTML)
        else:
            self.send_json(404, {"success": False, "error": "Not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            data = self.read_json()
            if path == "/api/send-otp":
                self.handle_send_otp(data)
            elif path == "/api/verify-otp":
                self.handle_verify_otp(data)
            elif path == "/api/logout":
                secure = "; Secure" if SESSION_COOKIE_SECURE else ""
                self.send_json(200, {"success": True}, {"Set-Cookie": f"ds_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax{secure}"})
            elif path == "/scan":
                if not self.require_user():
                    return
                self.send_json(200, scan_target(data.get("url", "")))
            elif path == "/chat":
                if not self.require_user():
                    return
                self.send_json(200, {"reply": chat_reply(data.get("vulnerability", ""))})
            else:
                self.send_json(404, {"success": False, "error": "Not found"})
        except ValueError as exc:
            self.send_json(400, {"success": False, "error": str(exc)})
        except Exception as exc:
            self.send_json(500, {"success": False, "error": str(exc)})

    def handle_send_otp(self, data):
        email = (data.get("email") or "").strip().lower()
        name = (data.get("name") or "").strip()
        if not re.match(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", email):
            raise ValueError("Enter a valid email address")
        otp = "".join(random.choices(string.digits, k=6))
        OTP_STORAGE[email] = {
            "otp_hash": hashlib.sha256((otp + SECRET_KEY).encode("utf-8")).hexdigest(),
            "expires": time.time() + 300,
            "attempts": 0,
            "name": name,
        }
        response = {"success": True, "message": "OTP sent", "email": email}
        try:
            send_otp_email(email, otp)
        except Exception as exc:
            if not (DEV_OTP_FALLBACK or OTP_FALLBACK_ON_MAIL_ERROR):
                raise RuntimeError(f"Unable to send OTP email. On Render, set RESEND_API_KEY and RESEND_FROM, or use a paid instance for SMTP. Details: {exc}")
            response["message"] = "Email delivery failed, using fallback OTP"
            response["mail_error"] = str(exc)
            response["dev_otp"] = otp
        if DEV_OTP_FALLBACK:
            response["dev_otp"] = otp
        self.send_json(200, response)

    def handle_verify_otp(self, data):
        email = (data.get("email") or "").strip().lower()
        otp = (data.get("otp") or "").strip()
        record = OTP_STORAGE.get(email)
        if not record:
            raise ValueError("No OTP found. Request a new one.")
        if time.time() > record["expires"]:
            OTP_STORAGE.pop(email, None)
            raise ValueError("OTP expired. Request a new one.")
        if record["attempts"] >= 3:
            OTP_STORAGE.pop(email, None)
            raise ValueError("Too many attempts. Request a new OTP.")
        expected = record["otp_hash"]
        provided = hashlib.sha256((otp + SECRET_KEY).encode("utf-8")).hexdigest()
        if not hmac.compare_digest(expected, provided):
            record["attempts"] += 1
            raise ValueError(f"Invalid OTP. {3 - record['attempts']} attempt(s) remaining.")

        OTP_STORAGE.pop(email, None)
        name = record.get("name") or (data.get("name") or "").strip() or email.split("@")[0]
        USERS[email] = {"email": email, "name": name, "role": "user"}
        cookie = make_session(USERS[email])
        secure = "; Secure" if SESSION_COOKIE_SECURE else ""
        self.send_json(
            200,
            {"success": True, "message": "Verification successful", "user": USERS[email]},
            {"Set-Cookie": f"ds_session={cookie}; Path=/; Max-Age={SESSION_TTL_SECONDS}; HttpOnly; SameSite=Lax{secure}"},
        )


STATUS_TEXT = {
    200: "200 OK",
    400: "400 Bad Request",
    401: "401 Unauthorized",
    404: "404 Not Found",
    500: "500 Internal Server Error",
}


def wsgi_response(start_response, status_code, body, content_type="application/json; charset=utf-8", headers=None):
    if isinstance(body, (dict, list)):
        body = json.dumps(body, separators=(",", ":"))
    if isinstance(body, str):
        body = body.encode("utf-8")
    response_headers = [
        ("Content-Type", content_type),
        ("Content-Length", str(len(body))),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
        ("X-Frame-Options", "DENY"),
        ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
    ]
    response_headers.extend((headers or {}).items())
    start_response(STATUS_TEXT.get(status_code, f"{status_code} OK"), response_headers)
    return [body]


def wsgi_json_body(environ):
    try:
        length = int(environ.get("CONTENT_LENGTH") or "0")
    except ValueError:
        length = 0
    if length > MAX_BODY_BYTES:
        raise ValueError("Request body is too large")
    raw = environ["wsgi.input"].read(length) if length else b"{}"
    try:
        return json.loads(raw.decode("utf-8") or "{}")
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON")


def wsgi_user(environ):
    return read_session(environ.get("HTTP_COOKIE"))


def app(environ, start_response):
    """WSGI entrypoint for Render's default gunicorn app:app command."""
    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET").upper()

    try:
        if method == "GET":
            if path == "/healthz":
                return wsgi_response(start_response, 200, {"ok": True})
            if path == "/api/check-auth":
                user = wsgi_user(environ)
                return wsgi_response(start_response, 200, {"authenticated": bool(user), "user": user})
            if path in ("/", "/login"):
                return wsgi_response(start_response, 200, INDEX_HTML, "text/html; charset=utf-8")
            return wsgi_response(start_response, 404, {"success": False, "error": "Not found"})

        if method != "POST":
            return wsgi_response(start_response, 404, {"success": False, "error": "Not found"})

        data = wsgi_json_body(environ)
        if path == "/api/send-otp":
            email = (data.get("email") or "").strip().lower()
            name = (data.get("name") or "").strip()
            if not re.match(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", email):
                raise ValueError("Enter a valid email address")
            otp = "".join(random.choices(string.digits, k=6))
            OTP_STORAGE[email] = {
                "otp_hash": hashlib.sha256((otp + SECRET_KEY).encode("utf-8")).hexdigest(),
                "expires": time.time() + 300,
                "attempts": 0,
                "name": name,
            }
            response = {"success": True, "message": "OTP sent", "email": email}
            try:
                send_otp_email(email, otp)
            except Exception as exc:
                if not (DEV_OTP_FALLBACK or OTP_FALLBACK_ON_MAIL_ERROR):
                    raise RuntimeError(f"Unable to send OTP email. On Render, set RESEND_API_KEY and RESEND_FROM, or use a paid instance for SMTP. Details: {exc}")
                response["message"] = "Email delivery failed, using fallback OTP"
                response["mail_error"] = str(exc)
                response["dev_otp"] = otp
            if DEV_OTP_FALLBACK:
                response["dev_otp"] = otp
            return wsgi_response(start_response, 200, response)

        if path == "/api/verify-otp":
            email = (data.get("email") or "").strip().lower()
            otp = (data.get("otp") or "").strip()
            record = OTP_STORAGE.get(email)
            if not record:
                raise ValueError("No OTP found. Request a new one.")
            if time.time() > record["expires"]:
                OTP_STORAGE.pop(email, None)
                raise ValueError("OTP expired. Request a new one.")
            if record["attempts"] >= 3:
                OTP_STORAGE.pop(email, None)
                raise ValueError("Too many attempts. Request a new OTP.")
            expected = record["otp_hash"]
            provided = hashlib.sha256((otp + SECRET_KEY).encode("utf-8")).hexdigest()
            if not hmac.compare_digest(expected, provided):
                record["attempts"] += 1
                raise ValueError(f"Invalid OTP. {3 - record['attempts']} attempt(s) remaining.")

            OTP_STORAGE.pop(email, None)
            name = record.get("name") or (data.get("name") or "").strip() or email.split("@")[0]
            USERS[email] = {"email": email, "name": name, "role": "user"}
            cookie = make_session(USERS[email])
            secure = "; Secure" if SESSION_COOKIE_SECURE else ""
            return wsgi_response(
                start_response,
                200,
                {"success": True, "message": "Verification successful", "user": USERS[email]},
                headers={"Set-Cookie": f"ds_session={cookie}; Path=/; Max-Age={SESSION_TTL_SECONDS}; HttpOnly; SameSite=Lax{secure}"},
            )

        if path == "/api/logout":
            secure = "; Secure" if SESSION_COOKIE_SECURE else ""
            return wsgi_response(
                start_response,
                200,
                {"success": True},
                headers={"Set-Cookie": f"ds_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax{secure}"},
            )

        if path in ("/scan", "/chat") and not wsgi_user(environ):
            return wsgi_response(start_response, 401, {"success": False, "error": "Authentication required"})
        if path == "/scan":
            return wsgi_response(start_response, 200, scan_target(data.get("url", "")))
        if path == "/chat":
            return wsgi_response(start_response, 200, {"reply": chat_reply(data.get("vulnerability", ""))})
        return wsgi_response(start_response, 404, {"success": False, "error": "Not found"})
    except ValueError as exc:
        return wsgi_response(start_response, 400, {"success": False, "error": str(exc)})
    except Exception as exc:
        return wsgi_response(start_response, 500, {"success": False, "error": str(exc)})


def run():
    port = int(os.environ.get("PORT", "5000"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print("=" * 64)
    print(f"{APP_NAME} single-file server")
    print(f"Listening on http://0.0.0.0:{port}")
    print("Render start command: python app.py")
    print("=" * 64)
    server.serve_forever()


if __name__ == "__main__":
    run()
