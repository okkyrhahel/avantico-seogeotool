#!/usr/bin/env python3
"""Website audit backend - browser version (Python 3.9+ standard library only, no pip; Google Chrome or Edge installed).
Run: python server.py  ->  http://localhost:8000
A real browser (the installed Chrome, driven by cdp.py over the Chrome DevTools Protocol) opens the homepage and up to
MAX_PAGES-1 subpages like a visitor would: JavaScript runs, the rendered page is scored, the homepage is also checked on a
phone-sized screen. Settings can also come from a .env file in this folder or the Tool folder.
Env: BROWSER_CHANNEL (chrome | msedge, default chrome), BROWSER_PATH (full path to the browser), MAX_BROWSERS (parallel
audits with a browser, default 2),
LEAD_WEBHOOK_URL (optional; receives each lead as JSON), PSI_KEY (optional Google PageSpeed API key), INTERNAL_TOKEN (enables /api/internal/*), HOST, PORT,
RATE_LIMIT (audits per IP per hour, default 5), ALLOW_PRIVATE=1 (dev only: lets the crawler reach localhost/private IPs)."""
import os, re, json, time, socket, hmac, ipaddress, secrets, threading, zlib
import urllib.request, urllib.parse, urllib.error
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from inputs import COUNTRIES, normalize_url, normalize_phone, country_checks
from cdp import Chrome


def load_env_file():
    """Local settings (PSI_KEY, INTERNAL_TOKEN, ...) from a .env file in this folder or the Tool folder above it.
    Real environment variables win; the .env file is for local runs only and must not be published."""
    here = os.path.dirname(os.path.abspath(__file__))
    for f in (os.path.join(here, ".env"), os.path.join(here, "..", ".env")):
        try:
            for line in open(f, encoding="utf-8"):
                k, sep, v = line.strip().partition("=")
                if sep and k and not k.startswith("#"):
                    os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
        except OSError:
            pass


load_env_file()

MAX_PAGES, TIMEOUT, MAX_BYTES, BUDGET = 10, 8, 1_500_000, 120  # homepage + up to 9 subpages, each scored on its own (no averaging)
UA = "SiteAuditBot/1.0"
BROWSERS = threading.Semaphore(int(os.environ.get("MAX_BROWSERS") or 2))
NAV_TIMEOUT = 25  # seconds per page in the browser
AI_BOTS = ["GPTBot", "ClaudeBot", "PerplexityBot", "Google-Extended", "CCBot"]
CTA = (
    # English
    "contact", "get started", "book", "quote", "enquir", "inquir", "demo", "call", "consult", "appointment", "schedule",
    # German
    "kontakt", "kontaktieren", "termin vereinbaren", "termin buchen", "beratung buchen", "beratung vereinbaren",
    "jetzt anfragen", "anfrage senden", "angebot anfordern", "offerte anfordern", "rückruf", "rueckruf",
    # French / Italian / Indonesian
    "prendre rendez-vous", "demander un devis", "nous contacter", "contattaci", "prenota", "hubungi", "konsultasi", "buat janji"
)
W = {"high": 15, "medium": 8, "low": 3, "info": 0}
# GEO has a separate weighting model because some readiness signals are more consequential.
GEO_W = {"high": 20, "medium": 10, "low": 4, "info": 0}
# A category score can never look better than its worst open issue:
# blocker -> max 49, high -> max 59 ("Needs work"), medium -> max 79 ("Needs attention").
CAP = {"blocker": 49, "high": 59, "medium": 79}
# Issues that stop the page from doing its job (being indexed, trusted or contacted), whatever else is in place.
BLOCKERS = {"Pages without a title", "Pages set to 'noindex'", "HTTP header sets noindex", "robots.txt blocks all crawlers",
            "Website is not served over HTTPS", "No clear contact route on the homepage"}
STEPS = ("connect", "render", "seo", "geo", "content", "journey", "speed", "summary")
CATS = ("seo", "geo", "content", "journey", "speed")
ALLOW_PRIVATE = os.environ.get("ALLOW_PRIVATE") == "1"
RATE_LIMIT = int(os.environ.get("RATE_LIMIT") or 5)
KEEP_SECONDS = 7200  # audits are forgotten after 2 hours
AUDITS, HITS = {}, {}
HERE = os.path.dirname(os.path.abspath(__file__))


# ---------- safe fetching (SSRF protection incl. redirects) ----------
def check(url):
    u = urllib.parse.urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("bad url")
    if not ALLOW_PRIVATE:
        for ai in socket.getaddrinfo(u.hostname, None):
            ip = ipaddress.ip_address(ai[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                raise ValueError("blocked host")


class Redir(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        check(newurl)
        return super().redirect_request(req, fp, code, msg, hdrs, newurl)


OPENER = urllib.request.build_opener(Redir)


class AuditError(Exception):
    """Audit stops with a message the visitor can understand."""


def decode_body(raw, encoding):
    # Some servers compress the response even when it was not requested: decompress before reading it as text.
    enc = (encoding or "").lower().strip()
    if enc in ("gzip", "x-gzip", "deflate"):
        for wbits in ((16 + zlib.MAX_WBITS, zlib.MAX_WBITS, -zlib.MAX_WBITS) if "gzip" in enc else (zlib.MAX_WBITS, -zlib.MAX_WBITS)):
            try:
                raw = zlib.decompressobj(wbits).decompress(raw, MAX_BYTES)
                break
            except zlib.error:
                continue
        else:
            raise AuditError("The website sent a compressed response that could not be read.")
    elif enc and enc != "identity":
        # br / zstd are not in the standard library; only gzip/deflate are requested, so this is rare.
        raise AuditError("The website sent its page in a format this tool cannot read (" + enc + ").")
    return raw.decode("utf-8", "replace")


def fetch(url, method="GET"):
    check(url)
    t = time.time()
    req = urllib.request.Request(url, method=method, headers={"User-Agent": UA, "Accept-Encoding": "gzip, deflate"})
    try:
        r = OPENER.open(req, timeout=TIMEOUT)
    except urllib.error.HTTPError as e:
        r = e
    body = "" if method == "HEAD" else decode_body(r.read(MAX_BYTES), r.headers.get("content-encoding"))
    return dict(status=r.code, url=r.geturl(), ctype=r.headers.get("content-type", ""),
                headers={str(k).lower(): str(v) for k, v in r.headers.items()},
                body=body, ms=int((time.time() - t) * 1000))


# Bot protection / challenge pages: auditing them would report on a "page" that visitors never see.
CHALLENGE = re.compile(r"cf-browser-verification|cf_chl_opt|<title>\s*(just a moment|attention required|access denied|"
                       r"ddos-guard|security check|please wait)|_incapsula_resource|px-captcha|captcha-delivery|"
                       r"sgcaptcha|checking your browser", re.I)


def is_challenge(r):
    h = r.get("headers", {})
    protected = "cf-ray" in h or bool(re.search(r"cloudflare|ddos-guard|sucuri|akamai", h.get("server", ""), re.I))
    if r["status"] in (403, 429, 503) and protected:
        return True
    # Markers only count on a nearly empty page: normal pages behind a firewall can carry similar scripts.
    text = re.sub(r"(?is)<(script|style)\b.*?</\1>|<[^>]+>", " ", r["body"][:200000])
    return len(text.split()) < 150 and bool(CHALLENGE.search(r["body"][:20000]))


def tf(url, method="GET"):
    try:
        return fetch(url, method)
    except Exception:
        return None


# ---------- HTML parsing ----------
class P(HTMLParser):
    def __init__(s):
        super().__init__()
        s.d = dict(title="", meta={}, h=[], canon=None, noalt=0, images=[], links=[], atext=[], anchor_details=[],
                   buttons=[], inputs=[], ld=[], lang=None, viewport=False, forms=0, words=0, body_text="",
                   has_main=False, has_article=False, iframes=[], videos=0, paragraphs=0)
        s.cap, s.buf, s.skip = None, "", False

    def handle_starttag(s, tag, a):
        a, d = dict(a), s.d
        if tag == "html":
            d["lang"] = a.get("lang")
        elif tag == "meta":
            n = (a.get("name") or a.get("property") or "").lower()
            if n:
                d["meta"][n] = a.get("content") or ""
            if n == "viewport":
                d["viewport"] = True
        elif tag == "link" and "canonical" in (a.get("rel") or "").lower():
            d["canon"] = a.get("href")
        elif tag == "img":
            if "alt" not in a:
                d["noalt"] += 1
            d["images"].append({"src": a.get("src", ""), "alt": a.get("alt"),
                                "width": a.get("width"), "height": a.get("height"),
                                "loading": a.get("loading", "").lower()})
        elif tag == "main":
            d["has_main"] = True
        elif tag == "article":
            d["has_article"] = True
        elif tag == "iframe":
            d["iframes"].append({"src": a.get("src", ""), "title": a.get("title", "").strip()})
        elif tag == "video":
            d["videos"] += 1
        elif tag == "p":
            d["paragraphs"] += 1
        elif tag == "form":
            d["forms"] += 1
        elif tag == "input":
            d["inputs"].append({"type": (a.get("type") or "text").lower(), "name": a.get("name", ""),
                                "id": a.get("id", ""), "aria": a.get("aria-label", ""),
                                "required": "required" in a, "placeholder": a.get("placeholder", "")})
        elif tag == "a" and a.get("href"):
            d["links"].append(a["href"])
            d["anchor_details"].append({"href": a["href"], "rel": a.get("rel", "").lower(),
                                         "target": a.get("target", "").lower()})
            s.cap, s.buf = "a", ""
        elif tag in ("button", "title", "h1", "h2", "h3"):
            s.cap, s.buf = tag, ""
            if tag == "button" and a.get("aria-label"):
                d["buttons"].append(a.get("aria-label", "").lower())
        elif tag in ("script", "style"):
            s.skip = True
            if "ld+json" in (a.get("type") or ""):
                s.cap, s.buf = "ld", ""

    def handle_endtag(s, tag):
        if tag in ("script", "style"):
            s.skip = False
        c = s.cap
        if c and (c == tag or (c == "ld" and tag == "script")):
            t, d = " ".join(s.buf.split()), s.d
            if c == "title": d["title"] = t
            elif c == "ld": d["ld"].append(s.buf)
            elif c == "a": d["atext"].append(t.lower())
            elif c == "button": d["buttons"].append(t.lower())
            else: d["h"].append((c, t))
            s.cap = None

    def handle_data(s, x):
        if s.cap:
            s.buf += x
        if not s.skip and s.cap != "ld":
            s.d["words"] += len(x.split())
            s.d["body_text"] += " " + x


def parse(r):
    p = P()
    p.feed(r["body"])
    return {**p.d, "ms": r["ms"]}


def ld_types(blobs):
    out, bad = set(), 0

    def walk(o):
        if isinstance(o, list):
            for i in o: walk(i)
        elif isinstance(o, dict):
            t = o.get("@type")
            out.update(t if isinstance(t, list) else [t] if t else [])
            for v in o.values(): walk(v)
    for b in blobs:
        try: walk(json.loads(b))
        except Exception: bad += 1
    return {str(x).lower() for x in out}, bad



def ld_entities(blobs):
    """Return basic Organization/LocalBusiness names and URLs for consistency checks."""
    found = []
    def walk(o):
        if isinstance(o, list):
            for item in o: walk(item)
        elif isinstance(o, dict):
            typ = o.get("@type", [])
            types = [typ] if isinstance(typ, str) else typ if isinstance(typ, list) else []
            if any(str(t).lower() in ("organization", "localbusiness", "professionalservice", "medicalbusiness") for t in types):
                found.append({"name": str(o.get("name", "")).strip(), "url": str(o.get("url", "")).strip()})
            for value in o.values(): walk(value)
    for blob in blobs:
        try: walk(json.loads(blob))
        except Exception: pass
    return found


def robots_blocked(txt):
    agents, rules, blocked = [], False, set()
    for line in (txt or "").splitlines():
        line = line.split("#")[0].strip()
        if ":" not in line: continue
        k, v = [x.strip() for x in line.split(":", 1)]
        k = k.lower()
        if k == "user-agent":
            if rules: agents, rules = [], False
            agents.append(v.lower())
        elif k in ("disallow", "allow"):
            rules = True
            if k == "disallow" and v == "/": blocked.update(agents)
    return blocked


def get_psi(url):
    q = [("url", url), ("strategy", "mobile"), ("category", "performance"), ("category", "seo")]
    if os.environ.get("PSI_KEY"): q.append(("key", os.environ["PSI_KEY"]))
    try:
        r = urllib.request.urlopen("https://www.googleapis.com/pagespeedonline/v5/runPagespeed?" + urllib.parse.urlencode(q), timeout=70)
        j = json.load(r)["lighthouseResult"]; a = j["audits"]
        categories = j.get("categories", {})
        return dict(score=round(categories["performance"]["score"] * 100),
                    lighthouse_seo=round(categories["seo"]["score"] * 100) if categories.get("seo", {}).get("score") is not None else None,
                    lcp=a.get("largest-contentful-paint", {}).get("displayValue", "Unavailable"),
                    tbt=a.get("total-blocking-time", {}).get("displayValue", "Unavailable"),
                    cls=a.get("cumulative-layout-shift", {}).get("displayValue", "Unavailable"))
    except urllib.error.HTTPError as e:
        # Preserve the HTTP status (especially 429 quota/rate-limit responses) for transparent reporting.
        return {"error": f"HTTP {e.code}"}
    except Exception as e:
        return {"error": type(e).__name__}


# ---------- real browser (installed Chrome via cdp.py) ----------
# Collected inside the rendered page. Visible text only (innerText), so hidden menus/templates do not count as content.
PAGE_JS = r"""(mobile) => {
  const vis = el => { const r = el.getBoundingClientRect(), cs = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none' && +cs.opacity !== 0; };
  const text = (document.body && document.body.innerText) || '';
  const clickables = [...document.querySelectorAll('a[href], button, [role=button], input[type=submit]')].filter(vis);
  const vh = innerHeight, vw = innerWidth;
  const label = el => (el.innerText || el.value || el.getAttribute('aria-label') || el.title || '').trim().replace(/\s+/g, ' ').slice(0, 80);
  const firstScreen = clickables.filter(el => { const r = el.getBoundingClientRect(); return r.top < vh && r.bottom > 0; })
                                .map(el => ({label: label(el).toLowerCase(), href: el.href || ''}));
  const small = mobile ? clickables.filter(el => { const r = el.getBoundingClientRect(); return (r.width < 32 || r.height < 32) && label(el); }).length : 0;
  let tiny = 0, sized = 0;
  if (mobile) for (const el of document.querySelectorAll('p, li, span, a, td')) {
    if (!el.childNodes.length || ![...el.childNodes].some(n => n.nodeType === 3 && n.textContent.trim().length > 3) || !vis(el)) continue;
    sized++; if (parseFloat(getComputedStyle(el).fontSize) < 12) tiny++; }
  const imgs = [...document.images].filter(i => i.complete && i.currentSrc && !i.currentSrc.startsWith('data:'));
  return {
    text, words: text.split(/\s+/).filter(Boolean).length,
    links: [...new Set([...document.querySelectorAll('a[href]')].map(a => a.href))],
    nav: [...new Set([...document.querySelectorAll('header a[href], nav a[href], [role=navigation] a[href]')].map(a => a.href))],
    first_screen: firstScreen, small_targets: small, tiny_text: tiny, text_elements: sized,
    overflow: document.documentElement.scrollWidth > vw + 4,
    broken_images: imgs.filter(i => i.naturalWidth === 0).map(i => i.currentSrc).slice(0, 10),
    hreflang: [...document.querySelectorAll('link[rel=alternate][hreflang]')].map(l => l.hreflang),
    copyright: (text.match(/(?:©|copyright)\s*(?:\d{4}\s*[-–]\s*)?(\d{4})/i) || [])[1] || null,
  };
}"""

_HOSTS = {}


def host_allowed(url):
    """SSRF guard for every request the browser makes (pages, redirects, images, scripts)."""
    h = urllib.parse.urlparse(url).hostname
    if not h:
        return True  # data:, blob:
    if h not in _HOSTS:
        try:
            check(url); _HOSTS[h] = True
        except Exception:
            _HOSTS[h] = False
    return _HOSTS[h]


class Browser:
    """One Chrome instance per audit; each visit opens an isolated tab (desktop 1366x900, or a phone 390x844 with touch)."""

    def __enter__(s):
        BROWSERS.acquire()
        try:
            s.chrome = Chrome().__enter__()
        except Exception:
            BROWSERS.release(); raise
        return s

    def __exit__(s, *a):
        try:
            s.chrome.__exit__(*a)
        finally:
            BROWSERS.release()

    def visit(s, url, mobile=False):
        page = s.chrome.new_page(mobile=mobile, guard=host_allowed)
        try:
            r = page.goto(url, timeout=NAV_TIMEOUT)
            page.wait_idle()  # many sites never go fully idle (chat, analytics): wait at most a few seconds
            if not mobile:  # scroll once so lazy-loaded sections render, as a visitor would see them
                page.run("window.scrollTo(0, document.body.scrollHeight)"); time.sleep(0.7); page.run("window.scrollTo(0, 0)")
            data = page.evaluate(PAGE_JS, mobile)
            return dict(status=r["status"], url=r["url"], ctype=r["headers"].get("content-type", "text/html"), headers=r["headers"],
                        body=page.content(), ms=r["ms"], rendered=data, console=page.console[:10], failed=page.failed[:10])
        finally:
            page.close()


# ---------- the audit ----------
ASSET =re.compile(r"\.(jpe?g|png|gif|webp|svg|pdf|zip|css|js|ico|mp4|xml)$", re.I)


def run(A):
    try:
        _run(A)
    except AuditError as e:
        A["internal"].append(dict(cat="system", sev="info", title="Audit stopped", what=str(e), why="", urls=[], evidence=""))
        A.update(status="failed", message=str(e))
    except Exception as e:
        A["internal"].append(dict(cat="system", sev="info", title="Audit failed", what=repr(e), why="", urls=[], evidence=""))
        A.update(status="failed", message="We couldn't reach or read this website. Please check the address and try again.")


def _run(A):
    t0, S, notes = time.time(), A["steps"], []
    url = A["url"]; u = urllib.parse.urlparse(url); origin = f"{u.scheme}://{u.netloc}"
    A.update(status="discovering", message="Connecting to your website…"); S["connect"] = "running"

    def first_fetch(x):
        try:
            return fetch(x)
        except (urllib.error.URLError, socket.timeout, ConnectionError, TimeoutError):
            time.sleep(2)
            return fetch(x)  # one retry for a slow or briefly unavailable connection
    try:
        home = first_fetch(url)
    except (urllib.error.URLError, socket.timeout, ConnectionError, TimeoutError, OSError):
        if A.get("scheme_given") or not url.startswith("https://"):
            raise
        url = "http://" + url[len("https://"):]  # address typed without http(s)://: try plain http before giving up
        home = first_fetch(url)
    if is_challenge(home):
        raise AuditError("This website blocks automated checks (bot protection or a captcha), so the page could not be read. "
                         "Allow the audit tool in the firewall / bot protection settings and try again.")
    if home["status"] >= 400 or "html" not in home["ctype"].lower():
        raise RuntimeError(f"homepage status {home['status']}")
    S["connect"] = "done"; hurl = home["url"]
    # Use the final redirected homepage as the canonical audit origin for robots/sitemap and links.
    fu = urllib.parse.urlparse(hurl); origin = f"{fu.scheme}://{fu.netloc}"
    psi = {}; S["speed"] = "running"
    th = threading.Thread(target=lambda: psi.update(get_psi(hurl)), daemon=True); th.start()

    host = lambda x: urllib.parse.urlparse(x).netloc.lower().removeprefix("www.")
    rob = tf(origin + "/robots.txt")
    robots = rob["body"] if rob and rob["status"] == 200 and "html" not in rob["ctype"].lower() else None
    sm = re.findall(r"(?im)^sitemap:\s*(\S+)", robots or "") or [origin + "/sitemap.xml"]
    locs, r = [], tf(sm[0])
    if r and r["status"] == 200:
        locs = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", r["body"])
        if "<sitemapindex" in r["body"] and locs:
            r2 = tf(locs[0]); locs = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", r2["body"]) if r2 and r2["status"] == 200 else []
    has_sitemap = bool(locs)

    # What a crawler that does not run JavaScript receives (many AI crawlers): kept for the GEO comparison.
    raw = parse(home)
    js_shell = raw["words"] < 80 and bool(re.search(r"<div[^>]+id=[\"'](root|app|__next|__nuxt)[\"'][^>]*>\s*</div>", home["body"], re.I)
                                          or home["body"].lower().count("<script") >= 8)

    # Visit the site in a real browser, like a visitor: homepage (desktop + phone), then the pages its menu leads to.
    A.update(status="discovering", message="Opening the website in a browser…"); S["render"] = "running"
    pages, rend, broken_pages = {}, {}, []
    try:
        with Browser() as B:
            hp = B.visit(hurl)
            if is_challenge(hp):
                raise AuditError("This website blocks automated browsers (bot protection or a captcha), so the page could not be read. "
                                 "Allow the audit tool in the firewall / bot protection settings and try again.")
            hurl = hp["url"] if host(hp["url"]) == host(hurl) else hurl
            pages[hurl] = {**parse(hp), "status": hp["status"]}; rend[hurl] = hp
            mob = B.visit(hurl, mobile=True)
            # Menu links first (what a visitor clicks), important pages first, then other homepage links, then the sitemap.
            r0 = hp["rendered"]
            prio = ("kontakt", "contact", "about", "ueber", "uber", "team", "studio", "service", "leistung", "angebot",
                    "preis", "price", "pricing", "tarif", "kurs", "class", "product", "produkt", "faq", "impressum")
            cand = []
            for h in r0["nav"] + r0["links"] + locs:
                x = urllib.parse.urldefrag(urllib.parse.urljoin(hurl, h))[0]
                p = urllib.parse.urlparse(x)
                if p.scheme in ("http", "https") and host(x) == host(hurl) and not ASSET.search(p.path) \
                        and x.rstrip("/") != hurl.rstrip("/") and x not in cand:
                    cand.append(x)
            nav_set = {urllib.parse.urldefrag(x)[0] for x in r0["nav"]}
            cand.sort(key=lambda x: (x not in nav_set, not any(k in x.lower() for k in prio)))
            A.update(status="analysing", pages_discovered=1 + len(cand), pages_analysed=1, message="Visiting the pages a visitor would open…")
            for x in cand[:MAX_PAGES - 1]:
                if time.time() - t0 > BUDGET:
                    notes.append("The time budget was reached, so some discovered pages were not analysed."); break
                try:
                    r = B.visit(x)
                except Exception:
                    broken_pages.append(x); continue
                if r["status"] >= 400:
                    broken_pages.append(x)
                elif "html" in r["ctype"].lower() and r["url"] not in pages and host(r["url"]) == host(hurl):
                    pages[r["url"]] = {**parse(r), "status": r["status"]}; rend[r["url"]] = r
                A["pages_analysed"] = len(pages)
    except AuditError:
        raise
    except Exception as e:
        if not pages:
            raise AuditError("The website could not be opened in the audit browser (" + type(e).__name__ + "). Please try again.")
        notes.append("The browser stopped early (" + type(e).__name__ + "); the pages opened so far are included.")
    S["render"] = "done"
    hd = pages[hurl]
    n = len(pages)
    notes.append(f"Opened {n} page(s) in a real browser (Chrome) with JavaScript, like a visitor: the homepage and the pages its menu "
                 f"links to (limit {MAX_PAGES}). Each finding says how many of these pages are affected.")
    S["seo"] = "running"

    def add(cat, sev, title, what, why, urls=(), ev=""):
        A["internal"].append(dict(cat=cat, sev=sev, title=title, what=what, why=why, urls=list(urls), evidence=ev))
        A["customer"].append(dict(cat=cat, sev=sev, title=title, what=what, why=why, pages=len(urls) or None))

    ok = lambda cat, t: A["passed"].append(dict(cat=cat, title=t))
    pg = lambda f: [x for x, d in pages.items() if f(d)]

    def chk(cat, bad, sev, title, what, why, good):
        if bad: add(cat, sev, title, f"{len(bad)} of {n} analysed pages {what}.", why, bad)
        else: ok(cat, good)

    # SEO
    t = lambda d: d["title"].strip()
    md = lambda d: d["meta"].get("description", "").strip()
    h1 = lambda d: [x for x in d["h"] if x[0] == "h1"]
    chk("seo", pg(lambda d: not t(d)), "high", "Pages without a title", "have no title tag", "Titles are the headline shown in search results and browser tabs.", "All analysed pages have a title")
    chk("seo", pg(lambda d: t(d) and not 20 <= len(t(d)) <= 65), "medium", "Titles outside the recommended length", "have a title shorter than 20 or longer than 65 characters", "Very short titles say little; very long ones are cut off in search results.", "Title lengths look appropriate")
    titles = {}
    for x, d in pages.items():
        if t(d): titles.setdefault(t(d).lower(), []).append(x)
    chk("seo", [x for v in titles.values() if len(v) > 1 for x in v], "medium", "Duplicate page titles", "share a title with another page", "Distinct titles help people and search engines tell pages apart.", "No duplicate titles found")
    chk("seo", pg(lambda d: not md(d)), "medium", "Missing meta descriptions", "have no meta description", "The description is often used as the summary under a search result.", "All analysed pages have a meta description")
    chk("seo", pg(lambda d: not h1(d)), "medium", "Pages without a main heading (H1)", "have no H1", "A clear H1 tells visitors and crawlers what the page is about.", "The homepage has an H1")
    chk("seo", pg(lambda d: len(h1(d)) > 1), "low", "Multiple H1 headings", "have more than one H1", "Multiple main headings are not automatically a ranking penalty, but may weaken the page's content hierarchy.", "No multiple-H1 issue detected")
    chk("seo", pg(lambda d: not any(x[0] == "h2" for x in d["h"])), "medium", "No H2 subheadings", "have no H2 subheadings", "Subheadings can make long content easier to scan and help communicate topic structure.", "H2 subheadings are present")
    chk("seo", pg(lambda d: d["words"] < 250), "medium", "Limited visible text content", "contain fewer than 250 extracted words", "A homepage with very little extractable text may not explain its offer, expertise, and relevance clearly. Word count alone does not determine quality.", "The homepage contains at least 250 extracted words")
    chk("seo", pg(lambda d: bool(md(d)) and len(md(d)) < 70), "low", "Very short meta description", "have a meta description shorter than 70 characters", "A very short description may miss an opportunity to explain the page's value in search snippets.", "Meta description length is not obviously short")
    chk("seo", pg(lambda d: bool(md(d)) and len(md(d)) > 170), "low", "Very long meta description", "have a meta description longer than 170 characters", "Long descriptions may be truncated in search snippets; search engines can also choose their own snippet.", "Meta description length is not obviously long")
    chk("seo", pg(lambda d: "noindex" in d["meta"].get("robots", "").lower()), "high", "Pages set to 'noindex'", "tell search engines not to index them", "Pages marked noindex will not appear in search results.", "No analysed page is blocked from indexing")
    chk("seo", pg(lambda d: not d["canon"]), "low", "Missing canonical links", "have no canonical link", "Canonical links help avoid duplicate-content confusion.", "Canonical links are present")
    chk("seo", pg(lambda d: d["noalt"] > 0), "low", "Images without an alt attribute", "contain images with no alt attribute", "Alternative text supports accessibility and gives images context.", "Images have alt attributes")
    chk("seo", pg(lambda d: not d["viewport"]), "medium", "No mobile viewport", "have no viewport meta tag", "Without it, pages may display poorly on phones.", "Mobile viewport is set")
    chk("seo", pg(lambda d: not d["lang"]), "low", "Missing page language", "have no lang attribute on <html>", "The language attribute helps browsers, screen readers and search engines.", "Page language is declared")
    if not hurl.startswith("https://"): add("seo", "high", "Website is not served over HTTPS", "The homepage loads over an insecure connection.", "Browsers warn visitors about insecure sites and search engines favour HTTPS.")
    else: ok("seo", "Website is served over HTTPS")
    blocked = robots_blocked(robots)
    if "*" in blocked: add("seo", "high", "robots.txt blocks all crawlers", "robots.txt disallows the whole website for all crawlers.", "Search engines may not be able to crawl or list your pages.")
    elif robots is None: add("seo", "low", "No robots.txt found", "The website has no robots.txt file.", "It is optional, but it lets you guide crawlers and point them to your sitemap.")
    else: ok("seo", "robots.txt is present and does not block all crawlers")
    if has_sitemap: ok("seo", "XML sitemap found")
    else: add("seo", "medium", "No XML sitemap found", "No readable sitemap was found at the location listed in robots.txt or at /sitemap.xml.", "Sitemaps help search engines discover all your pages.")
    internal = []
    for h in hd["links"]:
        x = urllib.parse.urldefrag(urllib.parse.urljoin(hurl, h))[0]
        if urllib.parse.urlparse(x).scheme in ("http", "https") and host(x) == host(hurl) and x not in internal: internal.append(x)
    broken = []
    for x in internal[:15]:
        r = tf(x, "HEAD")
        if r and r["status"] >= 400 and r["status"] not in (403, 405, 429): broken.append(x)
    if broken: add("seo", "high", "Broken links on the homepage", f"{len(broken)} of {min(15, len(internal))} internal homepage links checked returned an error.", "Broken links frustrate visitors and waste crawl budget.", broken)
    elif internal: ok("seo", "Homepage internal links checked are working")
    else: add("seo", "low", "Few or no internal links detected", "No crawlable internal links were extracted from the homepage.", "Internal links help visitors and crawlers discover related pages.", [hurl])

    # Additional SEO checks based on the supplied checklist. No new external API is used.
    # Header-based directives and transport/security signals.
    home_headers = home.get("headers", {})
    x_robots = home_headers.get("x-robots-tag", "").lower()
    if "noindex" in x_robots:
        add("seo", "high", "HTTP header sets noindex", "The homepage response includes an X-Robots-Tag header containing noindex.", "Search engines are instructed not to index the page even if the HTML itself does not contain a noindex directive.", [hurl], "X-Robots-Tag=" + x_robots)
    elif x_robots:
        ok("seo", "X-Robots-Tag header inspected (no noindex directive detected)")
    else:
        ok("seo", "No X-Robots-Tag header directive detected")

    canon = (hd.get("canon") or "").strip()
    if canon:
        canon_url = urllib.parse.urljoin(hurl, canon)
        cp = urllib.parse.urlparse(canon_url)
        if cp.scheme not in ("http", "https") or host(canon_url) != host(hurl):
            add("seo", "medium", "Canonical points to a different host or invalid URL", "The canonical target is not on the audited host or is not a normal HTTP(S) URL.", "An unexpected canonical target can consolidate search signals onto a different URL.", [hurl], "canonical=" + canon_url)
        elif canon_url.rstrip("/") != hurl.rstrip("/"):
            cr = tf(canon_url, "HEAD")
            if cr and cr["status"] >= 400 and cr["status"] not in (403, 405, 429):
                add("seo", "high", "Canonical target appears unavailable", f"The canonical target returned HTTP {cr['status']}.", "A canonical target that cannot be accessed may send conflicting indexing signals.", [hurl, canon_url], "canonical=" + canon_url)
            else:
                add("seo", "low", "Canonical is not self-referencing", "The homepage canonical points to a different URL.", "This may be intentional, but should be checked to ensure the preferred URL is correct.", [hurl, canon_url], "canonical=" + canon_url)
        else:
            ok("seo", "Homepage canonical is self-referencing")

    if hurl.startswith("https://"):
        mixed = [im.get("src", "") for im in hd.get("images", []) if im.get("src", "").startswith("http://")]
        mixed += [href for href in hd.get("links", []) if href.startswith("http://") and urllib.parse.urlparse(href).netloc.lower() != urllib.parse.urlparse(hurl).netloc.lower()]
        if mixed:
            add("seo", "medium", "HTTP resources or links found on HTTPS page", f"{len(mixed)} extracted image/link URLs use HTTP rather than HTTPS.", "Insecure embedded resources can trigger mixed-content problems; external HTTP links should be reviewed separately.", [hurl], json.dumps(mixed[:10]))
        else:
            ok("seo", "No obvious HTTP image resources or external HTTP links detected")

    title_text = t(hd)
    h1_text = " ".join(x[1] for x in h1(hd)).strip()
    desc_text = md(hd)
    norm = lambda x: re.sub(r"[^a-z0-9]+", " ", (x or "").lower()).strip()
    title_words = set(norm(title_text).split())
    h1_words = set(norm(h1_text).split())
    if title_text and h1_text and len(title_words & h1_words) == 0:
        add("seo", "low", "Title and H1 topic may not align", "The homepage title and H1 share no words after basic normalization.", "The title and main heading should describe the same primary page topic. This simple language heuristic may misread brand-led or multilingual pages.", [hurl], "title=" + title_text + "; h1=" + h1_text)
    elif title_text and h1_text:
        ok("seo", "Title and H1 have some topical wording in common")

    if desc_text and h1_text and len(set(norm(desc_text).split()) & h1_words) == 0:
        add("seo", "low", "Meta description may not match the main heading", "The meta description and H1 share no words after basic normalization.", "A relevant description can help searchers understand what the page offers. This heuristic does not judge meaning or search intent accurately.", [hurl])
    elif desc_text and h1_text:
        ok("seo", "Meta description shares wording with the main heading")

    # Open Graph / social metadata.
    missing_og = [k for k in ("og:title", "og:description", "og:image") if not hd["meta"].get(k, "").strip()]
    if missing_og:
        add("seo", "low", "Some Open Graph tags are missing", "The homepage is missing: " + ", ".join(missing_og) + ".", "Social metadata can improve how links are presented when shared; it is not a direct guarantee of higher search rankings.", [hurl])
    else:
        ok("seo", "Core Open Graph tags are present")
    if not hd["meta"].get("twitter:card", "").strip():
        add("seo", "low", "Twitter card metadata not detected", "No twitter:card meta tag was found.", "A card declaration can help control link previews on platforms that use Twitter card metadata.", [hurl])
    else:
        ok("seo", "Twitter card metadata is present")

    # Heading hierarchy: report skipped levels without treating them as a guaranteed ranking issue.
    heading_levels = [int(x[0][1]) for x in hd["h"] if x[0] in ("h1", "h2", "h3", "h4", "h5", "h6")]
    skipped_levels = any(cur > prev + 1 for prev, cur in zip(heading_levels, heading_levels[1:]))
    if skipped_levels:
        add("seo", "low", "Heading hierarchy skips levels", "The extracted heading sequence skips one or more heading levels.", "A logical heading outline improves scanning and accessibility; heading level jumps can be intentional in some layouts.", [hurl])
    elif heading_levels:
        ok("seo", "No obvious skipped heading levels detected")

    if not hd.get("has_main") and not hd.get("has_article"):
        add("seo", "low", "No main or article landmark detected", "The returned HTML has no <main> or <article> element.", "Semantic landmarks help identify the primary content, although their absence does not prevent indexing.", [hurl])
    else:
        ok("seo", "A main-content landmark is present")

    # Image and embedded-media checks.
    images = hd.get("images", [])
    missing_dims = [im for im in images if not im.get("width") or not im.get("height")]
    if missing_dims:
        add("seo", "low", "Image dimensions are not declared", f"{len(missing_dims)} of {len(images)} extracted images lack a width or height attribute.", "Declared dimensions help browsers reserve layout space and reduce unexpected layout shifts.", [hurl])
    elif images:
        ok("seo", "Extracted images declare width and height")
    lazy_missing = [im for im in images[1:] if im.get("loading") != "lazy"]
    if lazy_missing:
        add("seo", "low", "Some non-leading images are not lazy-loaded", f"{len(lazy_missing)} images after the first extracted image do not declare loading=lazy.", "Lazy loading may reduce initial loading work for below-the-fold images. The crawler cannot reliably identify the actual LCP image, so the first image is excluded from this heuristic.", [hurl])
    elif len(images) > 1:
        ok("seo", "Images after the first declare lazy loading")
    no_title_iframes = [f for f in hd.get("iframes", []) if not f.get("title")]
    if no_title_iframes:
        add("seo", "low", "Embedded frames lack titles", f"{len(no_title_iframes)} iframe elements have no title attribute.", "Iframe titles help assistive technology users understand embedded content.", [hurl])
    elif hd.get("iframes"):
        ok("seo", "Embedded frames have title attributes")

    # Anchor quality and security attributes.
    generic_anchors = {"click here", "read more", "learn more", "here", "more", "details"}
    weak_anchors = [a for a in hd.get("atext", []) if norm(a) in generic_anchors or not norm(a)]
    if weak_anchors:
        add("seo", "low", "Generic or empty link text detected", f"{len(weak_anchors)} extracted links use generic or empty anchor text.", "Descriptive link text helps visitors and search engines understand the destination.", [hurl])
    else:
        ok("seo", "No obvious generic or empty link labels detected")
    unsafe_targets = [a for a in hd.get("anchor_details", []) if a.get("target") == "_blank" and "noopener" not in a.get("rel", "") and "noreferrer" not in a.get("rel", "")]
    if unsafe_targets:
        add("seo", "low", "New-tab links lack rel protection", f"{len(unsafe_targets)} links with target=_blank do not declare rel=noopener or noreferrer.", "The rel attributes reduce access from the opened page to the originating window in supporting browsers.", [hurl])
    elif any(a.get("target") == "_blank" for a in hd.get("anchor_details", [])):
        ok("seo", "New-tab links include rel protection")

    # Trust/contact signals and author metadata are heuristic; absence is not a ranking verdict.
    if not hd["meta"].get("author", "").strip():
        add("seo", "low", "Author metadata not detected", "No meta name=author value was found in the homepage HTML.", "Author metadata can be useful for editorial pages, but it is not required for every business homepage.", [hurl])
    else:
        ok("seo", "Author metadata is present")
    trust_terms = ("about", "contact", "privacy", "terms", "impressum", "über uns", "ueber-uns", "kontakt", "datenschutz")
    trust_links = [href for href in hd.get("links", []) if any(term in (urllib.parse.urlparse(urllib.parse.urljoin(hurl, href)).path.lower() + " " + href.lower()) for term in trust_terms)]
    if trust_links:
        ok("seo", "Homepage links to at least one trust or transparency page")
    else:
        add("seo", "low", "Trust or transparency links not detected", "No obvious About, Contact, Privacy, Terms or Impressum link was detected from the homepage.", "Clear business and privacy information can support visitor confidence. Custom link labels or routes may not be recognised.", [hurl])

    # Off-page authority cannot be measured with HTML or the allowed PageSpeed API alone.
    notes.append("Off-page authority (backlinks, referring domains, anchor-text profile, toxic links, independent reviews and unlinked brand mentions) was NOT VERIFIED because no backlink/brand data source is connected.")
    notes.append("Site-wide checks cover the opened pages only. Orphan pages, full sitemap quality, hreflang/pagination and external link destinations are not fully verified.")

    # Found by the browser: pages from the menu that fail, script errors, files that do not load, broken images.
    if broken_pages:
        add("seo", "high", "Pages linked from the website do not open", f"{len(broken_pages)} linked page(s) returned an error or did not load in the browser.",
            "Visitors who click these links reach an error instead of content, and search engines may drop the pages.", broken_pages)
    else:
        ok("seo", "All opened pages loaded without an error")
    slug_re = re.compile(r"/(?:blank|copy-of|untitled|new-page|page|seite|kopie-von|neue-seite)(?:[-_]\d+)*(?:/|$)|/[^/]*-\d+-\d+(?:/|$)", re.I)
    vague = [x for x in pages if slug_re.search(urllib.parse.urlparse(x).path + "/")]
    if vague:
        add("seo", "medium", "Page addresses do not describe the content", f"{len(vague)} of {n} analysed pages use a generic address such as /blank-6 or /copy-of-...",
            "Descriptive addresses help visitors and search engines understand a page before opening it. Generic names often come from "
            "website-builder defaults that were never renamed.", vague, ", ".join(vague[:5]))
    else:
        ok("seo", "Page addresses use descriptive words")
    js_err = [x for x, r in rend.items() if r["console"]]
    if js_err:
        add("seo", "low", "JavaScript errors in the browser", f"{len(js_err)} of {n} analysed pages report script errors in the browser console.",
            "Script errors can break menus, forms or tracking for some visitors.", js_err, json.dumps({x: rend[x]["console"][:3] for x in js_err[:3]}))
    else:
        ok("seo", "No JavaScript errors were reported in the browser")
    bad_files = [x for x, r in rend.items() if r["failed"] or r["rendered"]["broken_images"]]
    if bad_files:
        add("seo", "medium", "Images or files fail to load", f"{len(bad_files)} of {n} analysed pages request images, scripts or styles that return an error.",
            "Missing images and files make pages look broken and can hide content.", bad_files,
            json.dumps({x: (rend[x]["failed"] + rend[x]["rendered"]["broken_images"])[:4] for x in bad_files[:3]}))
    else:
        ok("seo", "Images and files load without errors")
    S["seo"] = "done"

    # GEO — assess access, machine-readable identity, and useful extractable content.
    # These checks estimate technical/content readiness; they do not measure actual AI citations.
    S["geo"] = "running"

    bots = [b for b in AI_BOTS if b.lower() in blocked]
    if bots:
        add("geo", "medium", "Some AI crawlers are blocked",
            f"robots.txt appears to block: {', '.join(bots)}.",
            "Blocked crawlers may be unable to fetch public content for the related AI products. This may be intentional, and robots.txt does not control every form of reuse.")
    else:
        ok("geo", "No listed major AI crawler is explicitly blocked by the simple robots.txt check")

    # llms.txt is optional and emerging: its absence is only a low-priority observation.
    ll = tf(origin + "/llms.txt")
    if ll and ll["status"] == 200 and "html" not in ll["ctype"].lower():
        ll_text = ll["body"][:50000].lower()
        home_text = (hd.get("title", "") + " " + hd.get("body_text", "")).lower()
        token_re = r"[a-zäöüà-ÿ0-9]{4,}"
        home_tokens = set(re.findall(token_re, home_text))
        ll_tokens = set(re.findall(token_re, ll_text))
        overlap = len(home_tokens & ll_tokens)
        domain_token = urllib.parse.urlparse(hurl).hostname.lower().replace("www.", "").split(".")[0]
        brand_match = bool(domain_token and domain_token in ll_text)
        overlap_ratio = overlap / max(1, len(ll_tokens))
        if len(ll_text.strip()) >= 80 and (brand_match or (overlap >= 5 and overlap_ratio >= 0.08)):
            ok("geo", "llms.txt contains basic signals relevant to the homepage")
        else:
            add("geo", "low", "llms.txt relevance could not be confirmed",
                "A readable file exists, but automated text checks found limited overlap with the homepage identity or topics.",
                "An inaccurate or outdated guidance file may confuse readers or systems. This heuristic cannot verify factual accuracy.", [hurl],
                "llms.txt token overlap=" + str(overlap) + "; domain token match=" + str(brand_match))
    else:
        add("geo", "low", "No readable llms.txt file detected",
            "No readable /llms.txt file was found.",
            "llms.txt is an optional emerging convention, not a universal requirement or a confirmed ranking factor. Its absence alone does not mean GEO readiness is poor.", [hurl])

    types = {x: ld_types(d["ld"]) for x, d in pages.items()}
    chk("geo", pg(lambda d: not d["ld"]), "medium", "No JSON-LD structured data detected",
        "have no JSON-LD structured data in the HTML returned to the crawler",
        "Structured data can make selected facts about a page easier for software to interpret, but it must be accurate and appropriate to the page.",
        "JSON-LD structured data is present")
    chk("geo", [x for x, (_, bad_count) in types.items() if bad_count], "medium",
        "Some JSON-LD could not be parsed",
        "contain one or more JSON-LD blocks that failed JSON parsing",
        "Malformed blocks may be ignored by systems that rely on them. This check validates JSON syntax only, not schema.org rules or eligibility.",
        "JSON-LD blocks passed basic JSON parsing")

    entity_types = types[hurl][0]
    business_types = {"organization", "localbusiness", "professionalservice", "medicalbusiness"}
    business_entities = ld_entities(hd["ld"])
    declared_business = any(t in business_types for t in entity_types)

    if not declared_business:
        add("geo", "medium", "Business identity is not explicit in structured data",
            "No Organization or LocalBusiness-type entity was detected in the homepage JSON-LD.",
            "A clear machine-readable business identity can help disambiguate who operates the website. This is a useful signal for business sites, but not every website needs a business entity.", [hurl])
    else:
        named_entities = [e for e in business_entities if e.get("name")]
        if not named_entities:
            add("geo", "medium", "Structured business entity has no readable name",
                "A business-type schema was detected, but no non-empty name was extracted from it.",
                "Without a clear name, the structured entity provides less useful identity information. The automated parser may miss some valid schema patterns.", [hurl])
        else:
            page_identity = (hd.get("title", "") + " " + hd.get("body_text", "")).lower()
            domain_token = urllib.parse.urlparse(hurl).hostname.lower().replace("www.", "").split(".")[0]
            def norm_identity(value):
                return re.sub(r"[^a-z0-9]+", " ", (value or "").lower()).strip()
            norm_page = norm_identity(page_identity)
            norm_domain = norm_identity(domain_token)
            mismatched = [
                e for e in named_entities
                if norm_identity(e["name"]) not in norm_page
                and not (norm_domain and norm_domain in norm_identity(e["name"]))
            ]
            if mismatched:
                add("geo", "medium", "Business identity may be inconsistent",
                    "At least one structured business name could not be matched to the extracted homepage text or domain name.",
                    "Conflicting business names can make it harder to associate the page with the correct entity. This is a heuristic warning, not proof of an error.", [hurl],
                    json.dumps(mismatched[:3], ensure_ascii=False))
            else:
                ok("geo", "A business name in structured data broadly matches the homepage identity")

        # Check useful fields on detected business entities, rather than only schema presence.
        parsed_business = []
        def collect_business(o):
            if isinstance(o, list):
                for item in o:
                    collect_business(item)
            elif isinstance(o, dict):
                typ = o.get("@type", [])
                type_list = [typ] if isinstance(typ, str) else typ if isinstance(typ, list) else []
                if any(str(t).lower() in business_types for t in type_list):
                    parsed_business.append(o)
                for value in o.values():
                    collect_business(value)
        for blob in hd["ld"]:
            try:
                collect_business(json.loads(blob))
            except Exception:
                pass
        if parsed_business:
            missing_name = any(not str(o.get("name", "")).strip() for o in parsed_business)
            missing_url = any(not str(o.get("url", "")).strip() for o in parsed_business)
            missing_desc = any(not str(o.get("description", "")).strip() for o in parsed_business)
            if missing_name:
                # Avoid duplicating the same issue when the earlier name check already reported it.
                if named_entities:
                    add("geo", "medium", "Some business schema lacks a name",
                        "At least one detected business entity is missing a name.",
                        "Incomplete entity fields can reduce the usefulness of structured identity information.", [hurl])
            elif missing_url or missing_desc:
                fields = []
                if missing_url: fields.append("url")
                if missing_desc: fields.append("description")
                add("geo", "low", "Business schema has limited descriptive fields",
                    "At least one business entity is missing: " + " and/or ".join(fields) + ".",
                    "A canonical URL and a concise, accurate description can provide useful context. These fields should reflect the visible website and are not a guarantee of AI visibility.", [hurl])
            else:
                ok("geo", "Business schema includes a name, URL and description")

    # Assess visible content in bands; word count is only one signal, never a quality verdict.
    words = hd.get("words", 0)
    if words < 100:
        add("geo", "high", "Very little extractable homepage content",
            f"Only about {words} words were extracted from the homepage HTML.",
            "Very limited text gives systems little explicit information to interpret, summarise or quote. JavaScript-rendered text may not be included in this scan.", [hurl])
    elif words < 250:
        add("geo", "medium", "Limited extractable homepage content",
            f"About {words} words were extracted from the homepage HTML.",
            "The page may not provide enough explicit context about the organisation, its offer and relevant details. Word count alone does not determine content quality.", [hurl])
    else:
        ok("geo", "Homepage contains a reasonable amount of extractable text (quantity only)")

    # Heading usefulness: count descriptive headings and flag generic/empty heading structure.
    headings = [x[1].strip() for x in hd["h"] if x[0] in ("h1", "h2", "h3") and len(x[1].strip()) >= 4]
    generic_headings = {
        "home", "welcome", "learn more", "read more", "about us", "our services",
        "services", "contact us", "get started", "mehr erfahren", "willkommen",
        "nos services", "en savoir plus"
    }
    descriptive_headings = [h for h in headings if re.sub(r"[^a-zäöüà-ÿ0-9 ]", "", h.lower()).strip() not in generic_headings]
    if len(descriptive_headings) < 2:
        add("geo", "low", "Limited descriptive heading structure",
            f"Only {len(descriptive_headings)} clearly descriptive H1/H2/H3 headings were detected.",
            "Descriptive headings help readers and systems identify the page's topics. This check cannot judge whether the content beneath each heading is accurate or useful.", [hurl])
    else:
        ok("geo", "Multiple descriptive headings provide topic structure")

    # Check whether the homepage appears to explain its subject, rather than only presenting slogans.
    title_and_headings = " ".join([hd.get("title", "")] + headings).strip()
    meaningful_chars = len(re.sub(r"\s+", "", title_and_headings))
    sentence_like = re.findall(r"[^.!?。！？]{35,}[.!?。！？]", hd.get("body_text", ""))
    if meaningful_chars < 25 or len(sentence_like) < 2:
        add("geo", "low", "Few explicit explanatory content signals",
            "The extracted title/headings are very short or the page contains few sentence-like explanatory passages in the returned HTML.",
            "AI-search systems need clear context to interpret a page. This is a rough text heuristic and may miss short-form, multilingual or JavaScript-rendered content.", [hurl])
    else:
        ok("geo", "Some explicit explanatory text is present (basic text heuristic)")

    # A useful topical link can provide context, but it is not required for every homepage.
    internal_paths = []
    for href in hd.get("links", []):
        absolute = urllib.parse.urljoin(hurl, href)
        parsed_link = urllib.parse.urlparse(absolute)
        if parsed_link.scheme in ("http", "https") and host(absolute) == host(hurl):
            internal_paths.append(parsed_link.path.lower().strip("/"))
    topic_link = any(
        any(term in path.split("/") for term in ("about", "service", "services", "product", "products", "leistungen", "angebot", "ueber-uns", "über-uns"))
        for path in internal_paths
    )
    if topic_link:
        ok("geo", "Homepage links to at least one about, service or product page")
    else:
        add("geo", "low", "No obvious about, service or product link detected",
            "No internal homepage link with a commonly recognised about/service/product path was detected.",
            "Relevant internal pages can provide additional context about the business and its offer. Custom URL structures may not be recognised by this check.", [hurl])

    # Many AI crawlers read the HTML without running JavaScript: compare that HTML with what the browser shows.
    shown = hp["rendered"]["words"]
    if shown >= 80 and raw["words"] < shown * 0.5:
        sev = "high" if raw["words"] < shown * 0.2 else "medium"
        add("geo", sev, "Much of the text only appears with JavaScript",
            f"Visitors see about {shown} words, but the HTML sent to crawlers contains about {raw['words']}.",
            "Many AI crawlers and some search tools do not run JavaScript, so text that is added in the browser may be invisible to them.", [hurl],
            f"rendered={shown}; raw html={raw['words']}")
    else:
        ok("geo", "The main text is already in the HTML (readable without JavaScript)")

    S["geo"] = "done"

    # Content: what a visitor actually reads. Text repeated on most pages (menu, footer, cookie banner) is not counted.
    S["content"] = "running"
    lines = {x: [l.strip() for l in r["rendered"]["text"].splitlines() if len(l.strip()) > 2] for x, r in rend.items()}
    boiler = set()
    if n >= 3:
        seen = {}
        for ls in lines.values():
            for l in set(ls): seen[l] = seen.get(l, 0) + 1
        boiler = {l for l, c in seen.items() if c >= max(2, 0.6 * n)}
    main_words = {x: sum(len(l.split()) for l in ls if l not in boiler) for x, ls in lines.items()}
    legal = re.compile(r"impressum|imprint|datenschutz|privacy|agb|terms|cookie|kontakt|contact|legal|mentions", re.I)
    hw = main_words.get(hurl, 0)
    if hw < 150:
        add("content", "high", "The homepage says very little", f"Visitors see only about {hw} words of real content on the homepage (menu and footer not counted).",
            "A homepage needs to explain what you offer, for whom, where and why to choose you. Short slogans and images alone "
            "leave visitors and search engines guessing.", [hurl], f"main words={hw}")
    elif hw < 300:
        add("content", "medium", "Homepage content is thin", f"The homepage has about {hw} words of real content (menu and footer not counted).",
            "More explanation of the offer, the audience and the benefits helps visitors decide and gives search engines more to work with.", [hurl])
    else:
        ok("content", f"The homepage has a reasonable amount of real content ({hw} words)")
    content_pages = [x for x in pages if x != hurl and not legal.search(x)]
    thin = [x for x in content_pages if main_words.get(x, 0) < 150]
    if content_pages and len(thin) >= max(1, len(content_pages) / 2):
        add("content", "high", "Most subpages are thin", f"{len(thin)} of {len(content_pages)} content pages have fewer than 150 words of their own content.",
            "Pages with very little text rarely rank or convince visitors; each page should answer the questions its title raises.", thin,
            json.dumps({x: main_words[x] for x in thin[:8]}))
    elif thin:
        add("content", "medium", "Some subpages are thin", f"{len(thin)} of {len(content_pages)} content pages have fewer than 150 words of their own content.",
            "Pages with very little text rarely rank or convince visitors.", thin, json.dumps({x: main_words[x] for x in thin[:8]}))
    elif content_pages:
        ok("content", "Subpages have their own content")
    placeholder = re.compile(r"lorem ipsum|dolor sit amet|i'?m a (?:paragraph|title)|add (?:your )?(?:paragraph|title) text|this is your "
                             r"(?:about|blog|page)|click (?:here )?to edit|double click to edit|your (?:business|company) name|"
                             r"ich bin ein (?:absatz|titel)|text hier einf\u00fcgen|hier klicken,? um", re.I)
    ph = [x for x, r in rend.items() if placeholder.search(r["rendered"]["text"])]
    if ph:
        add("content", "high", "Template placeholder text is still online", f"{len(ph)} of {n} analysed pages still show template text such as 'Lorem ipsum' or 'I'm a paragraph'.",
            "Placeholder text looks unfinished and immediately lowers trust.", ph,
            json.dumps({x: placeholder.search(rend[x]["rendered"]["text"]).group(0) for x in ph[:5]}))
    else:
        ok("content", "No template placeholder text found")
    dup = {}
    for x in content_pages:
        key = " ".join(l for l in lines[x] if l not in boiler)[:400].lower()
        if len(key) > 60: dup.setdefault(key, []).append(x)
    dups = [x for v in dup.values() if len(v) > 1 for x in v]
    if dups:
        add("content", "medium", "Pages repeat the same content", f"{len(dups)} of {n} analysed pages start with the same text as another page.",
            "Duplicate pages compete with each other and give visitors nothing new.", dups)
    elif len(content_pages) > 1:
        ok("content", "Subpages have distinct content")
    all_links = " ".join(urllib.parse.unquote(l).lower() for r in rend.values() for l in r["rendered"]["links"])
    all_text = " ".join(r["rendered"]["text"].lower() for r in rend.values())
    topics = [("About / team page", r"about|ueber-uns|uber-uns|\u00fcber-uns|team|qui-sommes|chi-siamo|tentang", "medium",
               "Visitors want to know who is behind the business before they book or buy."),
              ("Services / offer page", r"service|leistung|angebot|offer|kurs|klassen|class|course|produkt|product|treatment|behandlung|layanan", "medium",
               "A page per service or offer explains what visitors get and gives search engines a page to rank for each topic."),
              ("Prices", r"preis|price|pricing|tarif|kosten|cost|harga|prix|prezzi", "low",
               "Clear prices (or a 'from' price) remove a common reason not to enquire."),
              ("FAQ", r"faq|fragen|questions|haeufige|h\u00e4ufige|domande|pertanyaan", "low",
               "Answers to common questions help visitors decide and are easy for AI-search systems to quote.")]
    for label, rx, sev, why in topics:
        if re.search(rx, all_links): ok("content", label + " found")
        else: add("content", sev, label + " not found", f"No {label.lower()} was found in the links of the analysed pages.", why)
    if re.search(r"testimonial|review|bewertung|kundenstimme|erfahrungsbericht|rezension|avis client|recensioni|ulasan|\u2605|google rating|trustpilot", all_text):
        ok("content", "Reviews or testimonials are shown")
    else:
        add("content", "medium", "No reviews or testimonials found", "No reviews, testimonials or ratings were found on the analysed pages.",
            "Feedback from real customers is one of the strongest trust signals for new visitors.")
    years = [int(r["rendered"]["copyright"]) for r in rend.values() if r["rendered"]["copyright"]]
    if years and max(years) < int(time.strftime("%Y")) - 1:
        add("content", "low", "Copyright year looks outdated", f"The footer shows {max(years)}.",
            "An old year makes the website look unmaintained.", [hurl])
    elif years:
        ok("content", "Copyright year is current")
    S["content"] = "done"

    # Enquiry journey
    S["journey"] = "running"
    hl = [h.lower() for h in hd["links"]]
    if any(h.startswith(("mailto:", "tel:")) or "wa.me" in h or "contact" in h or "kontak" in h for h in hl): ok("journey", "A contact route is linked from the homepage")
    else: add("journey", "high", "No clear contact route on the homepage", "The homepage has no email, phone, WhatsApp or contact-page link.", "Visitors who want to enquire need an obvious way to reach you.", [hurl])
    cta_texts = hd["atext"] + hd.get("buttons", [])
    if any(c in a for a in cta_texts for c in CTA):
        ok("journey", "A recognised CTA label was found in a link or button")
    else:
        add("journey", "medium", "No recognised call-to-action label", "No recognised CTA phrase was found in extracted link or button text.", "A clear next step helps visitors act. Detection covers common English, German, French, Italian and Indonesian phrases, but custom wording or text rendered only by JavaScript may be missed.", [hurl])
    if any(len(a.strip()) >= 5 for a in cta_texts):
        ok("journey", "Some links or buttons have descriptive labels")
    else:
        add("journey", "low", "Limited descriptive link/button labels", "No link or button with a descriptive text label was extracted.", "Descriptive labels help visitors understand the next action and improve accessibility. This does not assess visual prominence or usability.", [hurl])
    if sum(d["forms"] for d in pages.values()): ok("journey", "An enquiry form was found")
    else: add("journey", "medium", "No form found on analysed pages", f"None of the {n} analysed pages contains a form.", "Forms are an easy way for visitors to enquire, though not the only one.")
    contact_rx = re.compile(r"kontakt|contact|anfrage|enquir|inquir|hubungi|contatt", re.I)
    if any(contact_rx.search(urllib.parse.unquote(x)) for x in hp["rendered"]["nav"]):
        ok("journey", "The contact page is one click away in the menu")
    else:
        add("journey", "medium", "Contact page is not in the menu", "No contact page link was found in the header / navigation menu.",
            "Visitors look for 'Contact' in the menu; if it is missing they have to search, and many give up.", [hurl])
    contact_pages = [x for x in pages if contact_rx.search(urllib.parse.unquote(x))]
    for x in contact_pages[:1]:
        d = pages[x]
        if d["forms"] or any(l.lower().startswith(("tel:", "mailto:")) for l in d["links"]):
            ok("journey", "The contact page offers a form, a phone link or an email link")
        else:
            add("journey", "medium", "Contact page has no direct way to get in touch", "The contact page has no form and no clickable phone or email link.",
                "A contact page should let visitors act immediately, not only read an address.", [x])
    first = mob["rendered"]["first_screen"]
    if any(any(c in f["label"] for c in CTA) or f["href"].lower().startswith(("tel:", "mailto:")) or "wa.me" in f["href"] or "whatsapp" in f["href"]
           for f in first):
        ok("journey", "A call to action is visible on the first screen on a phone")
    else:
        add("journey", "medium", "No call to action on the first phone screen", "On a phone-sized screen, no contact / booking button or link is visible before scrolling.",
            "Most visitors arrive on a phone; if the next step is not visible straight away, many leave without acting.", [hurl],
            json.dumps([f["label"] for f in first][:12], ensure_ascii=False))
    offsite = sorted({urllib.parse.urlparse(l).hostname for r in rend.values() for l in r["rendered"]["links"]
                      if urllib.parse.urlparse(l).scheme in ("http", "https") and host(l) != host(hurl)
                      and re.search(r"book|calendar|termin|schedule|appointment|reserv|bsport|eversports|calendly|shop", l, re.I)})
    if offsite:
        add("journey", "low", "Booking or buying continues on another website", "Booking / scheduling links lead to: " + ", ".join(offsite[:4]) + ".",
            "Switching to another website can feel unexpected; say clearly where the link goes, and make sure enquiries can be tracked.",
            ev=", ".join(offsite))
    m = mob["rendered"]
    if m["overflow"]:
        add("journey", "medium", "Page is wider than a phone screen", "On a phone-sized screen the homepage scrolls sideways.",
            "Sideways scrolling makes text hard to read and buttons hard to reach on phones.", [hurl])
    else:
        ok("journey", "The homepage fits a phone screen")
    if m["small_targets"] > 5:
        add("journey", "low", "Small buttons and links on phones", f"{m['small_targets']} visible links or buttons are smaller than 32x32 pixels on a phone-sized screen.",
            "Small tap targets are easy to miss with a finger.", [hurl])
    if m["text_elements"] and m["tiny_text"] / m["text_elements"] > 0.2:
        add("journey", "low", "Text is very small on phones", f"{m['tiny_text']} of {m['text_elements']} text elements use a font smaller than 12px on a phone.",
            "Very small text is hard to read without zooming.", [hurl])
    schema_phones = set()
    for d in pages.values():
        for blob in d["ld"]:
            for tel in re.findall(r'"telephone"\s*:\s*"([^"]+)"', blob):
                try: schema_phones.add(normalize_phone(tel, A.get("country")))
                except ValueError: pass
    country_checks(add, ok, A.get("country"), A.get("phone"), hd.get("lang"), [r["rendered"]["text"] for r in rend.values()],
                   [l for r in rend.values() for l in r["rendered"]["links"]], hp["rendered"]["hreflang"], schema_phones)
    S["journey"] = "done"

    # Speed
    if home["ms"] > 1500: add("speed", "medium", "Slow server response", f"The server took {home['ms']} ms to deliver the homepage HTML.", "Slow responses delay everything that follows.", [hurl])
    else: ok("speed", "The server responds quickly")
    slow = [x for x, r in rend.items() if r["ms"] > 5000]
    chk("speed", slow, "medium", "Pages load slowly in the browser", "took longer than 5 seconds to finish loading in the browser",
        "Visitors wait for the full page; slow pages are left before they finish.", "Pages finish loading in the browser within 5 seconds")
    th.join(max(1, 75 - (time.time() - t0)))
    speed = None
    if "score" in psi:
        speed = psi["score"]
        sev = "high" if speed < 50 else "medium" if speed < 90 else None
        if sev: add("speed", sev, "Mobile performance can be improved", f"Lighthouse mobile performance score is {speed}/100 for the homepage.", "Slower pages create a less comfortable experience and can reduce enquiries.", [hurl])
        else: ok("speed", f"Homepage mobile performance score is {speed}/100")
        S["speed"] = "done"
    else:
        S["speed"] = "unavailable"
        notes.append("PageSpeed data was unavailable for this run" + (f" ({psi['error']})" if psi.get("error") else "") + "; no PageSpeed score is shown.")

    # Use the SEO category returned by the same PageSpeed Insights API request as a cross-check.
    # It is not a separate API and does not replace the crawler's SEO checks.
    lighthouse_seo = psi.get("lighthouse_seo")
    if lighthouse_seo is not None and lighthouse_seo < 80:
        sev = "high" if lighthouse_seo < 50 else "medium"
        add("seo", sev, "Lighthouse SEO checks found issues", f"Google Lighthouse returned an SEO category score of {lighthouse_seo}/100 for the homepage.", "This is a supplementary set of technical SEO checks. Review it alongside the individual findings; it does not measure content quality or rankings.", [hurl], f"Lighthouse SEO score={lighthouse_seo}")

    # Summary
    S["summary"] = "running"
    if js_shell:
        notes.append("The HTML sent by the server is almost empty: this website builds its content with JavaScript. The browser "
                     "audit sees the content, but crawlers that do not run JavaScript may not.")
    for f in A["customer"]:
        f["blocker"] = f["title"] in BLOCKERS and f["sev"] == "high"
    sc, caps = {}, {}
    for c in CATS:
        issues = [x for x in A["customer"] if x["cat"] == c]
        weights = GEO_W if c == "geo" else W
        base = speed if c == "speed" else max(0, 100 - sum(weights[x["sev"]] for x in issues))
        if base is None:
            sc[c] = None
            continue
        # The worst open issue sets a ceiling, so many passed checks cannot hide one serious gap.
        worst = "blocker" if any(x["blocker"] for x in issues) else "high" if any(x["sev"] == "high" for x in issues) \
            else "medium" if any(x["sev"] == "medium" for x in issues) else None
        sc[c] = min(base, CAP[worst]) if worst else base
        if sc[c] < base: caps[c] = worst
    vals = {k: v for k, v in sc.items() if v is not None}
    # Overall: the average, but at most 20 points above the weakest area, and max 59 ("Needs work")
    # when two or more areas need work. Strong areas cannot average away weak ones.
    overall, limited_by = None, None
    if vals:
        avg = round(sum(vals.values()) / len(vals))
        weakest = min(vals, key=vals.get)
        overall = min(avg, vals[weakest] + 20)
        if sum(1 for v in vals.values() if v < 60) >= 2: overall = min(overall, 59)
        if overall < avg: limited_by = weakest
    order = sorted(A["customer"], key=lambda x: (not x["blocker"], -W[x["sev"]]))
    # Missing PSI is a coverage failure, not a passing score. Keep the numeric score provisional.
    speed_missing = speed is None
    assessment = "incomplete" if speed_missing else "complete"
    limitations = [
        "GEO score measures technical/content readiness signals only; it does not measure actual visibility or citations in AI-generated answers.",
        "Automated checks cannot fully assess factual accuracy, content expertise, visual design, keyboard/screen-reader usability, conversion rate, or real visitor behaviour.",
        "PageSpeed is measured for the homepage on mobile only. It is not a site-wide performance score.",
        "Content checks count and compare text; they cannot judge whether the text is accurate, persuasive or well written."
    ]
    psi_seo = psi.get("lighthouse_seo")
    if psi_seo is not None:
        notes.append(f"PageSpeed/Lighthouse SEO category score: {psi_seo}/100. This is a supplementary signal, not a replacement for the internal SEO audit.")
    A["report"] = dict(
        generated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), domain=urllib.parse.urlparse(hurl).hostname,
        final_url=hurl, scores=sc, overall=overall, limited_by=limited_by, caps=caps, js_rendered=bool(js_shell),
        findings=order, passed=A["passed"],
        # Presentation only (does not change any score): open issues and passed checks per category.
        checks={c: dict(passed=sum(1 for x in A["passed"] if x["cat"] == c),
                        **{k: sum(1 for x in A["customer"] if x["cat"] == c and x["sev"] == k) for k in ("high", "medium", "low")})
                for c in CATS},
        assessment_status=assessment, limitations=limitations,
        coverage=dict(pages_analysed=n, pages_discovered=A.get("pages_discovered", n), page_limit=MAX_PAGES, notes=notes,
                      speed=(f"Performance {speed}/100; LCP {psi['lcp']}, TBT {psi['tbt']}, CLS {psi['cls']}" if "score" in psi else None),
                      lighthouse_seo=psi_seo, speed_status="available" if not speed_missing else "unavailable"))
    S["summary"] = "done"
    A.update(status="partial" if speed_missing else "completed", message="Your report is ready" if not speed_missing else "Report ready, but PageSpeed data is missing")


# ---------- HTTP ----------
def deliver_lead(lead):
    print("LEAD", json.dumps(lead), flush=True)  # always visible in the host's logs
    url = os.environ.get("LEAD_WEBHOOK_URL")
    if url:
        try:
            urllib.request.urlopen(urllib.request.Request(url, data=json.dumps(lead).encode(), headers={"Content-Type": "application/json"}), timeout=10)
        except Exception as e:
            print("LEAD webhook failed:", type(e).__name__, flush=True)


class H(BaseHTTPRequestHandler):
    def send(s, code, obj, ctype="application/json"):
        b = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        s.send_response(code); s.send_header("Content-Type", ctype); s.send_header("Cache-Control", "no-store")
        s.send_header("Content-Length", str(len(b))); s.end_headers(); s.wfile.write(b)

    def do_GET(s):
        p = urllib.parse.urlparse(s.path).path
        m = re.fullmatch(r"/api/audits/([\w-]+)/(status|report)", p)
        if m:
            A = AUDITS.get(m[1])
            if not A: return s.send(404, {"error": "not found"})
            if m[2] == "status":
                return s.send(200, {k: A[k] for k in ("status", "steps", "pages_discovered", "pages_analysed", "message")})
            if A["status"] not in ("completed", "partial"): return s.send(409, {"error": "not ready"})
            return s.send(200, A["report"])  # customer-safe serializer only
        m = re.fullmatch(r"/api/internal/audits/([\w-]+)", p)
        if m:
            tok = os.environ.get("INTERNAL_TOKEN", "")
            if not tok or not hmac.compare_digest(s.headers.get("Authorization", ""), "Bearer " + tok): return s.send(404, {"error": "not found"})
            A = AUDITS.get(m[1])
            return s.send(200, dict(url=A["url"], findings=A["internal"], passed=A["passed"])) if A else s.send(404, {"error": "not found"})
        if p in ("/health", "/api/health"): return s.send(200, {"ok": True})
        if p == "/api/countries":  # the form's country list (with dial codes) comes from inputs.py, so both stay in sync
            return s.send(200, [dict(code=k, name=v[0], dial=v[1]) for k, v in sorted(COUNTRIES.items(), key=lambda kv: kv[1][0])])
        if p in ("/", "/index.html"):  # local dev convenience; in production Netlify serves the page
            for d in (HERE, os.path.join(HERE, "..", "frontend")):
                try: return s.send(200, open(os.path.join(d, "index.html"), "rb").read(), "text/html; charset=utf-8")
                except OSError: pass
            return s.send(200, {"ok": True})
        s.send(404, {"error": "not found"})

    def do_POST(s):
        if s.path != "/api/audits": return s.send(404, {"error": "not found"})
        ip, now = (s.headers.get("X-Nf-Client-Connection-Ip") or s.headers.get("X-Forwarded-For", "").split(",")[0].strip() or s.client_address[0]), time.time()
        HITS[ip] = [x for x in HITS.get(ip, []) if now - x < 3600]
        if len(HITS[ip]) >= RATE_LIMIT: return s.send(429, {"error": "Too many requests. Please try again later."})
        try: d = json.loads(s.rfile.read(min(int(s.headers.get("Content-Length", 0)), 10000)))
        except Exception: return s.send(400, {"error": "Invalid request."})
        if d.get("hp"): return s.send(200, {"token": secrets.token_urlsafe(16)})  # honeypot
        name, email, raw = str(d.get("name", "")).strip()[:100], str(d.get("email", "")).strip()[:200], str(d.get("url", "")).strip()
        country = str(d.get("country", "")).strip().upper()[:2]
        if not name or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or d.get("consent") is not True:
            return s.send(400, {"error": "Please complete all fields and accept the consent notice."})
        if country not in COUNTRIES and country != "XX":
            return s.send(400, {"error": "Please select the country or area of the business."})
        try: phone = normalize_phone(str(d.get("phone", ""))[:40], country)
        except ValueError: return s.send(400, {"error": "Please enter a valid phone number (with the country code, e.g. +41 76 123 45 67)."})
        try:
            url, scheme_given = normalize_url(raw)
            check(url)
        except Exception: return s.send(400, {"error": "Please enter a valid, public website address, e.g. https://www.example.com, www.example.com or example.com."})
        HITS[ip].append(now)
        for k in [k for k, v in list(AUDITS.items()) if now - v.get("at", now) > KEEP_SECONDS]: AUDITS.pop(k, None)
        token = secrets.token_urlsafe(16)
        A = AUDITS[token] = dict(url=url, scheme_given=scheme_given, phone=phone, country=country, status="queued", message="Waiting to start…", steps={k: "waiting" for k in STEPS},
                                 pages_discovered=0, pages_analysed=0, customer=[], internal=[], passed=[], report=None, at=now)
        lead = dict(name=name, email=email, phone=phone, country=country, url=url, consent=True, at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        threading.Thread(target=deliver_lead, args=(lead,), daemon=True).start()
        threading.Thread(target=run, args=(A,), daemon=True).start()
        s.send(200, {"token": token})

    def log_message(s, *a): pass


if __name__ == "__main__":
    host, port = os.environ.get("HOST", "127.0.0.1"), int(os.environ.get("PORT", 8000))
    print(f"Website audit running on http://{host}:{port}")
    ThreadingHTTPServer((host, port), H).serve_forever()
