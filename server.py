#!/usr/bin/env python3
"""AVANTICO audit backend (Python 3.9+, stdlib only).  Run: python3 server.py  ->  http://localhost:8000
Env: LEAD_WEBHOOK_URL (optional; receives each lead as JSON), PSI_KEY (optional Google PageSpeed API key), INTERNAL_TOKEN (enables /api/internal/*), RATE_LIMIT (audits per IP per hour, default 5), HOST, PORT,
ALLOW_PRIVATE=1 (dev only: lets the crawler reach localhost/private IPs)."""
import os, re, json, time, socket, hmac, ipaddress, secrets, threading
import urllib.request, urllib.parse, urllib.error
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_PAGES, TIMEOUT, MAX_BYTES, BUDGET = 12, 8, 1_500_000, 60
UA = "AVANTICO-AuditBot/1.0"
AI_BOTS = ["GPTBot", "ClaudeBot", "PerplexityBot", "Google-Extended", "CCBot"]
CTA = ("contact", "get started", "book", "quote", "enquir", "inquir", "demo", "call", "consult", "hubungi", "konsultasi")
W = {"high": 15, "medium": 8, "low": 3, "info": 0}
STEPS = ("connect", "seo", "geo", "journey", "speed", "summary")
ALLOW_PRIVATE = os.environ.get("ALLOW_PRIVATE") == "1"
RATE_LIMIT = int(os.environ.get("RATE_LIMIT", 5))
AUDIT_TTL = 2 * 3600  # finished or abandoned audits are forgotten after 2 hours
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


def fetch(url, method="GET"):
    check(url)
    t = time.time()
    req = urllib.request.Request(url, method=method, headers={"User-Agent": UA})
    try:
        r = OPENER.open(req, timeout=TIMEOUT)
    except urllib.error.HTTPError as e:
        r = e
    body = b"" if method == "HEAD" else r.read(MAX_BYTES)
    return dict(status=r.code, url=r.geturl(), ctype=r.headers.get("content-type", ""),
                body=body.decode("utf-8", "replace"), ms=int((time.time() - t) * 1000))


def tf(url, method="GET"):
    try:
        return fetch(url, method)
    except Exception:
        return None


# ---------- HTML parsing ----------
class P(HTMLParser):
    def __init__(s):
        super().__init__()
        s.d = dict(title="", meta={}, h=[], canon=None, noalt=0, links=[], atext=[], ld=[],
                   lang=None, viewport=False, forms=0, words=0)
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
        elif tag == "img" and "alt" not in a:
            d["noalt"] += 1
        elif tag == "form":
            d["forms"] += 1
        elif tag == "a" and a.get("href"):
            d["links"].append(a["href"]); s.cap, s.buf = "a", ""
        elif tag in ("title", "h1", "h2", "h3"):
            s.cap, s.buf = tag, ""
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
            else: d["h"].append((c, t))
            s.cap = None

    def handle_data(s, x):
        if s.cap:
            s.buf += x
        if not s.skip and s.cap != "ld":
            s.d["words"] += len(x.split())


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
    q = {"url": url, "strategy": "mobile", "category": "performance"}
    if os.environ.get("PSI_KEY"): q["key"] = os.environ["PSI_KEY"]
    try:
        r = urllib.request.urlopen("https://www.googleapis.com/pagespeedonline/v5/runPagespeed?" + urllib.parse.urlencode(q), timeout=90)
        j = json.load(r)["lighthouseResult"]; a = j["audits"]
        return dict(score=round(j["categories"]["performance"]["score"] * 100),
                    lcp=a["largest-contentful-paint"]["displayValue"],
                    tbt=a["total-blocking-time"]["displayValue"],
                    cls=a["cumulative-layout-shift"]["displayValue"])
    except urllib.error.HTTPError as e:
        try: msg = json.load(e)["error"]["message"]
        except Exception: msg = ""
        print("PSI error", e.code, msg[:300], flush=True)  # full reason is in the host's logs
        return {"error": f"HTTP {e.code}"}
    except Exception as e:
        print("PSI error", type(e).__name__, flush=True)
        return {"error": type(e).__name__}


# ---------- the audit ----------
ASSET = re.compile(r"\.(jpe?g|png|gif|webp|svg|pdf|zip|css|js|ico|mp4|xml)$", re.I)


def run(A):
    try:
        _run(A)
    except Exception as e:
        A["internal"].append(dict(cat="system", sev="info", title="Audit failed", what=repr(e), why="", urls=[], evidence=""))
        A.update(status="failed", message="We couldn't reach or read this website. Please check the address and try again.")


def _run(A):
    t0, S, notes = time.time(), A["steps"], []
    url = A["url"]; u = urllib.parse.urlparse(url); origin = f"{u.scheme}://{u.netloc}"
    A.update(status="discovering", message="Connecting to your website…"); S["connect"] = "running"
    home = fetch(url)
    if home["status"] >= 400 or "html" not in home["ctype"].lower():
        raise RuntimeError(f"homepage status {home['status']}")
    S["connect"] = "done"; hurl = home["url"]
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

    pages = {hurl: {**parse(home), "status": 200}}
    hd = pages[hurl]
    cand = []
    for h in hd["links"] + locs:
        x = urllib.parse.urldefrag(urllib.parse.urljoin(hurl, h))[0]
        p = urllib.parse.urlparse(x)
        if p.scheme in ("http", "https") and host(x) == host(hurl) and not ASSET.search(p.path) \
                and x.rstrip("/") != hurl.rstrip("/") and x not in cand:
            cand.append(x)
    cand = cand[:MAX_PAGES - 1]
    A.update(status="analysing", pages_discovered=len(cand) + 1, pages_analysed=1, message="Analysing pages…")
    S["seo"] = "running"; skipped = 0
    for x in cand:
        if time.time() - t0 > BUDGET:
            notes.append("The time budget was reached, so some discovered pages were not analysed."); break
        r = tf(x)
        if r and r["status"] < 400 and "html" in r["ctype"].lower():
            pages[r["url"]] = {**parse(r), "status": r["status"]}
        else:
            skipped += 1
        A["pages_analysed"] = len(pages)
    if skipped: notes.append(f"{skipped} discovered page(s) could not be analysed (errors or non-HTML responses).")
    n = len(pages)

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
    chk("seo", pg(lambda d: not h1(d)), "medium", "Pages without a main heading (H1)", "have no H1", "A clear H1 tells visitors and crawlers what the page is about.", "Every analysed page has an H1")
    chk("seo", pg(lambda d: len(h1(d)) > 1), "low", "Multiple H1 headings", "have more than one H1", "One main heading per page keeps the structure unambiguous.", "No page has multiple H1s")
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
    else: ok("seo", "Homepage internal links checked are working")
    S["seo"] = "done"

    # GEO
    S["geo"] = "running"
    bots = [b for b in AI_BOTS if b.lower() in blocked]
    if bots: add("geo", "medium", "Some AI crawlers are blocked", f"robots.txt blocks: {', '.join(bots)}.", "Blocked crawlers cannot read your content for those AI products. This may be intentional.")
    else: ok("geo", "No major AI crawler is blocked in robots.txt")
    ll = tf(origin + "/llms.txt")
    if ll and ll["status"] == 200 and "html" not in ll["ctype"].lower(): ok("geo", "llms.txt file found")
    else: add("geo", "low", "No llms.txt file", "No /llms.txt file was found.", "It is an emerging convention for describing a site to AI tools; it is not a confirmed ranking factor.")
    types = {}
    for x, d in pages.items(): types[x] = ld_types(d["ld"])
    chk("geo", pg(lambda d: not d["ld"]), "medium", "Pages without structured data", "have no JSON-LD structured data", "Structured data states facts about a page in a machine-readable way.", "Structured data is present on all analysed pages")
    chk("geo", [x for x, (_, b) in types.items() if b], "low", "Invalid structured data", "contain JSON-LD that cannot be parsed", "Broken structured data is ignored by search and AI systems.", "Structured data parses correctly")
    if any("organization" in t_ or "business" in t_ for t_ in types[hurl][0]): ok("geo", "Organisation/business details are declared in structured data")
    else: add("geo", "medium", "No organisation details in structured data", "The homepage does not declare an Organization or LocalBusiness entity.", "Explicit entity details help systems identify who you are and what you offer.", [hurl])
    chk("geo", pg(lambda d: d["words"] < 150), "medium", "Pages with very little text", "contain fewer than 150 words", "Thin pages give search and AI systems little to understand or quote.", "Analysed pages have substantial text")
    S["geo"] = "done"

    # Enquiry journey
    S["journey"] = "running"
    hl = [h.lower() for h in hd["links"]]
    if any(h.startswith(("mailto:", "tel:")) or "wa.me" in h or "contact" in h or "kontak" in h for h in hl): ok("journey", "A contact route is linked from the homepage")
    else: add("journey", "high", "No clear contact route on the homepage", "The homepage has no email, phone, WhatsApp or contact-page link.", "Visitors who want to enquire need an obvious way to reach you.", [hurl])
    if any(c in a for a in hd["atext"] for c in CTA): ok("journey", "The homepage has a call-to-action link")
    else: add("journey", "medium", "No call-to-action link on the homepage", "No link text such as 'contact', 'get a quote' or 'book' was found on the homepage.", "A clear next step helps visitors act.", [hurl])
    if sum(d["forms"] for d in pages.values()): ok("journey", "An enquiry form was found")
    else: add("journey", "medium", "No form found on analysed pages", f"None of the {n} analysed pages contains a form.", "Forms are an easy way for visitors to enquire, though not the only one.")
    S["journey"] = "done"

    # Speed
    slow = pg(lambda d: d["ms"] > 1500)
    chk("speed", slow, "medium", "Slow server response", "took longer than 1.5 seconds to deliver the HTML", "Slow responses delay everything that follows.", "Pages respond quickly")
    th.join(max(1, 100 - (time.time() - t0)))
    speed = None
    if "score" in psi:
        speed = psi["score"]
        sev = "high" if speed < 50 else "medium" if speed < 90 else None
        if sev: add("speed", sev, "Mobile performance can be improved", f"Lighthouse mobile performance score is {speed}/100 for the homepage.", "Slower pages create a less comfortable experience and can reduce enquiries.", [hurl])
        else: ok("speed", f"Homepage mobile performance score is {speed}/100")
        S["speed"] = "done"
    else:
        S["speed"] = "unavailable"
        notes.append("PageSpeed data was unavailable for this run" + (f" ({psi['error']})" if psi.get("error") else " (the request timed out)") + "; no PageSpeed score is shown.")

    # Summary
    S["summary"] = "running"
    sc = {}
    for c in ("seo", "geo", "journey"):
        sc[c] = max(0, 100 - sum(W[x["sev"]] for x in A["customer"] if x["cat"] == c))
    sc["speed"] = speed
    vals = [v for v in sc.values() if v is not None]
    order = sorted(A["customer"], key=lambda x: -W[x["sev"]])
    A["report"] = dict(
        generated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), domain=urllib.parse.urlparse(hurl).hostname,
        scores=sc, overall=round(sum(vals) / len(vals)) if vals else None, findings=order, passed=A["passed"],
        coverage=dict(pages_analysed=n, pages_discovered=len(cand) + 1, page_limit=MAX_PAGES, notes=notes,
                      speed=(f"LCP {psi['lcp']}, TBT {psi['tbt']}, CLS {psi['cls']}" if "score" in psi else None)))
    S["summary"] = "done"
    A.update(status="partial" if notes else "completed", message="Your report is ready", pages_discovered=len(cand) + 1)


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
        if not name or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or d.get("consent") is not True:
            return s.send(400, {"error": "Please complete all fields and accept the consent notice."})
        url = raw if re.match(r"https?://", raw, re.I) else "https://" + raw
        try: check(url)
        except Exception: return s.send(400, {"error": "Please enter a valid, public website address."})
        HITS[ip].append(now)
        for k in [k for k, v in list(AUDITS.items()) if now - v["created"] > AUDIT_TTL]: AUDITS.pop(k, None)  # no old results kept around
        for k in [k for k, v in list(HITS.items()) if not v]: HITS.pop(k, None)
        token = secrets.token_urlsafe(16)
        A = AUDITS[token] = dict(created=now, url=url, status="queued", message="Waiting to start…", steps={k: "waiting" for k in STEPS},
                                 pages_discovered=0, pages_analysed=0, customer=[], internal=[], passed=[], report=None)
        lead = dict(name=name, email=email, url=url, consent=True, at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        threading.Thread(target=deliver_lead, args=(lead,), daemon=True).start()
        threading.Thread(target=run, args=(A,), daemon=True).start()
        s.send(200, {"token": token})

    def log_message(s, *a): pass


if __name__ == "__main__":
    host, port = os.environ.get("HOST", "127.0.0.1"), int(os.environ.get("PORT", 8000))
    print(f"AVANTICO audit running on http://{host}:{port}")
    ThreadingHTTPServer((host, port), H).serve_forever()
