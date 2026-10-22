# AVANTICO Website Visibility Audit Tool

A lead-generation tool that audits a public website and returns a clear, customer-friendly report covering **SEO**, **GEO (AI-search readiness)**, **PageSpeed** and the **enquiry journey**. A visitor enters their name, email and website; the tool crawls the site, scores it and shows the results in the browser.

- **Backend:** one Python file (`server.py`), standard library only. No `pip install`.
- **Frontend:** one HTML file (`index.html`), Bootstrap 5.0.2 and Plus Jakarta Sans via CDN.
- **Hosting:** runs anywhere Docker or Python 3.9+ runs. The server serves the page and the API from one origin, so no separate frontend host or proxy is needed.

## Files

| File | Purpose |
|---|---|
| `server.py` | Crawler, scoring, API and static page server |
| `index.html` | The whole UI: form, progress screen, report |
| `Dockerfile` | Container image (Python 3.12 slim, port 8000) |
| `README.md` | This document |

## How it works

1. The visitor submits name, email, website URL and a consent checkbox.
2. The backend creates an audit (random token), stores the lead, and starts the audit in a background thread.
3. The page polls `/api/audits/<token>/status` every 1.5 s and shows live progress for six steps: connect, SEO, GEO, enquiry journey, speed, summary.
4. When finished, the page loads the report and shows: overall score, four category scores, "things to know first" (top 5 findings), full findings per category, passed checks, and coverage notes.

### What is checked

| Category | Checks |
|---|---|
| **SEO** | Titles (missing, length, duplicates), meta descriptions, H1 (missing, multiple), noindex, canonical links, image alt text, mobile viewport, `lang` attribute, HTTPS, robots.txt, XML sitemap, broken internal links on the homepage |
| **GEO** | AI crawlers blocked in robots.txt (GPTBot, ClaudeBot, PerplexityBot, Google-Extended, CCBot), `llms.txt`, JSON-LD structured data (present, valid, Organization/LocalBusiness), thin content (< 150 words) |
| **Enquiry journey** | Contact route on homepage (email, phone, WhatsApp or contact page), call-to-action link, form present |
| **PageSpeed** | Server response time, and Google PageSpeed Insights (mobile, homepage): score, LCP, TBT, CLS |

### Scoring

- SEO, GEO and Enquiry journey each start at 100 and lose points per finding: **High -15, Medium -8, Low -3**.
- PageSpeed uses the Lighthouse mobile performance score directly (shown as unavailable if the API did not answer).
- The overall score is the average of the available category scores.
- Score bands: 80+ "Looking good", 60-79 "Needs attention", below 60 "Needs work".

The report footer shows an **Audit ID**, how long the audit took and when the PageSpeed test actually ran. A different Audit ID proves a new audit; a repeated PageSpeed time means Google reused its own earlier test.

### Crawl limits

Up to **12 pages** per audit (homepage plus pages found in its links and the sitemap), **8 s** timeout per request, **1.5 MB** per page, **60 s** crawl budget. If a limit is reached, the report says so under "Coverage & method".

## Run locally

```bash
python3 server.py
# open http://localhost:8000
```

To audit a site running on your own machine (development only):

```bash
ALLOW_PRIVATE=1 python3 server.py
```

## Run with Docker

```bash
docker build -t site-audit .
docker run -p 8000:8000 -e PSI_KEY=your_key site-audit
```

## Deploy

Push the four files to a git repository and connect it to any host that builds a Dockerfile (for example SnapDeploy). Set the environment variables below. The health check path is `/health`. Because the server serves `index.html` itself, the host's public URL is the tool's URL.

> Every audit gets its own random token and its own isolated state; the page is fully reset before each new audit. Reports and audits are held **in memory** and are forgotten after 2 hours, or when the container restarts or redeploys. That is fine for a live demo; for persistent reports, add storage first.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `PSI_KEY` | Recommended | Google PageSpeed Insights API key (free; create it in a Google Cloud project). Without a key the API is heavily rate limited and PageSpeed may show as unavailable. |
| `LEAD_WEBHOOK_URL` | Optional | Every lead (name, email, URL, consent, timestamp) is POSTed here as JSON, for example a Zapier, Make or Google Apps Script webhook. Leads are always printed to the server log as `LEAD {...}` as a fallback. |
| `INTERNAL_TOKEN` | Optional | Enables the private endpoint `/api/internal/audits/<token>` that returns the detailed internal findings. Send it as `Authorization: Bearer <token>`. Disabled when unset. |
| `HOST` | Optional | Bind address. Use `0.0.0.0` in containers (the Dockerfile sets it). Default `127.0.0.1`. |
| `PORT` | Optional | Port. Default `8000`. |
| `RATE_LIMIT` | Optional | Audits allowed per IP per hour. Default `5`; raise it while testing. |
| `PSI_BYPASS_CACHE` | Optional | `1` makes every audit ask Google for a brand-new PageSpeed run (by adding a unique query string to the tested URL). Off by default: that URL can skip the site's own page cache, so scores may look slightly worse than real visitors see. |
| `ALLOW_PRIVATE` | Dev only | `1` lets the crawler reach localhost and private IPs. Never set in production. |

## API

| Method and path | Description |
|---|---|
| `POST /api/audits` | Body: `{name, email, url, consent: true}`. Returns `{token}`. |
| `GET /api/audits/<token>/status` | Status, per-step progress, pages discovered and analysed. |
| `GET /api/audits/<token>/report` | The customer-safe report (409 until ready). |
| `GET /api/internal/audits/<token>` | Detailed internal findings with affected URLs. Requires `INTERNAL_TOKEN`. |
| `GET /health` | Health check. |

## Safeguards

- **SSRF protection:** hostnames are resolved and private, loopback, link-local and reserved IPs are blocked, including on redirects.
- **Rate limit:** 5 audits per IP per hour.
- **Honeypot field** and consent checkbox on the form; email format and input size validated server-side.
- **Customer vs internal:** the customer report lists findings and their impact only. Affected URLs and technical evidence stay on the internal endpoint.
- Findings come from automated checks of public pages and are not a guarantee of ranking.

## Customising

- Brand name and the "A" mark are in the navbar and footer of `index.html`.
- The "Discuss your results" button opens an email to `hello@avantico.com` (`index.html`).
- The accent colour is the CSS variable `--blue` at the top of the stylesheet; the design is a tech-phase design and can change once the AVANTICO brand identity is ready.
- The crawler identifies itself as `AVANTICO-AuditBot/1.0` (`server.py`).
