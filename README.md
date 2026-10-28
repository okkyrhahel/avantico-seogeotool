# Website Page Audit Tool

A general tool that audits a public web page and returns a clear report covering **SEO**, **GEO (AI-search readiness)**, **PageSpeed** and the **enquiry journey**. The visitor enters their name, email and a page URL; the tool checks the page, scores it and shows a prioritised list of what is still missing.

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
| `render.yaml` / `_redirects` | Optional Render blueprint / Netlify proxy for `/api/*` (set your own backend URL) |

## How it works

1. The visitor submits name, email, website URL and a consent checkbox.
2. The backend creates an audit (random token), stores the lead, and starts the audit in a background thread.
3. The page polls `/api/audits/<token>/status` every 1.5 s and shows live progress for six steps: connect, SEO, GEO, enquiry journey, speed, summary.
4. When finished, the page loads the report. It leads with **what is missing**: a headline with the number of high-impact gaps, a tally (fix first / fix next / nice to have / passed), and a warning when the overall score looks better than the weakest area. Then four area cards (score, open issues, checks passed; click to filter), the to-do list grouped by priority (tick off, open for "why it matters"), passed checks, and coverage notes. The list can be copied as text or printed / saved as PDF.

### What is checked

| Category | Checks |
|---|---|
| **SEO** | Titles (missing, length, duplicates), meta descriptions, H1 (missing, multiple), noindex, canonical links, image alt text, mobile viewport, `lang` attribute, HTTPS, robots.txt, XML sitemap, broken internal links on the homepage |
| **GEO** | AI crawlers blocked in robots.txt (GPTBot, ClaudeBot, PerplexityBot, Google-Extended, CCBot), `llms.txt`, JSON-LD structured data (present, valid, Organization/LocalBusiness), thin content (< 150 words) |
| **Enquiry journey** | Contact route on homepage (email, phone, WhatsApp or contact page), call-to-action link, form present |
| **PageSpeed** | Server response time, and Google PageSpeed Insights (mobile, homepage): score, LCP, TBT, CLS |

### Scoring

- SEO, GEO and Enquiry journey each start at 100 and lose points per finding: **High -15, Medium -8, Low -3** (GEO: -20 / -10 / -4).
- PageSpeed uses the Lighthouse mobile performance score directly (shown as unavailable if the API did not answer).
- **Ceiling per area:** an area can never score higher than its worst open issue allows: a **blocker** caps it at 49, a **high** issue at 59, a **medium** issue at 79. Many passed checks therefore cannot hide one serious gap.
- **Blockers** are issues that stop the page from doing its job: no title, noindex (meta or header), robots.txt blocking all crawlers, no HTTPS, no contact route.
- **Overall score:** the average of the available areas, but at most 20 points above the weakest area, and at most 59 when two or more areas are below 60. The report names the area that holds the score back (`limited_by`).
- Score bands: 80+ "Looking good", 60-79 "Needs attention", below 60 "Needs work".

### Reading the page

- Compressed responses (gzip / deflate) are decompressed before the HTML is read.
- If the page is a bot-protection / captcha page (Cloudflare challenge and similar), the audit stops with a clear message instead of reporting on the challenge page.
- If the page seems to be built with JavaScript in the browser (very little text and an empty app root or many scripts), the report adds a coverage note that content-related findings may be overstated.
- The first request is retried once after a connection error or timeout.

The report footer shows an **Audit ID**, how long the audit took and when the PageSpeed test actually ran. A different Audit ID proves a new audit; a repeated PageSpeed time means Google reused its own earlier test.

### Crawl limits

**1 page** per audit (the final URL after redirects; robots.txt, sitemap and llms.txt are read from its origin), **8 s** timeout per request, **1.5 MB** per page. Up to 15 internal links on the page are checked for errors.

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

Push the files to a git repository and connect it to any host that builds a Dockerfile (for example SnapDeploy). Set the environment variables below. The health check path is `/health`. Because the server serves `index.html` itself, the host's public URL is the tool's URL.

> Every audit gets its own random token and its own isolated state; the page is fully reset before each new audit. Reports and audits are held **in memory** and are forgotten after 2 hours, or when the container restarts or redeploys. That is fine for a live demo; for persistent reports, add storage first.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `PSI_KEY` | Recommended | Google PageSpeed Insights API key (free; create it in a Google Cloud project). Without a key the API is heavily rate limited and PageSpeed may show as unavailable. |
| `LEAD_WEBHOOK_URL` | Optional | Every submission (name, email, URL, consent, timestamp) is POSTed here as JSON, for example a Zapier, Make or Google Apps Script webhook. Submissions are always printed to the server log as `LEAD {...}` as a fallback. |
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
- **Public vs internal:** the public report lists findings and their impact only. Affected URLs and technical evidence stay on the internal endpoint.
- Findings come from automated checks of public pages and are not a guarantee of ranking.

## Customising

- The tool name and mark are in the navbar and footer of `index.html`.
- The accent colour is the CSS variable `--blue` at the top of the stylesheet.
- The crawler identifies itself as `SiteAuditBot/1.0` (`server.py`).
