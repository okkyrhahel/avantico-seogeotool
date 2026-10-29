# Website Audit Tool (Playwright)

Audits a public website in a real browser (Google Chrome via Playwright) and returns a report on **SEO, GEO, Content,
Enquiry journey and PageSpeed** (Google PageSpeed Insights).

## Files

| File | Purpose |
|---|---|
| `server.py` | Crawler, scoring, API, serves `index.html` |
| `inputs.py` | URL / phone / country input and country checks |
| `index.html` | The whole UI |
| `requirements.txt` | `playwright` |
| `Dockerfile` | Python 3.12 + Playwright + Google Chrome |

## Deploy (GitHub + SnapDeploy)

1. Push this folder to a GitHub repository (the files above at the repository root).
2. In SnapDeploy, create an app from the repository; it builds the `Dockerfile`.
3. Environment variables in SnapDeploy:
   - `PSI_KEY` = your Google PageSpeed Insights API key (**required** for PageSpeed; without it Google's shared quota answers `HTTP 429`).
   - Port: the server reads `PORT` (default `8000`, exposed in the Dockerfile). Use 8000 unless SnapDeploy sets `PORT` itself.
4. Health check path: `/health`.

Chrome needs memory: choose a plan with at least **1 GB RAM**. The server log shows
`PageSpeed key set` at start-up and prints `PSI error ...` if Google rejects a request.

## Run locally

```bash
pip install -r requirements.txt
# Google Chrome must be installed (normal desktop Chrome is fine)
python server.py            # http://localhost:8000
```

Put `PSI_KEY=...` in a `.env` file next to `server.py` (see `.env.example`). `.env` is ignored by git and Docker.

## Environment variables

| Variable | Description |
|---|---|
| `PSI_KEY` | Google PageSpeed Insights API key |
| `PORT` / `HOST` | Port (default 8000) / bind address (Dockerfile sets `0.0.0.0`) |
| `BROWSER_CHANNEL` | `chrome` (default) or `msedge` |
| `MAX_BROWSERS` | Audits running a browser at the same time (default 1) |
| `RATE_LIMIT` | Audits per IP per hour (default 5) |
| `LEAD_WEBHOOK_URL` | Optional: each submission is POSTed here as JSON (always also printed as `LEAD {...}` in the log) |
| `INTERNAL_TOKEN` | Optional: enables `GET /api/internal/audits/<token>` with `Authorization: Bearer <token>` |
| `ALLOW_PRIVATE` | Dev only: `1` lets the crawler reach localhost / private IPs |

## API

`POST /api/audits` `{name, email, url, phone?, consent: true}` -> `{token}` ·
`GET /api/audits/<token>/status` · `GET /api/audits/<token>/report` · `GET /health`

There is no country field. The country (for the language / address / phone checks) comes from the phone's dial code
(`+41 ...` -> Switzerland), otherwise from the domain ending (`.ch`, `.de`, `.co.id` ...). A national number without `+`
(`076 ...`) only works on a country domain; on `.com` the visitor is asked for the number with the country code.

Audits are kept in memory for 2 hours (lost on restart / redeploy).
