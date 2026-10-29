# Website Audit - axe-core version

The base tool (`../server.py`, one page read from its HTML) plus a new **Accessibility** area: the homepage is opened in
the installed **Google Chrome** (or Edge, driven by `cdp.py` over the Chrome DevTools Protocol) and checked with **axe-core** (`vendor/axe.min.js`, version 4.14.0, MPL-2.0,
licence in `vendor/axe-core-LICENSE.txt`). Areas: **SEO, GEO, Accessibility, Enquiry journey, PageSpeed**.

- **No pip, no npm, no virtualenv:** only Python 3.9+ (standard library) and an installed Chrome or Edge. axe-core only runs
  inside a browser page; it is loaded from `vendor/axe.min.js`. The crawl itself stays the base tool's single-page HTML check.
- Rules: WCAG 2.0/2.1/2.2 A and AA plus axe best practices. Each failing rule is one finding with the number of affected
  elements; impact **critical = High, serious = Medium, moderate / minor = Low**. Rules axe cannot decide ("incomplete",
  e.g. contrast on images) are listed in the coverage notes and not scored.
- The axe script runs as a DevTools script, so a site's Content-Security-Policy cannot block it.
- **Files:** `server.py`, `inputs.py` (URL / phone / country) and `cdp.py` (browser control), both identical in both versions,
  `index.html`, `vendor/`, `Dockerfile`.

## Input

Name, email, **website address**, **country / area** (required) and **business phone** (optional). Address formats:
`https://www.example.com`, `http://example.com`, `www.example.com`, `example.com`, `example.com/page` (without a scheme
`https://` is used, `http://` is tried if https cannot be reached). The phone and country are stored with the lead and
compared with the website (number shown / clickable / international format, page language, postal code).

## Run locally

Put `PSI_KEY=...` (and other settings) in `Tool/.env` (see `.env.example`); real environment variables win. The
`.env` file is not copied into the Docker image.

```bash
python server.py   # http://localhost:8000
```

Docker: `docker build -t site-audit-axe .` (installs Google Chrome, no pip; Chrome needs about 1 GB of memory). Extra
variables: `BROWSER_CHANNEL` (default `chrome`), `BROWSER_PATH`,
`MAX_BROWSERS` (default 2). `GET /api/countries` returns the country list for the form.
