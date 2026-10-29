# Website Audit - browser version (folder `playwright/`)

Same report as the base tool (`../server.py`), but the website is opened in a **real browser** like a visitor would, and the
score is built from what the browser shows. Five areas: **SEO, GEO, Content, Enquiry journey, PageSpeed**.

- **No pip, no npm, no virtualenv:** only Python 3.9+ (standard library) and an installed **Google Chrome** or **Microsoft Edge**.
  `cdp.py` starts the browser headless and drives it over the Chrome DevTools Protocol (the same protocol Playwright uses).
  The folder keeps its old name; the Playwright package itself is no longer needed.
- **Pages:** the homepage on desktop **and** on a phone-sized screen, then up to 9 pages from its menu (contact, about, services,
  prices first), then other homepage links and the sitemap. Limit `MAX_PAGES = 10`, time budget 120 s.
- **Files:** `server.py` (crawler, rules, API), `inputs.py` (URL / phone / country input and country checks, identical in both
  versions), `cdp.py` (browser control, identical in both versions), `index.html`, `Dockerfile`.

## What is new compared with the base tool

| Area | New checks (from the rendered pages) |
|---|---|
| **SEO** | Every opened page is scored (titles, H1, meta, duplicates...), linked pages that do not open, generic addresses (`/blank-6`, `/copy-of-...`), JavaScript errors, images/files that fail to load |
| **GEO** | Text that only appears with JavaScript (HTML sent to crawlers vs. what the browser shows) |
| **Content** (new area) | Real words on the homepage and per subpage with menu/footer text removed, thin pages, duplicate pages, template placeholder text (Lorem ipsum, "I'm a paragraph"), about/team, services, prices, FAQ, reviews/testimonials, outdated copyright year |
| **Enquiry journey** | Contact page in the menu, contact page with form / tel / mail link, call to action on the **first phone screen**, booking that continues on another website, page wider than a phone, small tap targets, tiny text |
| **Phone & country** | Entered phone shown on the website (text, `tel:`, WhatsApp), tap-to-call link, international format, structured-data phone, page language vs. country, language versions for multilingual countries, postal code / address |
| **PageSpeed** | Server response of the HTML plus page load time in the browser (in addition to Lighthouse) |

Scoring is unchanged: start at 100, minus High 15 / Medium 8 / Low 3 (GEO 20/10/4), capped by the worst open issue, overall at most
20 points above the weakest area.

## Input

Name, email, **website address**, **country / area** (required) and **business phone** (optional).
The website address may be written as `https://www.example.com`, `http://example.com`, `www.example.com`, `example.com` or
`example.com/page`; without a scheme `https://` is used and `http://` is tried if https cannot be reached. The phone may be
national (`076 537 39 99`, the dial code comes from the country) or international (`+41 76 537 39 99`, `0041...`).

## Run locally

Put `PSI_KEY=...` (and other settings) in `Tool/.env` (see `.env.example`); real environment variables win. The
`.env` file is not copied into the Docker image.

```bash
python server.py          # http://localhost:8000
```

The browser is found automatically (Chrome first, then Edge). Use `BROWSER_CHANNEL=msedge` for Edge first, or
`BROWSER_PATH=...` for another location. Safari / WebKit cannot be driven this way.

## Docker

`docker build -t site-audit-browser .` - the image installs Google Chrome from Google's package (no pip). Chrome needs
about 1 GB of memory; choose a plan with enough RAM.

Environment variables as in the base tool, plus `BROWSER_CHANNEL` (default `chrome`), `BROWSER_PATH` and `MAX_BROWSERS` (audits with a
browser at the same time, default 2). API as in the base tool; `POST /api/audits` also takes `phone` and `country`,
`GET /api/countries` returns the country list.
