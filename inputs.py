"""Visitor input (website URL, phone number, country) and the country / phone checks that compare it with the website.
Shared by both tool versions (playwright/ and axe-core/); keep the two copies identical."""
import re
import urllib.parse

# ISO code: (name, dial code, page languages expected for that market, postal-code pattern)
COUNTRIES = {
    "CH": ("Switzerland", "41", ("de", "fr", "it", "rm"), r"\b(?:CH-)?[1-9]\d{3}\b"),
    "DE": ("Germany", "49", ("de",), r"\b\d{5}\b"),
    "AT": ("Austria", "43", ("de",), r"\b(?:A-)?[1-9]\d{3}\b"),
    "LI": ("Liechtenstein", "423", ("de",), r"\b94\d{2}\b"),
    "FR": ("France", "33", ("fr",), r"\b\d{5}\b"),
    "IT": ("Italy", "39", ("it",), r"\b\d{5}\b"),
    "BE": ("Belgium", "32", ("nl", "fr", "de"), r"\b[1-9]\d{3}\b"),
    "NL": ("Netherlands", "31", ("nl",), r"\b[1-9]\d{3}\s?[A-Z]{2}\b"),
    "LU": ("Luxembourg", "352", ("lb", "fr", "de"), r"\b(?:L-)?\d{4}\b"),
    "ES": ("Spain", "34", ("es", "ca", "gl", "eu"), r"\b\d{5}\b"),
    "PT": ("Portugal", "351", ("pt",), r"\b\d{4}-\d{3}\b"),
    "GB": ("United Kingdom", "44", ("en",), r"\b[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b"),
    "IE": ("Ireland", "353", ("en", "ga"), r"\b[A-Z]\d[\dW]\s?[A-Z\d]{4}\b"),
    "SE": ("Sweden", "46", ("sv",), r"\b\d{3}\s?\d{2}\b"),
    "NO": ("Norway", "47", ("no", "nb", "nn"), r"\b\d{4}\b"),
    "DK": ("Denmark", "45", ("da",), r"\b\d{4}\b"),
    "FI": ("Finland", "358", ("fi", "sv"), r"\b\d{5}\b"),
    "PL": ("Poland", "48", ("pl",), r"\b\d{2}-\d{3}\b"),
    "US": ("United States", "1", ("en", "es"), r"\b\d{5}(?:-\d{4})?\b"),
    "CA": ("Canada", "1", ("en", "fr"), r"\b[A-Z]\d[A-Z]\s?\d[A-Z]\d\b"),
    "AU": ("Australia", "61", ("en",), r"\b\d{4}\b"),
    "NZ": ("New Zealand", "64", ("en", "mi"), r"\b\d{4}\b"),
    "SG": ("Singapore", "65", ("en", "ms", "zh", "ta"), r"\b\d{6}\b"),
    "MY": ("Malaysia", "60", ("ms", "en"), r"\b\d{5}\b"),
    "ID": ("Indonesia", "62", ("id",), r"\b\d{5}\b"),
    "TH": ("Thailand", "66", ("th",), r"\b\d{5}\b"),
    "PH": ("Philippines", "63", ("en", "fil", "tl"), r"\b\d{4}\b"),
    "VN": ("Vietnam", "84", ("vi",), r"\b\d{6}\b"),
    "IN": ("India", "91", ("en", "hi"), r"\b\d{3}\s?\d{3}\b"),
    "AE": ("United Arab Emirates", "971", ("ar", "en"), None),
    "JP": ("Japan", "81", ("ja",), r"\b\d{3}-\d{4}\b"),
}

HOST_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$", re.I)


def normalize_url(raw):
    """Accept every common way of writing a website address and return (url, scheme_given).

    https://www.example.com/page, http://example.com, www.example.com, example.com and example.com/page are all
    valid; without a scheme https:// is used (the audit falls back to http:// if https is not reachable).
    Raises ValueError for anything that is not a valid public web address."""
    v = (raw or "").strip()
    if not v or len(v) > 2000 or re.search(r"\s", v):
        raise ValueError("empty or contains spaces")
    given = bool(re.match(r"https?://", v, re.I))
    if not given and re.match(r"[a-z][a-z0-9+.-]*:", v, re.I) and not re.match(r"[^/:]+:\d+(/|$)", v):
        raise ValueError("unsupported scheme")          # ftp://, mailto:, javascript: ...
    if v.startswith("//"):
        v = v[2:]
    u = urllib.parse.urlsplit(v if given else "https://" + v)
    if u.username or u.password:
        raise ValueError("credentials in url")
    host = (u.hostname or "").rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")     # umlaut domains, e.g. zürich.ch
    except UnicodeError:
        raise ValueError("bad host")
    if not HOST_RE.match(host):
        raise ValueError("bad host")
    port = u.port                                       # raises ValueError for a bad port
    netloc = host.lower() + (f":{port}" if port else "")
    return urllib.parse.urlunsplit((u.scheme.lower(), netloc, u.path or "/", u.query, "")), given


def normalize_phone(raw, country):
    """Return the phone number in international format (+41765373999) or "" when empty. Raises ValueError if invalid.

    Accepts +41 76 537 39 99, 0041 76..., 076 537 39 99 (national, uses the dial code of the selected country)."""
    s = (raw or "").strip()
    digits = re.sub(r"\D", "", s)
    if not digits:
        return ""
    if s.startswith("+"):
        pass
    elif digits.startswith("00"):
        digits = digits[2:]
    else:
        dial = COUNTRIES.get(country, (None, ""))[1]
        if not dial:
            raise ValueError("national number without a country")
        digits = dial + digits.lstrip("0")
    if not 7 <= len(digits) <= 15:
        raise ValueError("phone length")
    return "+" + digits


PHONE_TEXT = re.compile(r"(?:\+|00)?\d[\d\s/().\-]{6,}\d")


def phones_on_site(texts, hrefs, country):
    """Phone numbers shown on the website, normalised to +<digits>; returns (numbers, any_international, any_tel_link)."""
    dial = COUNTRIES.get(country, (None, ""))[1]
    found, intl, tel = set(), False, False
    candidates = []
    for h in hrefs:
        h = urllib.parse.unquote(h or "")
        if h.lower().startswith("tel:"):
            tel = True
            candidates.append(h[4:])
        m = re.search(r"wa\.me/(\d{7,15})|whatsapp\.com/send\?phone=(\d{7,15})", h)
        if m:
            candidates.append("+" + (m.group(1) or m.group(2)))
    for t in texts:
        candidates += PHONE_TEXT.findall(t or "")
    for c in candidates:
        c = c.strip()
        d = re.sub(r"\D", "", c)
        if not 7 <= len(d) <= 15:
            continue
        if c.startswith("+"):
            intl = True
        elif d.startswith("00"):
            d, intl = d[2:], True
        elif d.startswith("0") and dial:
            d = dial + d[1:]
        else:
            continue  # plain digit runs (prices, dates, IDs) are not phone numbers
        found.add("+" + d)
    return found, intl, tel


def country_checks(add, ok, country, phone, lang, texts, hrefs, hreflangs, schema_phones, cat_contact="journey", cat_local="geo"):
    """Checks that use the visitor's country and phone number. add/ok are the audit's finding callbacks."""
    info = COUNTRIES.get(country)
    found, intl, tel = phones_on_site(texts, hrefs, country)
    if phone:
        if phone in found:
            ok(cat_contact, "The phone number you entered is shown on the website")
        else:
            add(cat_contact, "medium", "Your phone number is not shown on the website",
                f"The number {phone} was not found on the analysed pages (as text, a tel: link or a WhatsApp link).",
                "Visitors who want to call need to find the number quickly; a number that differs from the one in "
                "directories and profiles also weakens the business identity (name, address, phone consistency).")
        bad_schema = [p for p in schema_phones if p and p != phone]
        if bad_schema:
            add(cat_local, "medium", "Structured data lists a different phone number",
                "The telephone in the business structured data differs from the number you entered.",
                "Inconsistent phone numbers make it harder for search and AI systems to connect the website to the right business.",
                ev=", ".join(sorted(bad_schema)[:3]))
    if found and not tel:
        add(cat_contact, "low", "Phone number is not clickable",
            "A phone number is shown, but no tel: link was found.",
            "On phones, a tap-to-call link turns interest into a call with one tap.")
    elif tel:
        ok(cat_contact, "A tap-to-call (tel:) link is present")
    if not info:
        return
    name, dial, langs, postal = info
    if found and not intl:
        add(cat_contact, "low", "Phone shown without the international dialling code",
            f"Phone numbers on the website are written in national format, without +{dial}.",
            "Visitors from abroad (and tap-to-call on foreign phones) need the international format.")
    primary = (lang or "").split("-")[0].lower()
    if primary and primary not in langs and primary != "en":
        add(cat_local, "low", f"Page language does not match {name}",
            f"The page declares lang=\"{lang}\", which is not a usual language for {name} ({', '.join(langs)}).",
            "The declared language helps search engines show the page to the right audience. Check that the "
            "language attribute matches the content and the target market.")
    elif primary:
        ok(cat_local, f"Page language fits the target market ({name})")
    if len(langs) >= 2 and not hreflangs:
        add(cat_local, "low", f"No language versions for a multilingual market",
            f"{name} uses several languages ({', '.join(langs)}), but no hreflang language alternates were found.",
            "Visitors and search engines in other language regions are more likely to find a page in their own language. "
            "This is a recommendation, not an error: a single-language site can be a deliberate choice.")
    if postal:
        joined = " ".join(texts)
        if re.search(postal, joined):
            ok(cat_local, f"A {name} postal code / address is shown")
        else:
            add(cat_local, "medium", "No business address found",
                f"No {name} postal code was found in the text of the analysed pages.",
                "A visible address (name, address, phone) supports local search and visitor trust. Businesses without "
                "a public address can ignore this item.")
