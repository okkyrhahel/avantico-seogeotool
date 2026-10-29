"""Drive the installed Google Chrome / Microsoft Edge from Python without any package (standard library only).

Chrome is started headless with --remote-debugging-port and controlled over the Chrome DevTools Protocol (CDP) through a
small WebSocket client. Shared by both tool versions (playwright/ and axe-core/); keep the two copies identical.

    with Chrome() as c:
        page = c.new_page(mobile=False, guard=lambda url: True)
        info = page.goto("https://example.com")       # status, url, headers, ms
        title = page.evaluate("() => document.title")
        page.close()

Browser choice: BROWSER_PATH (full path to chrome / msedge) or BROWSER_CHANNEL (chrome | msedge); default: Chrome, then Edge.
"""
import base64, json, os, queue, shutil, socket, subprocess, sys, tempfile, threading, time

MOBILE_UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 "
             "(KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1")
RESOURCE_TYPES = ("Image", "Script", "Stylesheet", "Font", "Media")


class CDPError(Exception):
    pass


def find_browser():
    """Path of an installed Chrome or Edge, or raise CDPError with a clear message."""
    path = os.environ.get("BROWSER_PATH")
    if path:
        if os.path.exists(path):
            return path
        raise CDPError("BROWSER_PATH does not exist: " + path)
    edge_first = os.environ.get("BROWSER_CHANNEL", "chrome").lower() in ("msedge", "edge")
    pf, pf86, local = os.environ.get("PROGRAMFILES", r"C:\Program Files"), os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"), os.environ.get("LOCALAPPDATA", "")
    chrome = [os.path.join(pf, r"Google\Chrome\Application\chrome.exe"), os.path.join(pf86, r"Google\Chrome\Application\chrome.exe"),
              os.path.join(local, r"Google\Chrome\Application\chrome.exe"),
              "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
              "google-chrome-stable", "google-chrome", "chromium", "chromium-browser"]
    edge = [os.path.join(pf86, r"Microsoft\Edge\Application\msedge.exe"), os.path.join(pf, r"Microsoft\Edge\Application\msedge.exe"),
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge", "microsoft-edge-stable", "microsoft-edge"]
    for c in (edge + chrome if edge_first else chrome + edge):
        p = c if os.path.isabs(c) else shutil.which(c)
        if p and os.path.exists(p):
            return p
    raise CDPError("Google Chrome or Microsoft Edge was not found. Install Chrome, or set BROWSER_PATH to chrome.exe / msedge.exe.")


# ---------- minimal WebSocket client (RFC 6455, text frames only) ----------
class WebSocket:
    def __init__(s, port, path, timeout=30):
        s.sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        key = base64.b64encode(os.urandom(16)).decode()
        s.sock.sendall((f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = s.sock.recv(4096)
            if not chunk:
                raise CDPError("WebSocket handshake failed")
            head += chunk
        if b" 101 " not in head.split(b"\r\n", 1)[0]:
            raise CDPError("WebSocket handshake refused")
        s.buf = head.split(b"\r\n\r\n", 1)[1]
        s.sock.settimeout(None)
        s.lock = threading.Lock()

    def _read(s, n):
        while len(s.buf) < n:
            chunk = s.sock.recv(max(65536, n - len(s.buf)))
            if not chunk:
                raise EOFError
            s.buf += chunk
        out, s.buf = s.buf[:n], s.buf[n:]
        return out

    def _frame(s, opcode, data):
        n, mask = len(data), os.urandom(4)
        head = bytes([0x80 | opcode])
        head += bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + n.to_bytes(2, "big") if n < 65536 else bytes([0x80 | 127]) + n.to_bytes(8, "big")
        masked = (int.from_bytes(data, "big") ^ int.from_bytes((mask * (n // 4 + 1))[:n], "big")).to_bytes(n, "big") if n else b""
        with s.lock:
            s.sock.sendall(head + mask + masked)

    def send(s, text):
        s._frame(0x1, text.encode("utf-8"))

    def recv(s):
        """Next complete text message, or None when the connection closes."""
        parts = []
        while True:
            b0, b1 = s._read(2)
            opcode, n = b0 & 0x0F, b1 & 0x7F
            if n == 126:
                n = int.from_bytes(s._read(2), "big")
            elif n == 127:
                n = int.from_bytes(s._read(8), "big")
            if b1 & 0x80:  # servers do not mask, but handle it anyway
                mask = s._read(4); data = s._read(n)
                data = (int.from_bytes(data, "big") ^ int.from_bytes((mask * (n // 4 + 1))[:n], "big")).to_bytes(n, "big") if n else b""
            else:
                data = s._read(n)
            if opcode == 0x8:
                return None
            if opcode == 0x9:
                s._frame(0xA, data); continue
            if opcode in (0x1, 0x2, 0x0):
                parts.append(data)
                if b0 & 0x80:
                    return b"".join(parts).decode("utf-8", "replace")

    def close(s):
        try:
            s._frame(0x8, b"")
        except OSError:
            pass
        try:
            s.sock.close()
        except OSError:
            pass


# ---------- browser ----------
class Chrome:
    """One headless browser process. Pages are isolated (own browser context: no shared cookies or cache)."""

    def __enter__(s):
        s.dir = tempfile.mkdtemp(prefix="audit-chrome-")
        args = [find_browser(), "--headless=new", "--remote-debugging-port=0", "--user-data-dir=" + s.dir,
                "--no-first-run", "--no-default-browser-check", "--disable-extensions", "--disable-background-networking",
                "--disable-sync", "--disable-dev-shm-usage", "--hide-scrollbars", "--mute-audio", "--disable-gpu",
                "--window-size=1366,900", "about:blank"]
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            args.insert(1, "--no-sandbox")  # Docker runs as root; Chrome refuses to start sandboxed as root
        flags = 0x08000000 if sys.platform == "win32" else 0  # CREATE_NO_WINDOW
        s.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=flags)
        port_file, t = os.path.join(s.dir, "DevToolsActivePort"), time.time()
        while True:
            try:
                port, path = open(port_file).read().split()[:2]
                break
            except (OSError, ValueError):
                if s.proc.poll() is not None or time.time() - t > 20:
                    s._kill()
                    raise CDPError("The browser did not start.")
                time.sleep(0.1)
        s.ws = WebSocket(int(port), path)
        s.next_id, s.pending, s.handlers, s.alive = 0, {}, {}, True
        s.id_lock = threading.Lock()
        threading.Thread(target=s._reader, daemon=True).start()
        return s

    def __exit__(s, *a):
        try:
            s.call("Browser.close", timeout=5)
        except Exception:
            pass
        s.alive = False
        s.ws.close()
        s._kill()

    def _kill(s):
        try:
            s.proc.wait(timeout=5)
        except Exception:
            s.proc.kill()
        for _ in range(10):  # Windows keeps the profile locked for a moment after exit
            shutil.rmtree(s.dir, ignore_errors=True)
            if not os.path.exists(s.dir):
                break
            time.sleep(0.3)

    def _reader(s):
        while s.alive:
            try:
                msg = s.ws.recv()
            except Exception:
                msg = None
            if msg is None:
                break
            m = json.loads(msg)
            if "id" in m:
                slot = s.pending.pop(m["id"], None)
                if slot:
                    slot[1].append(m); slot[0].set()
            else:
                h = s.handlers.get(m.get("sessionId"))
                if h:
                    try:
                        h(m["method"], m.get("params", {}))
                    except Exception:
                        pass
        s.alive = False
        for ev, box in list(s.pending.values()):
            box.append({"error": {"message": "browser connection closed"}}); ev.set()

    def send(s, method, params=None, session=None):
        """Send without waiting for the answer; returns the message id."""
        with s.id_lock:
            s.next_id += 1
            mid = s.next_id
        msg = {"id": mid, "method": method, "params": params or {}}
        if session:
            msg["sessionId"] = session
        s.ws.send(json.dumps(msg))
        return mid

    def call(s, method, params=None, session=None, timeout=30):
        """Send a command and wait for its result."""
        ev, box = threading.Event(), []
        with s.id_lock:
            s.next_id += 1
            mid = s.next_id
            s.pending[mid] = (ev, box)
        msg = {"id": mid, "method": method, "params": params or {}}
        if session:
            msg["sessionId"] = session
        s.ws.send(json.dumps(msg))
        if not ev.wait(timeout):
            s.pending.pop(mid, None)
            raise CDPError(method + " timed out")
        r = box[0]
        if "error" in r:
            raise CDPError(method + ": " + r["error"].get("message", "error"))
        return r.get("result", {})

    def new_page(s, mobile=False, guard=None):
        return Page(s, mobile, guard)


class Page:
    """A tab in its own browser context. guard(url) -> bool is asked for every request (SSRF protection)."""

    def __init__(s, c, mobile, guard):
        s.c, s.guard = c, guard
        s.ctx = c.call("Target.createBrowserContext", {"disposeOnDetach": True})["browserContextId"]
        s.target = c.call("Target.createTarget", {"url": "about:blank", "browserContextId": s.ctx})["targetId"]
        s.sid = c.call("Target.attachToTarget", {"targetId": s.target, "flatten": True})["sessionId"]
        s.loaded, s.inflight, s.last_net = threading.Event(), set(), time.time()
        s.console, s.failed, s.doc, s.frame = [], [], None, None
        s.paused = queue.Queue()
        c.handlers[s.sid] = s._event
        if guard:  # decide requests on a worker thread: the host check may need a DNS lookup
            threading.Thread(target=s._guard_worker, daemon=True).start()
        for m, p in (("Page.enable", {}), ("Network.enable", {}), ("Runtime.enable", {}), ("Log.enable", {})):
            c.call(m, p, s.sid)
        if guard:
            c.call("Fetch.enable", {"patterns": [{"urlPattern": "*"}]}, s.sid)
        if mobile:
            c.call("Emulation.setDeviceMetricsOverride", {"width": 390, "height": 844, "deviceScaleFactor": 3, "mobile": True}, s.sid)
            c.call("Emulation.setTouchEmulationEnabled", {"enabled": True, "maxTouchPoints": 5}, s.sid)
            c.call("Emulation.setUserAgentOverride", {"userAgent": MOBILE_UA, "platform": "iPhone"}, s.sid)
        else:
            c.call("Emulation.setDeviceMetricsOverride", {"width": 1366, "height": 900, "deviceScaleFactor": 1, "mobile": False}, s.sid)

    def _guard_worker(s):
        while True:
            p = s.paused.get()
            if p is None:
                return
            try:
                if s.guard(p["request"]["url"]):
                    s.c.send("Fetch.continueRequest", {"requestId": p["requestId"]}, s.sid)
                else:
                    s.c.send("Fetch.failRequest", {"requestId": p["requestId"], "errorReason": "BlockedByClient"}, s.sid)
            except Exception:
                pass

    def _event(s, method, p):
        if method == "Fetch.requestPaused":
            s.paused.put(p)
        elif method == "Page.loadEventFired":
            s.loaded.set()
        elif method == "Network.requestWillBeSent":
            s.inflight.add(p["requestId"]); s.last_net = time.time()
        elif method in ("Network.loadingFinished", "Network.loadingFailed"):
            s.inflight.discard(p["requestId"]); s.last_net = time.time()
        elif method == "Network.responseReceived":
            r = p["response"]
            if p.get("type") == "Document" and p.get("frameId") == s.frame:
                s.doc = r
            elif r.get("status", 0) >= 400 and p.get("type") in RESOURCE_TYPES:
                s.failed.append(f"{r['status']} {r['url'][:150]}")
        elif method == "Runtime.consoleAPICalled" and p.get("type") == "error":
            s.console.append(" ".join(str(a.get("value", a.get("description", ""))) for a in p.get("args", []))[:200])
        elif method == "Log.entryAdded" and p.get("entry", {}).get("level") == "error" and p["entry"].get("source") in ("javascript", "security", "other"):
            s.console.append(str(p["entry"].get("text", ""))[:200])
        elif method == "Runtime.exceptionThrown":
            d = p.get("exceptionDetails", {})
            s.console.append(str(d.get("exception", {}).get("description") or d.get("text", "error"))[:200])

    def goto(s, url, timeout=25):
        """Open url and wait for the load event. Returns dict(status, url, headers, ms)."""
        s.loaded.clear(); s.doc = None
        s.frame = s.c.call("Page.getFrameTree", {}, s.sid)["frameTree"]["frame"]["id"]
        t = time.time()
        r = s.c.call("Page.navigate", {"url": url}, s.sid, timeout=timeout)
        if r.get("errorText"):
            raise CDPError(r["errorText"])
        if not s.loaded.wait(max(1, timeout - (time.time() - t))):
            raise CDPError("page load timed out")
        ms = int((time.time() - t) * 1000)
        doc = s.doc or {}
        return dict(status=doc.get("status", 0), url=s.evaluate("() => location.href"),
                    headers={str(k).lower(): str(v) for k, v in (doc.get("headers") or {}).items()}, ms=ms)

    def wait_idle(s, quiet=0.5, timeout=4):
        """Wait until no request has been running for `quiet` seconds (many sites never go fully idle)."""
        end = time.time() + timeout
        while time.time() < end:
            if not s.inflight and time.time() - s.last_net >= quiet:
                return True
            time.sleep(0.1)
        return False

    def evaluate(s, fn, arg=None, timeout=60):
        """Call the JavaScript function `fn` (e.g. "(x) => ...") with arg and return its value (promises are awaited)."""
        return s.run(f"({fn})({json.dumps(arg)})", timeout)

    def run(s, script, timeout=60):
        """Run a script in the page (not affected by the site's Content-Security-Policy) and return the last value."""
        r = s.c.call("Runtime.evaluate", {"expression": script, "returnByValue": True, "awaitPromise": True}, s.sid, timeout=timeout)
        if "exceptionDetails" in r:
            d = r["exceptionDetails"]
            raise CDPError("script error: " + str(d.get("exception", {}).get("description") or d.get("text"))[:300])
        return r.get("result", {}).get("value")

    def content(s):
        return s.evaluate("() => (document.doctype ? new XMLSerializer().serializeToString(document.doctype) : '') + document.documentElement.outerHTML")

    def close(s):
        s.paused.put(None)
        s.c.handlers.pop(s.sid, None)
        try:
            s.c.call("Target.closeTarget", {"targetId": s.target}, timeout=10)
            s.c.call("Target.disposeBrowserContext", {"browserContextId": s.ctx}, timeout=10)
        except Exception:
            pass
