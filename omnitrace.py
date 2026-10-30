#!/usr/bin/env python3
"""
OmniTrace - 10 public-data OSINT and privacy tools in one.
Use only on yourself, your own assets, or with permission.

Setup (Termux):
    pkg install python
    pip install requests pillow
Run:
    python omnitrace.py
"""
import os, re, sys, json, time, socket, ipaddress
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlparse, quote

try:
    import requests
except ImportError:
    sys.exit("Missing requests. Run: pip install requests")

UA = {"User-Agent": "Mozilla/5.0 (Linux; Android 13) OmniTrace/1.0"}
SEEN_FILE = os.path.expanduser("~/.omnitrace_seen.json")


def get(url, **kw):
    kw.setdefault("timeout", 12)
    kw.setdefault("headers", UA)
    return requests.get(url, **kw)


def clean_domain(s):
    s = s.strip()
    if "//" in s:
        s = urlparse(s).netloc
    return s.split("/")[0].split(":")[0].lower()


# 1. Username checker -------------------------------------------------------
SITES = {
    "GitHub": "https://github.com/{}",
    "GitLab": "https://gitlab.com/{}",
    "Reddit": "https://www.reddit.com/user/{}",
    "Twitter/X": "https://x.com/{}",
    "Instagram": "https://www.instagram.com/{}/",
    "TikTok": "https://www.tiktok.com/@{}",
    "YouTube": "https://www.youtube.com/@{}",
    "Pinterest": "https://www.pinterest.com/{}/",
    "Medium": "https://medium.com/@{}",
    "Dev.to": "https://dev.to/{}",
    "Telegram": "https://t.me/{}",
    "Twitch": "https://www.twitch.tv/{}",
    "SoundCloud": "https://soundcloud.com/{}",
    "Spotify": "https://open.spotify.com/user/{}",
    "Steam": "https://steamcommunity.com/id/{}",
    "Replit": "https://replit.com/@{}",
    "Keybase": "https://keybase.io/{}",
    "Flickr": "https://www.flickr.com/people/{}",
    "Vimeo": "https://vimeo.com/{}",
    "Behance": "https://www.behance.net/{}",
    "Dribbble": "https://dribbble.com/{}",
    "HackerNews": "https://news.ycombinator.com/user?id={}",
    "Pastebin": "https://pastebin.com/u/{}",
    "Linktree": "https://linktr.ee/{}",
    "About.me": "https://about.me/{}",
}


def username_check(user, quiet=False):
    def one(item):
        name, url = item
        u = url.format(user)
        try:
            r = get(u, allow_redirects=True)
            return name, u, r.status_code == 200
        except Exception:
            return name, u, None

    with ThreadPoolExecutor(12) as ex:
        results = list(ex.map(one, SITES.items()))
    found = [(n, u) for n, u, ok in results if ok]
    if not quiet:
        print(f"\nFound on {len(found)}/{len(SITES)} sites:")
        for n, u in found:
            print(f"  [+] {n}: {u}")
        print("(Some sites return 200 for missing users - verify manually.)")
    return found


# 2. Email breach checker ---------------------------------------------------
def email_breach(email, quiet=False):
    try:
        r = get(f"https://api.xposedornot.com/v1/check-email/{quote(email)}")
        if r.status_code == 404:
            if not quiet:
                print("\n[+] No breaches found for this email.")
            return []
        data = r.json()
        breaches = data.get("breaches", [[]])[0]
        if not quiet:
            print(f"\n[!] Found in {len(breaches)} breach(es):")
            for b in breaches:
                print("   -", b)
            if breaches:
                print("Change passwords on those services and enable 2FA.")
        return breaches
    except Exception as e:
        print("Error:", e)
        return []


# 3. Domain recon -----------------------------------------------------------
def rdap(domain):
    r = get(f"https://rdap.org/domain/{domain}")
    return r.json() if r.status_code == 200 else None


def domain_recon(domain):
    domain = clean_domain(domain)
    print(f"\n== WHOIS (RDAP) for {domain} ==")
    d = rdap(domain)
    if d:
        for e in d.get("events", []):
            print(f"  {e.get('eventAction')}: {e.get('eventDate')}")
        print("  Status:", ", ".join(d.get("status", [])))
        print("  Nameservers:", ", ".join(n["ldhName"] for n in d.get("nameservers", [])))
    else:
        print("  No RDAP data.")
    print("\n== DNS records ==")
    for t in ["A", "AAAA", "MX", "NS", "TXT"]:
        try:
            r = get("https://dns.google/resolve", params={"name": domain, "type": t}).json()
            for a in r.get("Answer", []):
                print(f"  {t}: {a['data']}")
        except Exception:
            pass
    print("\n== Subdomains (crt.sh) ==")
    try:
        r = get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=30)
        subs = set()
        for row in r.json():
            for n in row["name_value"].split("\n"):
                subs.add(n.strip().lstrip("*."))
        for s in sorted(subs)[:60]:
            print("  ", s)
        print(f"  ({len(subs)} total)")
    except Exception as e:
        print("  Could not fetch subdomains:", e)


# 4. IP lookup --------------------------------------------------------------
def ip_lookup(ip):
    ip = ip.strip()
    if not re.match(r"^[\d.:a-fA-F]+$", ip):
        try:
            ip = socket.gethostbyname(clean_domain(ip))
        except Exception:
            print("Could not resolve.")
            return
    fields = "status,message,country,regionName,city,isp,org,as,proxy,hosting,mobile,query"
    r = get(f"http://ip-api.com/json/{ip}", params={"fields": fields}).json()
    if r.get("status") != "success":
        print("Error:", r.get("message"))
        return
    print(f"\nIP: {r['query']}")
    print(f"Location: {r['city']}, {r['regionName']}, {r['country']}")
    print(f"ISP: {r['isp']} | Org: {r['org']}")
    print(f"AS: {r['as']}")
    print(f"VPN/Proxy: {'YES' if r['proxy'] else 'no'} | Datacenter/hosting: {'YES' if r['hosting'] else 'no'} | Mobile: {r['mobile']}")


# 5. Image metadata viewer + stripper --------------------------------------
def _deg(v, ref):
    d = float(v[0]) + float(v[1]) / 60 + float(v[2]) / 3600
    return -d if ref in ("S", "W") else d


def image_meta(path):
    try:
        from PIL import Image, ExifTags
    except ImportError:
        print("Install Pillow: pip install pillow")
        return
    path = path.strip().strip("'\"")
    try:
        img = Image.open(path)
    except Exception as e:
        print("Cannot open:", e)
        return
    exif = img.getexif()
    if not exif:
        print("No EXIF metadata found. Clean!")
        return
    print("\n== Metadata ==")
    for k, v in exif.items():
        name = ExifTags.TAGS.get(k, k)
        if name in ("MakerNote", "UserComment") or isinstance(v, bytes):
            continue
        print(f"  {name}: {v}")
    gps = exif.get_ifd(0x8825)
    if gps:
        try:
            lat = _deg(gps[2], gps[1])
            lon = _deg(gps[4], gps[3])
            print(f"\n[!] GPS location embedded: {lat:.6f}, {lon:.6f}")
            print(f"    https://maps.google.com/?q={lat},{lon}")
        except Exception:
            print("[!] GPS data present but unreadable.")
    if input("\nCreate a metadata-free copy? (y/n): ").lower() == "y":
        clean = Image.new(img.mode, img.size)
        clean.putdata(list(img.getdata()))
        base, ext = os.path.splitext(path)
        out = f"{base}_clean{ext}"
        clean.save(out)
        print("Saved:", out)


# 6. Phishing URL checker ---------------------------------------------------
BRANDS = ["paypal", "google", "facebook", "instagram", "apple", "microsoft",
          "amazon", "netflix", "binance", "whatsapp", "easypaisa", "jazzcash"]
BAD_TLDS = (".zip", ".xyz", ".top", ".tk", ".click", ".gq", ".ml", ".cf", ".work", ".support")
KEYWORDS = ["login", "verify", "secure", "account", "update", "wallet", "bank", "confirm", "signin"]


def phishing_check(url):
    if not url.startswith("http"):
        url = "http://" + url
    p = urlparse(url)
    host = (p.hostname or "").lower()
    score, why = 0, []

    def add(n, msg):
        nonlocal score
        score += n
        why.append(f"+{n} {msg}")

    try:
        ipaddress.ip_address(host)
        add(30, "uses a raw IP address")
    except ValueError:
        pass
    if p.scheme != "https":
        add(10, "not HTTPS")
    if "@" in url:
        add(20, "contains '@' (hides real destination)")
    if "xn--" in host:
        add(25, "punycode (lookalike characters)")
    if len(host) > 30:
        add(10, "very long hostname")
    if host.count(".") >= 4:
        add(10, "many subdomains")
    if host.count("-") >= 3:
        add(10, "many hyphens")
    if host.endswith(BAD_TLDS):
        add(15, "suspicious TLD")
    kw = [k for k in KEYWORDS if k in host]
    if kw:
        add(min(10 * len(kw), 20), f"keywords in domain: {', '.join(kw)}")
    parts = host.split(".")
    reg = ".".join(parts[-2:]) if len(parts) >= 2 else host
    for b in BRANDS:
        if b in host and not reg.startswith(b + "."):
            add(25, f"impersonates brand '{b}'")
            break
    try:
        d = rdap(reg)
        if d:
            for e in d.get("events", []):
                if e.get("eventAction") == "registration":
                    dt = datetime.fromisoformat(e["eventDate"].replace("Z", "+00:00"))
                    age = (datetime.now(timezone.utc) - dt).days
                    if age < 30:
                        add(30, f"domain only {age} days old")
                    elif age < 180:
                        add(10, f"domain only {age} days old")
                    else:
                        print(f"  Domain age: {age} days (ok)")
    except Exception:
        pass
    try:
        r = get(url, allow_redirects=True, timeout=8)
        if len(r.history) > 2:
            add(10, f"{len(r.history)} redirects")
        final = urlparse(r.url).hostname
        if final and final != host:
            add(10, f"redirects to different host: {final}")
    except Exception:
        why.append("(site unreachable - could not follow redirects)")

    print(f"\nRisk score: {min(score, 100)}/100")
    for w in why:
        print("  ", w)
    verdict = "HIGH RISK - do not open" if score >= 50 else "SUSPICIOUS - be careful" if score >= 25 else "Looks low risk (not a guarantee)"
    print("Verdict:", verdict)


# 7. Digital footprint scanner ---------------------------------------------
def footprint():
    print("Scan YOURSELF only. Leave blank to skip a field.")
    email = input("Your email: ").strip()
    user = input("Your username: ").strip()
    if email:
        print("\n--- Breaches ---")
        email_breach(email)
    if user:
        print("\n--- Accounts ---")
        username_check(user)
    name = input("\nYour full name (for news mentions): ").strip()
    if name:
        print("\n--- News mentions ---")
        news_once(f'"{name}"')


# 8. Website tech detector --------------------------------------------------
SIGS = {
    "WordPress": ["wp-content", "wp-includes"], "Shopify": ["cdn.shopify.com"],
    "Wix": ["wixstatic.com"], "Squarespace": ["squarespace.com"],
    "React": ["react", "__next_data__"], "Next.js": ["/_next/"],
    "Vue": ["vue.js", "vue.min.js", "data-v-"], "Angular": ["ng-version"],
    "jQuery": ["jquery"], "Bootstrap": ["bootstrap"], "Tailwind": ["tailwind"],
    "Google Analytics": ["googletagmanager", "google-analytics"],
    "Cloudflare": ["cloudflare"], "Firebase": ["firebaseapp", "firebase"],
}


def tech_detect(url):
    if not url.startswith("http"):
        url = "https://" + url
    r = get(url)
    print(f"\nStatus: {r.status_code} | Final URL: {r.url}")
    for h in ["Server", "X-Powered-By", "Via", "X-Generator", "CF-Ray"]:
        if h in r.headers:
            print(f"  Header {h}: {r.headers[h]}")
    body = r.text.lower()
    found = [n for n, sigs in SIGS.items() if any(s in body for s in sigs)]
    if "cf-ray" in {k.lower() for k in r.headers}:
        found.append("Cloudflare")
    print("Detected:", ", ".join(sorted(set(found))) or "nothing obvious")
    missing = [h for h in ["Strict-Transport-Security", "Content-Security-Policy",
                           "X-Frame-Options", "X-Content-Type-Options"] if h not in r.headers]
    if missing:
        print("Missing security headers:", ", ".join(missing))


# 9. Wayback tracker --------------------------------------------------------
def wayback(url):
    r = get("https://web.archive.org/cdx/search/cdx", params={
        "url": url, "output": "json", "fl": "timestamp,original,statuscode",
        "filter": "statuscode:200", "collapse": "timestamp:6", "limit": 40}, timeout=30)
    rows = r.json()[1:]
    if not rows:
        print("No snapshots found.")
        return
    print(f"\n{len(rows)} snapshots (about one per month):")
    for ts, orig, _ in rows:
        d = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
        print(f"  {d}  https://web.archive.org/web/{ts}/{orig}")


# 10. News and leak monitor -------------------------------------------------
def fetch_news(q):
    r = get("https://news.google.com/rss/search", params={"q": q, "hl": "en", "gl": "US", "ceid": "US:en"})
    root = ET.fromstring(r.content)
    return [(i.findtext("title"), i.findtext("link"), i.findtext("pubDate"))
            for i in root.iter("item")]


def news_once(q):
    try:
        items = fetch_news(q)[:8]
        if not items:
            print("  Nothing found.")
        for t, l, d in items:
            print(f"  - {t}\n    {l}")
    except Exception as e:
        print("Error:", e)


def monitor():
    kws = [k.strip() for k in input("Keywords (comma separated): ").split(",") if k.strip()]
    mins = int(input("Check every how many minutes? [10]: ") or 10)
    try:
        seen = set(json.load(open(SEEN_FILE)))
    except Exception:
        seen = set()
    print("Monitoring... press Ctrl+C to stop.")
    try:
        while True:
            for k in kws:
                try:
                    for t, l, d in fetch_news(k):
                        if l not in seen:
                            seen.add(l)
                            print(f"\n[NEW] ({k}) {t}\n      {l}")
                except Exception as e:
                    print("Fetch error:", e)
            json.dump(list(seen), open(SEEN_FILE, "w"))
            time.sleep(mins * 60)
    except KeyboardInterrupt:
        print("\nStopped.")


# Menu ----------------------------------------------------------------------
MENU = """
==============================
        OMNITRACE - All in One   
==============================
 1. Username checker
 2. Email breach checker
 3. Domain recon (WHOIS/DNS/subdomains)
 4. IP lookup
 5. Image metadata viewer / stripper
 6. Phishing URL checker
 7. Digital footprint scanner (yourself)
 8. Website tech detector
 9. Wayback tracker
10. News / mention monitor
 0. Exit
"""


def main():
    actions = {
        "1": lambda: username_check(input("Username: ").strip()),
        "2": lambda: email_breach(input("Email: ").strip()),
        "3": lambda: domain_recon(input("Domain: ")),
        "4": lambda: ip_lookup(input("IP or domain: ")),
        "5": lambda: image_meta(input("Image path: ")),
        "6": lambda: phishing_check(input("URL: ").strip()),
        "7": footprint,
        "8": lambda: tech_detect(input("Website: ").strip()),
        "9": lambda: wayback(input("URL: ").strip()),
        "10": monitor,
    }
    print("Use only on yourself or with permission.")
    while True:
        print(MENU)
        c = input("Choose: ").strip()
        if c == "0":
            break
        fn = actions.get(c)
        if not fn:
            print("Invalid choice.")
            continue
        try:
            fn()
        except KeyboardInterrupt:
            print("\nCancelled.")
        except Exception as e:
            print("Error:", e)
        input("\nPress Enter to continue...")


if __name__ == "__main__":
    main()
