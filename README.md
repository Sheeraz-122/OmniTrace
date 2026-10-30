# OmniTrace

**All-in-one OSINT and privacy toolkit for the terminal. Ten tools, one menu, no API keys.**

OmniTrace uses only public data sources to help you investigate links, domains and
IPs, and to see what the internet knows about *you*. It runs on Termux (Android),
Linux, macOS and Windows.

## Features

| # | Tool | What it does |
|---|------|--------------|
| 1 | Username checker | Finds where a username is registered across 25+ sites |
| 2 | Email breach checker | Checks if an email appears in known data breaches |
| 3 | Domain recon | WHOIS (RDAP), DNS records and subdomains |
| 4 | IP lookup | Country, ISP, VPN/proxy and datacenter detection |
| 5 | Image metadata tool | Reads EXIF and GPS data, saves a metadata-free copy |
| 6 | Phishing URL checker | Risk score from domain age, lookalikes, redirects and more |
| 7 | Digital footprint scanner | Checks your own email, username and name in one run |
| 8 | Website tech detector | Detects frameworks, server software and missing security headers |
| 9 | Wayback tracker | Lists archived snapshots of any page |
| 10 | News and mention monitor | Alerts you to new mentions of your keywords |

## Installation

### Termux (Android)

```bash
pkg update && pkg upgrade -y
pkg install python git -y
pkg install python-pillow -y
git clone https://github.com/YOUR-USERNAME/OmniTrace.git
cd OmniTrace
pip install requests
python omnitrace.py
```

If you downloaded the ZIP instead:

```bash
pkg install python unzip python-pillow -y
termux-setup-storage
cp ~/storage/downloads/OmniTrace.zip ~
unzip OmniTrace.zip
cd OmniTrace
pip install requests
python omnitrace.py
```

### Linux / macOS

```bash
git clone https://github.com/YOUR-USERNAME/OmniTrace.git
cd OmniTrace
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 omnitrace.py
```

### Windows

```powershell
git clone https://github.com/YOUR-USERNAME/OmniTrace.git
cd OmniTrace
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python omnitrace.py
```

## Usage

Run `python omnitrace.py`, then pick a number from the menu.

- Image tool: enter the full path, e.g. `/sdcard/DCIM/Camera/photo.jpg`
  (in Termux run `termux-setup-storage` first)
- Monitor: press `Ctrl+C` to stop. Seen items are saved to `~/.omnitrace_seen.json`

## Data sources

RDAP (rdap.org), Google DNS-over-HTTPS, crt.sh, ip-api.com, XposedOrNot,
Internet Archive (Wayback CDX) and Google News RSS. No API keys are needed.

## Limitations

- Username results can include false positives, since some sites return a
  success page for missing users. Verify manually.
- ip-api.com's free tier is rate-limited and HTTP-only.
- The phishing score is a heuristic, not a guarantee of safety.

## Responsible use

Use OmniTrace only on yourself, your own assets, or targets you have explicit
permission to investigate. Do not use it for stalking, harassment or any
unlawful activity. You are responsible for following the laws and the terms of
service of the sites queried.

## License

MIT. See [LICENSE](LICENSE).
