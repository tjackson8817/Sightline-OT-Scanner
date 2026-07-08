"""
OT OSINT scan — checks how visible an organization's OT/ICS footprint and
phishing-relevant infrastructure are on the public internet.

Everything here uses free, keyless public data sources:
  - crt.sh (certificate transparency logs) for subdomain discovery
  - Google's DNS-over-HTTPS resolver for live resolution checks
  - Simple HTTP HEAD/GET checks against the company's own domain

No personal data about named individuals is collected. The "leadership
page" check only confirms whether such a page exists on the company's
OWN site — it does not extract or store any individual's name.

Run manually via GitHub Actions (workflow_dispatch) with company_name,
domain, and industry as inputs. See README for details.
"""

import itertools
import json
import os
import re
import string
import sys
import time
from datetime import datetime, timezone

import requests

CRTSH_URL = "https://crt.sh/"
DOH_URL = "https://dns.google/resolve"
DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "reports")

OT_KEYWORDS = [
    "scada", "ics", "plc", "hmi", "rtu", "historian", "dcs", "ot-", "-ot",
    "vpn", "remote", "engineering", "automation", "control", "iiot",
    "modbus", "opc", "citect", "wonderware", "ignition", "factorytalk"
]

COMMON_TLD_SWAPS = ["net", "org", "co", "io", "biz", "info"]
LEADERSHIP_PATHS = [
    "/leadership", "/about/leadership", "/about-us/leadership", "/team",
    "/our-team", "/executives", "/management-team", "/about/executive-team",
    "/company/leadership", "/about/our-team"
]

REQUEST_HEADERS = {"User-Agent": "ot-osint-scanner/1.0 (defensive security research)"}


def doh_lookup(name, record_type="A"):
    """DNS-over-HTTPS lookup via Google's public resolver. Returns list of
    answer dicts, or empty list if NXDOMAIN / no answer / error."""
    try:
        resp = requests.get(
            DOH_URL, params={"name": name, "type": record_type},
            headers=REQUEST_HEADERS, timeout=10
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("Status") == 0 and "Answer" in data:
            return data["Answer"]
        return []
    except requests.RequestException:
        return []


def crtsh_subdomains(domain):
    """Query certificate transparency logs for every subdomain that's ever
    had a public cert issued under this domain."""
    try:
        resp = requests.get(
            CRTSH_URL, params={"q": f"%.{domain}", "output": "json"},
            headers=REQUEST_HEADERS, timeout=30
        )
        resp.raise_for_status()
        entries = resp.json()
    except (requests.RequestException, json.JSONDecodeError) as exc:
        print(f"crt.sh query failed: {exc}", file=sys.stderr)
        return set()

    subdomains = set()
    for entry in entries:
        for name in entry.get("name_value", "").split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name and name.endswith(domain):
                subdomains.add(name)
    return subdomains


def flag_ot_subdomains(subdomains):
    """Filter subdomains for OT/ICS-suggestive naming patterns."""
    flagged = []
    for sub in subdomains:
        label = sub.split(".")[0]
        for kw in OT_KEYWORDS:
            if kw in label:
                flagged.append({"subdomain": sub, "matched_keyword": kw})
                break
    return flagged


def check_live(subdomain):
    """Returns True if the subdomain currently resolves (A record)."""
    return len(doh_lookup(subdomain, "A")) > 0


def generate_typosquats(domain):
    """Generate a bounded set of common typosquat permutations of a domain.
    Not exhaustive (this isn't dnstwist) — covers the highest-yield patterns:
    omission, duplication, adjacent transposition, adjacent-key substitution,
    hyphenation, and common TLD swaps."""
    if "." not in domain:
        return []
    label, _, tld = domain.partition(".")
    candidates = set()

    # Omission: drop one character
    for i in range(len(label)):
        candidates.add(label[:i] + label[i+1:])

    # Duplication: double one character
    for i in range(len(label)):
        candidates.add(label[:i] + label[i] + label[i:])

    # Adjacent transposition: swap two neighboring characters
    for i in range(len(label) - 1):
        chars = list(label)
        chars[i], chars[i+1] = chars[i+1], chars[i]
        candidates.add("".join(chars))

    # Adjacent-key substitution (partial QWERTY neighbor map)
    keyboard_neighbors = {
        "a": "qsz", "b": "vghn", "c": "xdfv", "d": "serfcx", "e": "wsdr",
        "f": "drtgvc", "g": "ftyhbv", "h": "gyujnb", "i": "ujko", "j": "huikmn",
        "k": "jiolm", "l": "kop", "m": "njk", "n": "bhjm", "o": "iklp",
        "p": "ol", "q": "wa", "r": "edft", "s": "awedxz", "t": "rfgy",
        "u": "yhji", "v": "cfgb", "w": "qase", "x": "zsdc", "y": "tghu",
        "z": "asx"
    }
    for i, ch in enumerate(label):
        for neighbor in keyboard_neighbors.get(ch, ""):
            candidates.add(label[:i] + neighbor + label[i+1:])

    # Hyphenation
    for i in range(1, len(label)):
        candidates.add(label[:i] + "-" + label[i:])

    candidates.discard(label)
    candidates.discard("")
    typosquats = [f"{c}.{tld}" for c in candidates]

    # Common TLD swaps on the original label
    for swap_tld in COMMON_TLD_SWAPS:
        if swap_tld != tld:
            typosquats.append(f"{label}.{swap_tld}")

    return sorted(set(typosquats))


def check_leadership_pages(domain):
    found = []
    for path in LEADERSHIP_PATHS:
        url = f"https://{domain}{path}"
        try:
            resp = requests.get(url, headers=REQUEST_HEADERS, timeout=8, allow_redirects=True)
            if resp.status_code == 200:
                found.append(url)
        except requests.RequestException:
            continue
        time.sleep(0.3)
    return found


def make_finding(fid, category, title, description, severity, csf, recommendation, evidence):
    return {
        "id": fid, "category": category, "title": title, "description": description,
        "severity": severity, "csf_function": csf, "recommendation": recommendation,
        "evidence": evidence
    }


def run_scan(company_name, domain, industry):
    domain = domain.lower().strip().removeprefix("http://").removeprefix("https://").rstrip("/")
    findings = []
    fid_counter = itertools.count(1)

    print(f"Scanning {domain} ({company_name})...")

    # --- Certificate transparency + OT subdomain exposure ---
    print("Querying certificate transparency logs...")
    all_subdomains = crtsh_subdomains(domain)
    print(f"Found {len(all_subdomains)} total subdomains in certificate history.")
    ot_flagged = flag_ot_subdomains(all_subdomains)
    print(f"{len(ot_flagged)} subdomain(s) flagged as OT/ICS-suggestive by name.")

    for item in ot_flagged:
        sub = item["subdomain"]
        is_live = check_live(sub)
        severity = "high" if is_live else "medium"
        status = "currently resolving (live)" if is_live else "certificate exists but not currently resolving"
        findings.append(make_finding(
            f"F{next(fid_counter):03d}", "Certificate Transparency Exposure",
            f"OT-suggestive subdomain found: {sub}",
            f"A publicly logged SSL certificate exists for '{sub}', whose name suggests an OT/ICS "
            f"system (matched keyword: '{item['matched_keyword']}'). This subdomain is {status}.",
            severity, "PROTECT",
            "Review whether this subdomain needs to be internet-facing at all. If not operationally "
            "required, remove the public DNS record, retire the certificate, and place any legitimate "
            "service behind VPN or the internal corporate network only." if is_live else
            "Confirm whether this was intentionally decommissioned. If so, no action needed beyond "
            "documentation; if not, investigate why a certificate exists for a system that shouldn't "
            "be internet-facing.",
            {"subdomain": sub, "live": is_live, "matched_keyword": item["matched_keyword"]}
        ))

    # --- Typosquat / lookalike domain risk ---
    print("Generating and checking typosquat candidates...")
    typosquats = generate_typosquats(domain)
    print(f"Checking {len(typosquats)} candidate domains...")
    for candidate in typosquats:
        answers = doh_lookup(candidate, "A")
        if not answers:
            continue
        mx_answers = doh_lookup(candidate, "MX")
        has_mx = len(mx_answers) > 0
        severity = "critical" if has_mx else "medium"
        mail_note = (
            "This domain also has mail servers configured, meaning it is capable of sending email — "
            "treat this as active phishing infrastructure risk, not just a passively registered lookalike."
            if has_mx else
            "No mail server is configured for this domain, which somewhat lowers immediate phishing risk, "
            "but it should still be monitored, since mail capability can be added at any time."
        )
        findings.append(make_finding(
            f"F{next(fid_counter):03d}", "Domain Impersonation Risk",
            f"Lookalike domain is registered and resolving: {candidate}",
            f"'{candidate}' closely resembles your primary domain '{domain}' and currently resolves to "
            f"an active IP address. {mail_note}",
            severity, "GOVERN",
            "Treat as a probable phishing/impersonation risk. Consider defensive registration of close "
            "variants, report the domain to your registrar or a brand-protection service if it appears "
            "malicious, and alert staff — especially finance and executive assistants — about this "
            "specific lookalike domain." if has_mx else
            "Monitor this domain periodically for changes (e.g., mail servers being added). Defensive "
            "registration of high-risk variants is a reasonable low-cost precaution.",
            {"domain": candidate, "has_mx": has_mx}
        ))

    # --- Self-published leadership pages (context only, no personal data) ---
    print("Checking for self-published leadership pages...")
    leadership_pages = check_leadership_pages(domain)
    if leadership_pages:
        findings.append(make_finding(
            f"F{next(fid_counter):03d}", "Public Leadership Information",
            "Company publishes leadership/executive information",
            f"Your own website publishes {len(leadership_pages)} page(s) listing company leadership "
            f"or executive team members. This is normal and often expected for business reasons, but "
            f"it is also the raw material used in whaling and business-email-compromise attempts, since "
            f"it confirms names and titles to target.",
            "informational", "PROTECT",
            "No action needed on the page itself in most cases. Ensure named leaders and their "
            "assistants are included in phishing/whaling-specific awareness training, and confirm your "
            "finance team has an out-of-band verification step for any payment or wire-transfer request "
            "that appears to come from an executive.",
            {"pages_found": leadership_pages}
        ))

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 5))

    by_severity = {}
    for f in findings:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

    report = {
        "company": company_name,
        "domain": domain,
        "industry": industry,
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
        "summary": {"total_findings": len(findings), "by_severity": by_severity}
    }
    return report


def slugify(name):
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "unnamed-org"


def update_manifest(report, slug):
    manifest_path = os.path.join(DATA_DIR, "manifest.json")
    manifest = []
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path) as f:
                manifest = json.load(f)
        except json.JSONDecodeError:
            manifest = []

    manifest = [m for m in manifest if m.get("slug") != slug]
    manifest.append({
        "slug": slug,
        "company": report["company"],
        "domain": report["domain"],
        "industry": report["industry"],
        "scan_date": report["scan_date"],
        "total_findings": report["summary"]["total_findings"]
    })
    manifest.sort(key=lambda m: m["scan_date"], reverse=True)

    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)


def main():
    company_name = os.environ.get("COMPANY_NAME", "").strip()
    domain = os.environ.get("DOMAIN", "").strip()
    industry = os.environ.get("INDUSTRY", "").strip() or "Not specified"

    if not company_name or not domain:
        print("COMPANY_NAME and DOMAIN environment variables are required.", file=sys.stderr)
        sys.exit(1)

    report = run_scan(company_name, domain, industry)

    os.makedirs(DATA_DIR, exist_ok=True)
    slug = slugify(company_name)
    out_path = os.path.join(DATA_DIR, f"{slug}.json")
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    update_manifest(report, slug)

    print(f"\nScan complete: {report['summary']['total_findings']} finding(s).")
    print(f"By severity: {report['summary']['by_severity']}")
    print(f"Written to {out_path}")


if __name__ == "__main__":
    main()
