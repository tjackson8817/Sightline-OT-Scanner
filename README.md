[README.md](https://github.com/user-attachments/files/29811208/README.md)
# Sightline — OT OSINT Exposure Scanner

Checks how visible an organization's OT/ICS footprint and phishing-relevant
infrastructure are on the public internet — using only free, keyless data
sources. Outputs an executive + technical report.

## What it checks

1. **Certificate transparency exposure** — searches crt.sh (public certificate
   transparency logs) for every subdomain that's ever had an SSL certificate
   issued, then flags any whose name suggests an OT/ICS system (`scada`,
   `plc`, `hmi`, `vpn`, etc.), and checks whether each is currently live.
2. **Domain impersonation risk** — generates common typosquat variants of the
   company's domain (character swaps, omissions, adjacent-key typos, TLD
   swaps) and checks which are actually registered, resolving, and
   mail-capable. A resolving lookalike domain with mail servers configured is
   treated as active phishing infrastructure, not just a passive registration.
3. **Public leadership information** — confirms whether the company's own
   site publishes a leadership/executive team page. This does **not** extract
   or store any individual's name — it only confirms the page exists, as
   context for whaling/BEC risk.

## What this deliberately does NOT do

This tool does not look up, aggregate, or report on any named individual's
personal information (home address, family, personal social media, etc.).
That's a different kind of tool with different risk — see the project
discussion in chat for why that line matters. Executive names/titles that
a company **already self-publishes** are noted only as a finding category
("your site publishes this"), never expanded on.

## Setup

1. Push this repo to GitHub (public, for free Pages).
2. Settings → Pages → Deploy from branch → `main` → `/(root)`.
3. Settings → Actions → General → Workflow permissions → **Read and write**.

No API keys or secrets are required for this version — every data source
is free and keyless.

## Running a scan

1. Repo → **Actions** tab → **Run OT OSINT Scan** (left sidebar)
2. **Run workflow** → fill in:
   - Company name (e.g. "Acme Manufacturing Co.")
   - Domain, no `https://` (e.g. `acmemfg.com`)
   - Industry (optional)
3. Run it. Takes a minute or two — crt.sh and DNS lookups aren't instant.
4. Once it finishes, refresh your Pages URL — the new company appears in the
   dropdown automatically (via `data/reports/manifest.json`, which the script
   maintains).

Scan as many companies as you like; each gets its own report file and shows
up in the picker. Re-running a scan for the same company name overwrites its
previous report.

## Known limitations

- crt.sh and DNS-over-HTTPS lookups happen server-side in the GitHub Action
  (not in the browser) specifically to avoid CORS and bot-detection issues —
  the same lesson learned building the Fenceline threat-intel tool.
- Typosquat generation is a bounded, common-pattern set (omission,
  duplication, transposition, adjacent-key, hyphenation, TLD swap) — not an
  exhaustive commercial-grade permutation engine.
- Severity ratings are rule-based and documented in `scripts/osint_scan.py`,
  not AI-generated. A future version could add an AI-written narrative pass
  (same pattern as Fenceline's enrichment step) using an Anthropic API key,
  once you're ready to add that.
- Certificate transparency only shows subdomains that have had a *public* SSL
  certificate issued. Purely internal or non-HTTPS OT systems won't appear
  here even if they're technically internet-reachable — this is one input,
  not a complete exposure picture.
- No paid threat-intel sources (Shodan, Censys) are integrated in this
  version. Adding them would give direct confirmation of exposed ICS
  protocol banners rather than inferring risk from subdomain naming alone.
