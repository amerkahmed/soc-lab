# Scenario 01 — Nmap recon re-test (2026-10-27)

Evidence for the before/after `HOME_NET` comparison in
[`docs/scenarios/01-nmap-recon.md`](../../../docs/scenarios/01-nmap-recon.md) §2.
The point of the re-test: Suricata's **default `HOME_NET`** counted the Kali
attacker (`192.168.56.10`) as "home", so the `EXTERNAL_NET -> HOME_NET` ET SCAN
rules could never fire on it. Scoping `HOME_NET` to the victim hosts activates them.
Each scan was run **twice** — once under the default config, once under the fix.

## Timeline (all UTC — the before/after boundary is on the clock)

| Time (UTC) | Event |
|---|---|
| 20:44–20:47 | **before** scans: `-sS` (20:44 local 16:44), `-sV` (16:46), `-A` (16:47) |
| ~20:59 | `suricata.yaml` edited — `HOME_NET` scoped to `[192.168.56.20,192.168.56.30]` (file mtime) |
| ~21:00:25 / 21:00:43 | Suricata reload — "53123 rules successfully loaded" (from `suricata.log`) |
| 21:00:59–21:05 | **after** scans: `-sS` (21:00:59), `-sV` (21:01:44), `-A` (21:02:14→21:02:26), `-p1000` (21:05) |

The ET SCAN rules appear **only** in alerts timestamped after the reload — the fix
is the cause, verifiable against the reload timestamp.

## Contents

```
before/   default HOME_NET (Kali counts as home)
  nmap-sS.txt  nmap-sV.txt  nmap-A.txt     attacker output, one per scan
  fast-sS.txt                              empty (0 alerts)
  fast-sV.txt                              empty (0 alerts)
  fast-A.txt                               34 lines, all "SURICATA ICMPv4 unknown code"
  signature-counts.txt                     per-scan counts, derived from the fast extracts
after/    HOME_NET = [192.168.56.20,192.168.56.30]
  nmap-sS.txt  nmap-sV.txt  nmap-A.txt  nmap-p1000.txt
  fast-sS.txt (5)  fast-sV.txt (4)  fast-A.txt (45)  fast-p1000.txt (empty)
  signature-counts.txt
homenet-config.txt                         live vars{} block + provenance of the change
```

## How the counts map to §2

| Scan | before | after |
|---|---|---|
| `-sS` | 0 | 5 — MySQL/MSSQL/Oracle/PostgreSQL + VNC 5800-5820 |
| `-sV` | 0 | 4 — the four DB-port rules |
| `-A` | 34 (all ICMP decoder) | 45 across 8 signatures (adds OS Detection Probe ×5, DB/VNC/SSH port rules) |
| `-sS -p 1-1000` | — | 0 — blind spot (§6): none of the DB/VNC ports fall in 1–1000 |

The `-A` OS-detection UDP probe lands on port **43498**, matching the `CU=43498`
value in `after/nmap-A.txt` — the fingerprint's closed-UDP-port selection.

## Honesty notes

- **No pre-edit backup of `suricata.yaml` was kept**, so the exact prior `HOME_NET`
  string can't be re-read. It was a stock Suricata default that included
  `192.168.0.0/16` (which is why Kali counted as home); `homenet-config.txt` shows
  the current active value and the commented stock defaults. `docs/scenarios/01`
  states the default as `[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]`.
- One unrelated alert (`ET HUNTING curl User-Agent to Dotted Quad`) appears in the
  full-day log but in **none** of these per-scan captures — it is not nmap traffic
  and is correctly excluded.
