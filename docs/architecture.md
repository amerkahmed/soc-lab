# Architecture & Design

A self-built SOC lab demonstrating end-to-end threat detection, enrichment, and
case management across host and network layers, with SOAR automation. Built on
VirtualBox VMs with a cloud-hosted backend.

> **Note on redaction:** public cloud IPs are shown as `<MANAGER_IP>` /
> `<THEHIVE_IP>` in this public repo. Internal RFC1918 lab addresses
> (`192.168.56.0/24`) are kept because they are non-routable and illustrate the
> design.

---

## 1. Components

| Component | Role | Location |
|---|---|---|
| Kali Linux | Attacker | VM, internal net `192.168.56.10` |
| Ubuntu | Victim endpoint + network sensor | VM, `192.168.56.20` (internal) + NAT |
| Windows 10 | Victim endpoint | VM, `192.168.56.30` (internal) + NAT |
| Wazuh Manager | SIEM / correlation / alerting | Cloud server `<MANAGER_IP>` |
| TheHive | Case management | Cloud server `<THEHIVE_IP>:9000` |
| Shuffle (SaaS) | SOAR / automation | shuffler.io |
| VirusTotal | Threat-intel enrichment | External API |

**Versions:** Wazuh 4.14.7 · Suricata 8.0.7 · FreeRDP 3.x (`xfreerdp3`) · Hydra 9.7
· Nmap 7.991 · Mimikatz 2.2.0, plus Sysmon (Windows). Lab hosts use static IPs on an
isolated `192.168.56.0/24` internal network (setup in §2).

### End-to-end flow

```
Attacker (Kali)
      │  attack traffic (SSH/RDP brute force, nmap, IOC connection)
      ▼
Victim endpoints (Ubuntu / Windows)
      │  Wazuh agent (host logs) + Suricata (network, on Ubuntu)
      ▼
Wazuh Manager (cloud)  ── detection rules, CDB threat-intel list, correlation
      │  integration forwards curated alerts
      ▼
Shuffle (SOAR)  ── workflow: enrich with VirusTotal → build case
      ▼
TheHive  ── alert/case created for the analyst
```

---

## 2. Networking design

Each VM uses **two adapters** — a deliberate segmentation choice:

- **Adapter 1 — Internal Network (`intnet`)**: carries attack traffic between Kali
  and the victims, isolated from the internet so the "attack range" is contained.
  No DHCP on an internal network, so hosts use **static IPs** (`192.168.56.0/24`).
- **Adapter 2 — NAT**: gives victims internet access so their Wazuh agents can
  reach the cloud manager and packages/rules can update.

Static IPs were set via `nmcli` (NetworkManager) or `netplan`; the internal
adapter is given **no default gateway**, so internet-bound traffic routes out the
NAT adapter instead.

**Why it matters:** this models real network segmentation and produced a genuine
lesson about sensor placement — Suricata only sees the interface it monitors, so
traffic egressing the NAT adapter is invisible to it (see
[challenges-and-resolutions.md](challenges-and-resolutions.md), item 1).

---

## 3. Host-based detection (Wazuh HIDS)

Wazuh agents on Ubuntu and Windows collect host telemetry and ship it to the
cloud manager, which applies detection rules.

**Linux (Ubuntu)** — SSH brute force via Hydra triggers Wazuh rules **5710**
(invalid user) and **5712** (brute-force correlation). MITRE **T1110**.

**Windows** — agent installed via MSI, pointed at the cloud manager; **Sysmon**
installed for process/DLL/file telemetry. RDP brute force produces Security
**Event ID 4625** (rule **60122**), lockout **4740** (rule **60115**), and a
successful **4624** (rule **92657**, flagged as possible pass-the-hash). Sysmon
also surfaced account-discovery (T1087), remote-system discovery (T1018), and
scheduled-task DLL loads (T1053), plus a CIS benchmark (SCA) compliance scan.

**Key configuration lesson:** the Windows agent did not collect failed logons
until a `<localfile>` block for the **Security** event channel was added. Sysmon
≠ Security log — different sensors.

---

## 4. Network-based detection (Suricata NIDS)

Suricata runs on the Ubuntu target, watching `enp0s3`, with the full Emerging
Threats Open ruleset (~53,000 rules). It detects nmap recon (ICMP probes, service
banners) and writes JSON to `/var/log/suricata/eve.json`, which the Wazuh agent
forwards to the manager (built-in Suricata decoders).

**Why both HIDS and NIDS (defense-in-depth):** host-based detection only sees what
gets logged *on* a machine; a port scan generates no host log, so Wazuh alone is
blind to it, but Suricata catches it on the wire. Conversely, Suricata can't see a
successful login or a file change — those are host events. Together they give full
coverage.

---

## 5. Threat-intel-driven detection (phishing IOC)

A crafted phishing email is analyzed, its IOCs extracted, and the attacker IP
loaded into a Wazuh **CDB list** referenced by **custom rule 100100** (level 12,
T1566). A connection to the IOC is detected on the wire and matched against the
list. Full walkthrough: [scenarios/02-phishing-ioc.md](scenarios/02-phishing-ioc.md).

The lab IOC is a reserved documentation IP (`203.0.113.17`, RFC 5737);
"known-bad" means known-bad *within this lab's threat list*, exactly how real
watchlists work. VirusTotal enrichment is demonstrated separately against a
genuinely malicious IP from abuse.ch, with the lab IOC documented as synthetic.

---

## 6. SOAR automation (Wazuh → Shuffle → TheHive)

The manager forwards curated alerts to a Shuffle webhook — filtered to the
actionable alerts, never a broad level: by rule **group** (`phishing`,
`sysmon_eid10_detections`) and by rule **ID** (`5712` SSH correlation, `60115` RDP
lockout, `92657` RDP compromise). Per-attempt rules (`5710`, `60122`) and the
Suricata flood are deliberately excluded. The Shuffle workflow is **Webhook → VirusTotal lookup → HTTP
request node** that POSTs a hand-built JSON body to TheHive's `/api/v1/alert`
(HTTP 201). Selected scalar VT fields (malicious count, country, owner) are
embedded in the alert description.

**Why a raw HTTP node instead of the TheHive app node:** the native app node
proved unreliable (empty body, content-type mismatch). A plain HTTP node — with
explicit `Content-Type: application/json`, an auth header, and a hand-built body —
is reliable and fully visible for debugging.

**Design principle — selective enrichment:** VirusTotal enrichment is meaningful
for network/IP-based IOCs (phishing, recon with a real external IP), less so for
brute force (whose lab source is a private IP VT can't resolve). The mature design
applies enrichment selectively by alert type.

---

## 7. Response strategy (tiered model)

| Detection | Response | Rationale |
|---|---|---|
| Port scan (recon) | Alert only | Noisy; source IP is spoofable |
| Brute force (in progress) | Auto-block (`firewall-drop`) | High confidence, time-sensitive, reversible, source not spoofable (needs full TCP handshake) |
| Successful logon post-brute-force | Human-in-the-loop (analyst approves) | High impact, ambiguous, disruptive |

**Spoofability is the key distinction:** a SYN/ICMP scan can carry a forged source
IP, so auto-blocking it risks blocking an innocent/critical address (or being
weaponized to make you block yourself). A brute-force login requires a completed
TCP handshake, so its source IP is genuine and safe to block.
