# Detections & IOCs

## Detections

In a story's **Detections & sharing** panel, pick formats and click **Generate detections**:

| Format | Target |
|---|---|
| **KQL** | Microsoft Sentinel / Defender XDR (`DeviceProcessEvents`, `SigninLogs`, …) |
| **SPL** | Splunk (CIM data models / common sourcetypes) |
| **Sigma** | Complete rule with logsource, detection, condition, ATT&CK tags |
| **YARA** | Rule with meta, strings and condition |

Each detection has a title, description, confidence, tuning notes and a **structural validation** badge: valid Sigma
YAML with required fields, balanced KQL/SPL, YARA rule/condition present. Detections are stored on the story; regenerate
any time.

!!! warning
    Detections are AI-generated. Review them, test against your data and tune them before deploying. The generator never
    invents IOCs that aren't in the story.

Cost is one call with the chat model, about $0.05–0.10 on Opus.

## IOC extraction

Indicators come from:

- **explicitly defanged** hostnames, URLs and emails in article text (`evil[.]com`, `hxxps://`, `ops[@]bad[.]ru`)
- public **IPv4** addresses, URLs on raw IPs, and **MD5 / SHA-1 / SHA-256** hashes
- bare domains on TLDs rarely used by legitimate sites
- AI summaries, which add indicators the article presents as malicious

File names (`cmd.exe`, `tasks.json`), reverse-DNS IDs (`com.zoom`), the publisher's own site and common SaaS domains are
filtered out.

## IOCs page

The **IOCs** page aggregates every indicator across stories: type, defanged value, max severity, related malware, actors
and CVEs, first/last seen and the reporting stories. Filter by type, severity, window or value.

### Export and share

| Option | Notes |
|---|---|
| **STIX 2.1** | Bundle of `indicator` objects (stable UUIDv5 ids) plus `report` objects per story |
| **CSV** | One row per indicator, with context and story links |
| **TXT** | One value per line (refanged, for blocklists) |
| **Push to MISP** | See [MISP push](../integrations/misp.md) |
| **TAXII 2.1** | Continuous pull for SIEM/TIP; see [TAXII](../integrations/taxii.md) |

A single story's IOCs can also be exported from its detail panel.
