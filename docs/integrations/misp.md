# MISP push

Push the indicators shown on the **IOCs** page (current filters) to MISP as a single event.

1. In MISP, create an automation key for a user allowed to add events.
2. Set `MISP_URL` (e.g. `https://misp.example.org`) and `MISP_KEY`. Set `MISP_VERIFY_TLS=false` only for self-signed
   lab instances.
3. On the IOCs page, filter as needed and click **Push to MISP**.

The event is created with:

- `info`: "CyNewsFeed IOCs — <date> (last N days)"
- distribution **your organisation only**, analysis *ongoing*, threat level derived from the highest story severity
- tags `tlp:amber` and `source:cynewsfeed`
- one attribute per indicator (`ip-dst`, `domain`, `url`, `email-src`, `md5`, `sha1`, `sha256`) with `to_ids`, first/last seen,
  and the reporting story title as comment

For continuous sync, prefer [TAXII](taxii.md).
