# TAXII 2.1

CyNewsFeed serves a **read-only TAXII 2.1** API, so threat-intel platforms can pull indicators continuously as STIX 2.1.

| Endpoint | Path |
|---|---|
| Discovery | `/taxii2/` |
| API root | `/taxii2/api/` |
| Collections | `/taxii2/api/collections/` |
| Objects | `/taxii2/api/collections/{id}/objects/` (supports `added_after`, `match[type]`, `match[id]`, `limit`, `next`) |
| Manifest | `/taxii2/api/collections/{id}/manifest/` |

## Collections

| ID | Contents |
|---|---|
| `4f0b6b1e-0c4a-5d2e-9a77-000000000001` | All indicators in the retention window |
| `4f0b6b1e-0c4a-5d2e-9a77-000000000002` | Indicators from high and critical stories only |

Objects are an `identity`, one `indicator` per IOC (deterministic ids, `confidence` from severity, labels for malware,
actors and severity, external references to the stories), and one `report` per story linking its indicators.

## Authentication

Set `TAXII_TOKEN`; Terraform generates one (`terraform output -raw taxii_token`). Clients authenticate with either:

- **HTTP Basic**: any username, the token as password
- **Bearer**: `Authorization: Bearer <token>`

In Azure, `/taxii2/*` is excluded from Entra sign-in and protected only by the token.

```bash
curl -u taxii:$TAXII_TOKEN -H "Accept: application/taxii+json;version=2.1" \
  "https://<app>/taxii2/api/collections/4f0b6b1e-0c4a-5d2e-9a77-000000000002/objects/?limit=100"
```

## Client setup

=== "Microsoft Sentinel"

    *Data connectors → Threat Intelligence – TAXII* → **Add new**:

    - API root URL: `https://<app>/taxii2/api/`
    - Collection ID: one from the table above
    - Username: anything, Password: the TAXII token
    - Polling frequency: hourly

=== "OpenCTI"

    *Data → Ingestion → TAXII feeds* → add the API root, collection ID and Basic credentials. Choose STIX 2.1.

=== "MISP"

    Use a TAXII client (e.g. the `misp-taxii` tooling or a feed sync job) pointed at the API root and collection,
    with Basic auth.

=== "Splunk"

    Splunk Enterprise Security / Threat Intelligence Management: add a TAXII 2.1 source with the API root,
    collection ID and Basic credentials.
